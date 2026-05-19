//! On-disk PE helpers: map an image via `LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES)`
//! for pattern scanning + export lookups. No relocations applied — RVAs only.

use std::ffi::{c_void, CString};

use windows::core::PCSTR;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExA, DONT_RESOLVE_DLL_REFERENCES,
};

/// Load `name` as an unresolved image. Returns `(base, SizeOfImage)`.
pub fn load_image(name: &str) -> Result<(usize, usize), String> {
    let c = CString::new(name).map_err(|_| "bad name")?;
    let h = unsafe {
        LoadLibraryExA(PCSTR(c.as_ptr() as _), None, DONT_RESOLVE_DLL_REFERENCES)
    }.map_err(|e| format!("LoadLibraryExA({name}): {e}"))?;
    let base = h.0 as usize;
    let lfanew = unsafe { *((base + 0x3C) as *const u32) } as usize;
    let size   = unsafe { *((base + lfanew + 0x18 + 0x38) as *const u32) } as usize;
    Ok((base, size))
}

/// RVA of an exported symbol within an image loaded by `load_image`.
pub fn export_rva(module_base: usize, name: &str) -> Option<u64> {
    let c = CString::new(name).ok()?;
    let h = HMODULE(module_base as *mut c_void);
    let p = unsafe { GetProcAddress(h, PCSTR(c.as_ptr() as _)) }? as usize;
    Some((p - module_base) as u64)
}

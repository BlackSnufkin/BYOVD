# TfSysMon-Killer
- PoC for the TfSysMon driver from ThreatFire System Monitor (2013)
- SysMon.sys SHA256: `1C1A4CA2CBAC9FE5954763A20AEB82DA9B10D028824F42FFF071503DCBE15856`
- As of 2024-08-11, the driver is **listed on [LOLDDrivers](https://www.loldrivers.io/)** but remains **absent** from [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) as of 2024-09-11

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library. See the root [README](../README.md#-complete-driver-reverse-engineering-process-x64) for a full reverse engineering walkthrough of this driver.

## Usage

Place `sysmon.sys` in the same directory as the executable (driver file must be named `sysmon.sys`).

```text
BYOVD process killer using TfSysMon driver (ThreatFire)

Usage: TfSysMon-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p TfSysMon-Killer

# Run
.\TfSysMon-Killer.exe -n notepad.exe
```

Windows 10 Pro (Up to date)

![tfsysmon_poc](https://github.com/BlackSnufkin/BYOVD/assets/61916899/84a6497a-cee9-4ba5-9f24-78845c834b75)

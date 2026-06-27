# MonProcessEX-Killer
- PoC for vulnerability in MonProcessEX from HONOR MagicAnimation and HONOR PCManager

- As of 2026-06-27, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `MonProcessEX.sys` SHA256: `72d0b5615b996cbb01b1ca139e627079094f734da48a0435ffd8480a25d0a258`

## Usage

Place `MonProcessEX.sys` in the same directory as the executable.

```text
PS C:\Users\User\Desktop> .\MonProcessEX-Killer.exe -h
BYOVD process killer using MonProcessEX driver

Usage: MonProcessEX-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p MonProcessEX-Killer

# Run
.\MonProcessEX-Killer.exe -n notepad.exe
```

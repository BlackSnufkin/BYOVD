# STProcessMonitor-Killer
- PoC for CVE-2025-70795 vulnerability in STProcessMonitor Driver from Safetica
- Affects:
  - **Legacy builds (11.11.4.0)** -> low-privilege BYOVD abuse
  - **Current build (11.26.18.0)** -> LocalSystem-privilege BYOVD abuse

- As of 2026-02-12, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

**Driver hashes:**
- `STProcessMonitor.sys` **11.11.4.0** SHA256: `70bcec00c215fe52779700f74e9bd669ff836f594df92381cbfb7ee0568e7a8b`
- `STProcessMonitor.sys` **11.26.18.0** SHA256: `5b4f59236a9b950bcd5191b35d19125f60cfb9e1a1e1aa2e4f914b6745dde9df`

Usage:

To use STProcessMonitor-Killer, you need to have the STProcessMonitor.sys driver located at the same location as the executable

you will need to give it a process name

(the driver name must be STProcessMonitor.sys so rename if needed)

```text

PS C:\Users\User\Desktop> .\STProcessMonitor-Killer.exe -h
STProcessMonitor-Killer.exe 1.0
BlackSnufkin, wwwab
Kills a process by name using STProcessMonitor driver

USAGE:
    STProcessMonitor-Killer.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints version information

OPTIONS:
    -n, --name=process_name
```

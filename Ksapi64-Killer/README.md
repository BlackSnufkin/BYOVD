# Ksapi64-Killer
- PoC for the ksapi64 driver -- this PoC works on 2 driver variants
- ksapi64.sys SHA256: `1CD219F58B249A2E4F86553BDD649C73785093E22C87170798DAE90F193240AF`
- ksapi64_del.sys SHA256: `26ED45461E62D733F33671BFD0724399D866EE7606F3F112C90896CE8355392E`
- As of 2023-06-12, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library.

## Usage

Place `ksapi64.sys` in the same directory as the executable (driver file must be named `ksapi64.sys`).

```text
BYOVD process killer using ksapi64 driver (Kingsoft)

Usage: Ksapi64-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p Ksapi64-Killer

# Run
.\Ksapi64-Killer.exe -n notepad.exe
```

Tested on Windows 10 Build 14393 / Windows Server 2016

 Windows 10 Build 14393

![ksapi64_poc](https://github.com/BlackSnufkin/BYOVD/assets/61916899/1e6ac4ca-ca16-4b4d-a43e-f9c7de8eb161)

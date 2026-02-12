# NSec-Killer
- Reproduction ValleyRAT [BYOVD](https://hexastrike.com/resources/blog/threat-intelligence/valleyrat-exploiting-byovd-to-kill-endpoint-security/)
- PoC for vulnerability in NSecKrnl driver from NSecSoft
- NSecKrnl.sys SHA256: `206F27AE820783B7755BCA89F83A0FE096DBB510018DD65B63FC80BD20C03261`
- The driver is **listed on [LOLDDrivers](https://www.loldrivers.io/)** but remains **absent** from [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) as of 2025-10-15

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library. Note: this driver reports an error even on successful termination, so `ignore_ioctl_error` is enabled.

## Usage

Place `NSecKrnl.sys` in the same directory as the executable (driver file must be named `NSecKrnl.sys`).

```text
BYOVD process killer using NSecKrnl driver (ValleyRAT)

Usage: NSec-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p NSec-Killer

# Run
.\NSec-Killer.exe -n notepad.exe
```

Windows 11 Pro (Up to date)

<img width="1917" height="996" alt="Screenshot 2025-10-15 123923" src="https://github.com/user-attachments/assets/1411d548-ff51-4c2f-a62c-b1b3343ad257" />

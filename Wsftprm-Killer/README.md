# Wsftprm-Killer
- Reproduction SilverFox (APT-Q-27) [BYOVD](https://paper.seebug.org/3337/)
- PoC for CVE-2023-52271 vulnerability in wsftprm driver from Topaz Antifraud
- wsftprm.sys SHA256: `FF5DBDCF6D7AE5D97B6F3EF412DF0B977BA4A844C45B30CA78C0EEB2653D69A8`
- The driver is **listed on [LOLDDrivers](https://www.loldrivers.io/)** but remains **absent** from [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) as of 2025-07-21



Usage:

To use Wsftprm-Killer, you need to have the wsftprm.sys driver located at the same location as the executable

you will need to give it a process name

(the driver name must be wsftprm.sys so rename if needed)

```text

PS C:\Users\User\Desktop> .\wsftprm-Killer.exe -h
wsftprm-Killer.exe 1.0
BlackSnufkin
Kills a process by name using wsftprm driver

USAGE:
    wsftprm-Killer.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints version information

OPTIONS:
    -n, --name=process_name
```


Windows 10 Pro (Up to date)

<img width="1915" height="816" alt="wsftprn-poc" src="https://github.com/user-attachments/assets/6bec86f5-ba35-4db0-8fbf-2439bae48d13" />



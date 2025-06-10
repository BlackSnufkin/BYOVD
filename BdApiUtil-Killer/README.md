# BdApiUtil-Killer
- PoC for CVE-2024-51324 vulnerability in BdApiUtil driver from Baidu Antivirus
- BdApiUtil64.sys SHA256: `47EC51B5F0EDE1E70BD66F3F0152F9EB536D534565DBB7FCC3A05F542DBE4428`
- The driver not on the list of [LolDrivers](https://www.loldrivers.io/) and not on the [Microsoft](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) recommended driver block rules (10/06/2025)


Usage:

To use BdApiUtil-Killer, you need to have the BdApiUtil64.sys driver located at the same location as the executable

you will need to give it a process name

(the driver name must be BdApiUtil64.sys so rename if needed)

```text

PS C:\Users\User\Desktop> .\BdApiUtil-Killer.exe -h
BdApiUtil-Killer.exe 5.0
BlackSnufkin
Kills a process by name using a BYOVD

USAGE:
    BdApiUtil-Killer.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints version information

OPTIONS:
    -n, --name=process_name
```


Windows 10 Pro (Up to date)




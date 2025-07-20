# TfSysMon-Killer
- this a poc for the TfSysMon driver from ThreatFire System Monitor (2013)
- SysMon.sys SHA256: `1C1A4CA2CBAC9FE5954763A20AEB82DA9B10D028824F42FFF071503DCBE15856`
- As of 2024-08-11, the driver is **listed on [LOLDDrivers](https://www.loldrivers.io/)** but remains **absent** from [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) as of 2024-09-11



Usage:

To use TfSysMon-Killer, you need to have the sysmon.sys driver located at the same location as the executable

you will need to give it a process name

(the driver name must be sysmon.sys so rename if needed)

```text

PS C:\Users\User\Desktop> .\TfSysMon-Killer.exe -h
TfSysMon-Killer.exe 1.0
BlackSnufkin
Kills a process by name using Tfsysmon driver

USAGE:
    TfSysMon-Killer.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints version information

OPTIONS:
    -n, --name=process_name
```


Windows 10 Pro (Up to date)

![tfsysmon_poc](https://github.com/BlackSnufkin/BYOVD/assets/61916899/84a6497a-cee9-4ba5-9f24-78845c834b75)


# NSec-Killer
- Reproduction ValleyRAT [BYOVD](https://hexastrike.com/resources/blog/threat-intelligence/valleyrat-exploiting-byovd-to-kill-endpoint-security/)
- PoC for vulnerability in NSecKrnl driver from NSecSoft
- NSecKrnl.sys SHA256: `206F27AE820783B7755BCA89F83A0FE096DBB510018DD65B63FC80BD20C03261`
- The driver is **listed on [LOLDDrivers](https://www.loldrivers.io/)** but remains **absent** from [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) as of 2025-10-15



Usage:

To use NSec-Killer, you need to have the NSecKrnl.sys driver located at the same location as the executable

you will need to give it a process name

(the driver name must be NSecKrnl.sys so rename if needed)

```text

PS C:\Users\User\Desktop> .\NSec-Killer.exe -h
NSec-Killer.exe 1.0
BlackSnufkin
Kills a process by name using NSecKrnl driver

USAGE:
    NSec-Killer.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints version information

OPTIONS:
    -n, --name=process_name
```


Windows 11 Pro (Up to date)


<img width="1917" height="996" alt="Screenshot 2025-10-15 123923" src="https://github.com/user-attachments/assets/1411d548-ff51-4c2f-a62c-b1b3343ad257" />


# Ksapi64-Killer
- this a poc for the ksapi64 driver this poc is some how working on 2 drivers
- ksapi64.sys SHA256: `1CD219F58B249A2E4F86553BDD649C73785093E22C87170798DAE90F193240AF`
- ksapi64_del.sys SHA256: `26ED45461E62D733F33671BFD0724399D866EE7606F3F112C90896CE8355392E`
- As of 2023-06-12, the driver is **not** listed on [LOLDDrivers](https://www.loldrivers.io/) or in [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)


Usage:

To use Ksapi64-Killer, you need to have the ksapi64.sys driver located at the same location as the executable

you will need to give it a process name

(the driver name must be ksapi64.sys so rename if needed)

```text
Ksapi64-Killer.exe 1.0
BlackSnufkin
Kills a process by name using ksapi64 driver

USAGE:
    Ksapi64-Killer.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints version information

OPTIONS:
    -n, --name=process_name

```
Tested on Windows 10 Build 14393 / Windows Server 2016

 Windows 10 Build 14393

![ksapi64_poc](https://github.com/BlackSnufkin/BYOVD/assets/61916899/1e6ac4ca-ca16-4b4d-a43e-f9c7de8eb161)


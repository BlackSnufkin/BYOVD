# Ksapi64-Killer
- this a poc for the ksapi64 driver this poc is some how working on 2 drivers
- ksapi64.sys SHA256: `1CD219F58B249A2E4F86553BDD649C73785093E22C87170798DAE90F193240AF`
- ksapi64_del.sys SHA256: `26ED45461E62D733F33671BFD0724399D866EE7606F3F112C90896CE8355392E`
- The driver not on the list of [LolDrivers](https://www.loldrivers.io/) and not on the [Microsoft](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) recommended driver block rules (12/06/2023)


Usage:

To use Ksapi-Killer, you need to have the ksapi64.sys driver located at the same location as the executable

you will be presented with an options menu where you can specify a process ID or name

(the driver name must be ksapi64.sys so rename if needed)

The POC code relies heavily on [TrueSightKiller](https://github.com/MaorSabag/TrueSightKiller)

Tested on Windows 8.1 / Windows Server 2016

Windows Server 2016

![poc_srv](https://github.com/BlackSnufkin/BYOVD/assets/61916899/0d8df727-25db-4f69-a122-b79f59fb76c1)


![poc_srv_1](https://github.com/BlackSnufkin/BYOVD/assets/61916899/113fd59b-5ab1-46e5-8b82-241710b1efff)

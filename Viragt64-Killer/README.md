# Viragt64-Killer
- this a poc for the Viragt64 driver from Tg Soft (2016)
- viragt64.sys SHA256: `58A74DCEB2022CD8A358B92ACD1B48A5E01C524C3B0195D7033E4BD55EFF4495`
- I initially developed the POC for personal use and didnt release it due that the driver is on the Microsoft recommended driver block rules and also in LOLDrivers.
- However, upon discovering that it's being [abused](https://www.trendmicro.com/en_us/research/24/a/kasseika-ransomware-deploys-byovd-attacks-abuses-psexec-and-expl.html) in the wild, I've decided to share the POC. 


Usage:

To use Viragt64-Killer, you need to have the viragt64.sys driver located at the same location as the executable

you will need to give it a process name

(the driver name must be viragt64.sys so rename if needed)

```text

PS C:\Users\User\Desktop> .\viragt64-Killer.exe -h
viragt64-Killer.exe 4.2
BlackSnufkin
Kills a process by name using a BYOVD

USAGE:
    viragt64-Killer.exe [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -v, --version    Prints version information

OPTIONS:
    -n, --name=process_name
```

Tested on Windows 10 Pro

Windows 10 Pro (Up to date)



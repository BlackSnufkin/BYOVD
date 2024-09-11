# BYOVD (Bring Your Own Vulnerable Driver)

**BYOVD** is a collection of Proof of Concepts (PoCs) showcasing the exploitation of vulnerable drivers to terminate processes protected by AV/EDR solutions. This technique allows attackers to disable security software by leveraging flaws in signed drivers. These drivers are either not included in the Microsoft recommended driver block rules or were previously unlisted but found to be abused in the wild.

## Table of Contents
- [Overview](#overview)
- [POCs](#pocs)
- [Usage Instructions](#usage-instructions)
- [Detailed Driver Analysis](#detailed-driver-analysis)
- [References](#references)
- [Disclaimer](#disclaimer)

## Overview
The **BYOVD technique** has recently gained popularity in offensive security, particularly with the release of tools such as SpyBoy's *Terminator* (sold for $3,000) and the *ZeroMemoryEx Blackout* project. These tools capitalize on vulnerable drivers to disable AV/EDR agents, facilitating further attacks by reducing detection.

This repository contains several PoCs developed for educational purposes, helping researchers understand how these drivers can be abused to terminate processes.

## POCs
Below are the drivers and their respective PoCs available in this repository:

- **[Ksapi64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Ksapi64-Killer)**: Targets `ksapi64.sys` and `ksapi64_del.sys`.
- **[TfSysMon-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer)**: Targets `sysmon.sys` from ThreatFire System Monitor.
- **[Viragt64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Viragt64-Killer)**: Targets `viragt64.sys` from Tg Soft.

## Usage Instructions
To exploit these vulnerable drivers, you need to place the corresponding driver file in the same directory as the executable and specify the process name to be terminated.

### General Command Structure:
```bash
<driver-killer>.exe -n <process_name>
```

### Example for `Viragt64-Killer`:
```bash
PS C:\Users\User\Desktop> .\viragt64-Killer.exe -n target_process
```

### Flags and Options:
- `-h, --help`: Prints help information.
- `-v, --version`: Prints version information.
- `-n, --name`: Specify the name of the process to be terminated.

### PoC for Each Driver:
#### Viragt64-Killer:
- Targets: `viragt64.sys`
- SHA256: `58A74DCEB2022CD8A358B92ACD1B48A5E01C524C3B0195D7033E4BD55EFF4495`
- Usage Example:
    ```bash
    .\viragt64-Killer.exe -n ProcessName
    ```
- Tested on: Windows 10 Pro

#### TfSysMon-Killer:
- Targets: `sysmon.sys`
- SHA256: `1C1A4CA2CBAC9FE5954763A20AEB82DA9B10D028824F42FFF071503DCBE15856`
- Usage Example:
    ```bash
    .\TfSysMon-Killer.exe -n ProcessName
    ```
- Tested on: Windows 10 Pro

#### Ksapi64-Killer:
- Targets: `ksapi64.sys` and `ksapi64_del.sys`
- SHA256:
  - `ksapi64.sys`: `1CD219F58B249A2E4F86553BDD649C73785093E22C87170798DAE90F193240AF`
  - `ksapi64_del.sys`: `26ED45461E62D733F33671BFD0724399D866EE7606F3F112C90896CE8355392E`
- Usage Example:
    ```bash
    .\Ksapi64-Killer.exe -n ProcessName
    ```
- Tested on: Windows 10 Build 14393 / Windows Server 2016

## Detailed Driver Analysis
This project is based on research inspired by Alice Climent-Pommeret's blog post on [Finding and Exploiting Process Killer Drivers with LOL for $3000](https://alice.climent-pommeret.red/posts/process-killer-driver/). The blog details the methodology of finding and exploiting drivers that can terminate protected processes.

Some key points from the research:
- Vulnerable drivers are identified using the **LOLDrivers** project, which centralizes known vulnerable drivers.
- Drivers can be exploited via **IOCTL** calls to perform actions such as terminating processes.
- Two examples of vulnerable drivers (AswArPot.sys and kEvP64.sys) were analyzed to demonstrate how IOCTL codes could be leveraged to kill processes from user-mode applications.

### IRP Major Functions of Interest:
- `IRP_MJ_CREATE`: Called when the driver is created.
- `IRP_MJ_CLOSE`: Called when the driver is closed.
- `IRP_MJ_DEVICE_CONTROL`: Used to send IOCTLs to the driver.

### Key Exploitation Steps:
1. Identify vulnerable drivers using the **LOLDrivers Finder** script.
2. Analyze driver IRPs and IOCTLs to determine possible process-killing capabilities.
3. Develop a PoC that leverages the driver's vulnerability to terminate processes.

For more detailed analysis and reverse engineering steps, refer to Alice's [full blog post](https://alice.climent-pommeret.red/posts/process-killer-driver/).

## References
- **Alice Climent-Pommeret's Blog**: [Finding and Exploiting Process Killer Drivers with LOL for $3000](https://alice.climent-pommeret.red/posts/process-killer-driver/)
- **LOLDrivers**: [A Central Repository of Known Vulnerable Drivers](https://www.loldrivers.io/)
- **Microsoft Driver Block Rules**: [Microsoft's Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
- **Windows Kernel Programming** by Pavel Yosifovich
- **Windows Internals, Part 1 & 2** by Mark E. Russinovich, Alex Ionescu, David Solomon

## Disclaimer :loudspeaker:
**BYOVD** is for **educational and research purposes only**. The author is not responsible for any misuse or damage caused by these programs. Always seek explicit permission before using these tools on any system.

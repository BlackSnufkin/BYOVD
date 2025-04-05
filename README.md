# 🛠️ BYOVD (Bring Your Own Vulnerable Driver)

**BYOVD** is a collection of newly discoverd PoCs demonstrating how vulnerable drivers can be exploited to disable AV/EDR solutions by leveraging flaws in signed drivers. These drivers were either not listed in the [Microsoft driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) or the [LOLDrivers](https://www.loldrivers.io/) project (as of 12/08/2023).

> Since the initial discovery, the **TfSysMon** driver has been added to LOLDrivers and was abused by ransomware groups using the **EDRKillShifter** tool, as reported by [Sophos](https://sophos.com/news/2024/08/14/ransomware-attackers-introduce-new-edr-killer) & [ESET](https://www.welivesecurity.com/en/eset-research/shifting-sands-ransomhub-edrkillshifter/)





## 📚 Table of Contents
- [🔍 Overview](#-overview)
- [💡 POCs](#-pocs)
- [🔬 Detailed Driver Analysis](#-detailed-driver-analysis)
- [🔗 References](#-references)
- [⚠️ Disclaimer](#%EF%B8%8F-disclaimer)
  
## 🔍 Overview
The **BYOVD technique** has recently gained popularity in offensive security, particularly with the release of tools such as SpyBoy's *Terminator* (sold for $3,000) and the *ZeroMemoryEx Blackout* project. These tools capitalize on vulnerable drivers to disable AV/EDR agents, facilitating further attacks by reducing detection.

This repository contains several PoCs developed for educational purposes, helping researchers understand how these drivers can be abused to terminate processes.

## 💡 POCs
Below are the drivers and their respective PoCs available in this repository:

- **[Ksapi64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Ksapi64-Killer)**: Targets `ksapi64.sys` and `ksapi64_del.sys`.
- **[TfSysMon-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer)**: Targets `sysmon.sys` from ThreatFire System Monitor.
- **[Viragt64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Viragt64-Killer)**: Targets `viragt64.sys` from Tg Soft.


## 🔬 Detailed Driver Analysis

This project is inspired by Alice Climent-Pommeret's blog post, [Finding and Exploiting Process Killer Drivers with LOL for $3000](https://alice.climent-pommeret.red/posts/process-killer-driver/), which explains how to identify and exploit process-killing drivers. The key takeaway from this research is how to systematically find **new vulnerable drivers** that can be abused to disable AV/EDR protections. Below are the most important elements to focus on from the research to discover and exploit such drivers.

### 🔑 Key Insights for Finding New Vulnerable Drivers:
1. **🛠️ Focus on IOCTL Codes**: The heart of exploiting drivers lies in understanding **IOCTL (Input/Output Control) codes**. IOCTLs allow communication between user-mode applications and kernel-mode drivers. Vulnerable drivers can expose dangerous functions through these IOCTL codes, such as terminating processes or accessing protected resources.

2. **🔍 Look for Specific Function Imports**: In vulnerable drivers, look for functions that indicate process manipulation capabilities:
   - **ZwOpenProcess** or **NtOpenProcess**: These functions allow a driver to obtain a handle to any process, a necessary step before terminating it.
   - **ZwTerminateProcess** or **NtTerminateProcess**: These functions allow a driver to forcibly terminate a process.
   
3. **📊 Leverage LOLDrivers Database**: Use the **LOLDrivers** project, which centralizes information about known vulnerable drivers. This database provides detailed technical data about drivers and their imported functions, giving you a head start in identifying potential candidates for exploitation.

4. **🧠 Reverse Engineer Driver Logic**: Once you’ve identified a driver, reverse-engineer its IOCTL handling logic. **Focus on understanding how it processes commands**, particularly those sent via the `IRP_MJ_DEVICE_CONTROL` function. This is where you’ll find whether an IOCTL code corresponds to dangerous operations like process termination or access to sensitive resources.

### 🔎 The Approach to Finding New Drivers:
To discover new vulnerable drivers, you can adopt the following structured approach:

1. **Identify Driver Candidates**: Use the LOLDrivers project or your own collection of drivers to find those that import critical functions such as `ZwOpenProcess` and `ZwTerminateProcess`. A driver importing both indicates potential for process termination abuse.

2. **Analyze IOCTL Codes**: After identifying a candidate driver, examine how it processes IOCTL codes. Look for patterns that allow user-mode applications to send commands for terminating processes. Focus on IOCTL codes mapped to `IRP_MJ_DEVICE_CONTROL`, as this is where most critical functionality resides.

3. **Create Proof of Concept (PoC)**: Once you’ve reverse-engineered the vulnerable IOCTL logic, you can create a PoC to exploit the driver. The PoC should interact with the driver by sending the appropriate IOCTL code, along with a handle or PID of the target process to terminate it.

### Example of This Process in Action:
The blog by Alice Climent-Pommeret provides two case studies of vulnerable drivers (`AswArPot.sys` and `kEvP64.sys`), showing how they were exploited using this methodology. These drivers were found to expose process-killing capabilities through specific IOCTL codes, and the steps to reverse engineer and develop a PoC were outlined.

Following this method, you can identify new vulnerable drivers by:
- Searching for critical function imports,
- Understanding how the driver processes IOCTL codes,
- And leveraging LOLDrivers or similar resources to accelerate your search.

### IRP Major Functions of Interest:
When investigating drivers, pay close attention to the following IRP (I/O Request Packet) major functions. These are key to understanding how drivers handle user requests:
- **`IRP_MJ_CREATE`**: Called when communication with the driver is established.
- **`IRP_MJ_CLOSE`**: Called when communication is terminated.
- **`IRP_MJ_DEVICE_CONTROL`**: Critical for exploitation; used for sending IOCTL codes to drivers. Most process-killing vulnerabilities will be handled through this function.

### The Path to Exploitation:
1. **Driver Identification**: Find drivers that import `ZwOpenProcess` and `ZwTerminateProcess`.
2. **IOCTL Analysis**: Reverse engineer how IOCTLs are handled, focusing on dangerous commands like process termination.
3. **Exploit Development**: Write a PoC that interacts with the driver through the vulnerable IOCTL code, passing the necessary parameters to terminate a target process.

By following these steps, you can systematically find and exploit vulnerable drivers, similar to the process outlined in Alice’s [full blog post](https://alice.climent-pommeret.red/posts/process-killer-driver/).

## 🔗 References
- **Alice Climent-Pommeret's Blog**: [Finding and Exploiting Process Killer Drivers with LOL for $3000](https://alice.climent-pommeret.red/posts/process-killer-driver/)
- **LOLDrivers**: [A Central Repository of Known Vulnerable Drivers](https://www.loldrivers.io/)
- **Microsoft Driver Block Rules**: [Microsoft's Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
- **Windows Kernel Programming** by Pavel Yosifovich
- **Windows Internals, Part 1 & 2** by Mark E. Russinovich, Alex Ionescu, David Solomon


## ⚠️ Disclaimer
**The BYOVD Project** is for **educational and research purposes only**. The author is not responsible for any misuse or damage caused by these programs. Always seek explicit permission before using these tools on any system.

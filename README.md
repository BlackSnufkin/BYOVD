# 🛠️ BYOVD (Bring Your Own Vulnerable Driver)

**BYOVD** is a collection of newly discovered PoCs demonstrating how vulnerable drivers can be exploited to disable AV/EDR solutions by leveraging flaws in signed drivers. These drivers were either not listed in the [Microsoft driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) or the [LOLDrivers](https://www.loldrivers.io/) project (as of 12/08/2023).

> Since its initial discovery, the TfSysMon driver has been added to LOLDrivers and abused by ransomware groups using the **EDRKillShifter** tool, as reported by [Sophos](https://sophos.com/news/2024/08/14/ransomware-attackers-introduce-new-edr-killer) & [ESET](https://www.welivesecurity.com/en/eset-research/shifting-sands-ransomhub-edrkillshifter/)

## 📚 Table of Contents
- [🔍 Overview](#-overview)
- [💡 POCs](#-pocs)
- [🔬 Complete Driver Reverse Engineering Process (x64)](#-complete-driver-reverse-engineering-process-x64)
- [🔗 References](#-references)
- [⚠️ Disclaimer](#%EF%B8%8F-disclaimer)
  
## 🔍 Overview
The **BYOVD technique** has recently gained popularity in offensive security, particularly with the release of tools such as SpyBoy's *Terminator* (sold for $3,000) and the *ZeroMemoryEx Blackout* project. These tools capitalize on vulnerable drivers to disable AV/EDR agents, facilitating further attacks by reducing detection.

This repository contains several PoCs developed for educational purposes, helping researchers understand how these drivers can be abused to terminate processes.

## 💡 POCs
Below are the drivers and their respective PoCs available in this repository:

- **[BdApiUtil-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer)**: Targets `BdApiUtil64.sys` from `Baidu AntiVirus`.
- **[Ksapi64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Ksapi64-Killer)**: Targets `ksapi64.sys` and `ksapi64_del.sys`.
- **[TfSysMon-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer)**: Targets `sysmon.sys` from `ThreatFire System Monitor`.
- **[Viragt64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Viragt64-Killer)**: Targets `viragt64.sys` from `Tg Soft`.
- **[Wsftprm-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Wsftprm-Killer)**: Targets `wsftprm.sys` from `Topaz Antifraud`.


## 🔬 Complete Driver Reverse Engineering Process (x64)

This section demonstrates the complete A-Z reverse engineering methodology using the TfSysMon driver as a practical example. This process applies to any x64 Windows kernel driver analysis.

## 🎯 Step 0: Pre-Analysis - Function Import Screening

Check driver imports before starting reverse engineering.

A basic process killer driver requires 2 things:

a way to get a handle on a process (for instance **ZwOpenProcess** or **NtOpenProcess**)

a way to terminate the process (for instance  **ZwTerminateProcess** or **NtTerminateProcess**)

Check if a driver imports both function types. If a driver has in its imported functions Nt/ZwOpenProcess AND Nt/ZwTerminateProcess then it's a potential process killer driver candidate.

Only after confirming these imports should you proceed to detailed reverse engineering in IDA Pro.

### 🛠️ Prerequisites for x64 Driver Analysis

**Required Tools:**
- **IDA Pro** - for disassembling the driver for static analysis
- **OSRLoader** - for loading/running the driver (alternative to sc.exe command)

### 📍 Step 1: Locate and Analyze DriverEntry

**Every Windows driver starts with DriverEntry - find this function first:**

In TfSysMon, the DriverEntry looks like this:

```c
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  unsigned __int64 v2; // rax
  v2 = BugCheckParameter2;
  if ( !BugCheckParameter2 || BugCheckParameter2 == 0x2B992DDFA232LL )
  {
    v2 = ((unsigned __int64)&BugCheckParameter2 ^ MEMORY[0xFFFFF78000000320]) & 0xFFFFFFFFFFFFLL;
    if ( !v2 )
      v2 = 0x2B992DDFA232LL;
    BugCheckParameter2 = v2;
  }
  BugCheckParameter3 = ~v2;
  return sub_17484(DriverObject);
}
```

**Analysis Notes:**
- The code performs some initialization with BugCheckParameter2 and BugCheckParameter3
- The real driver initialization happens in `sub_17484`
- Follow the call to `sub_17484(DriverObject)` - this is where actual driver setup occurs

### 📍 Step 2: Follow Driver Initialization Chain

**Navigate to the initialization function (`sub_17484`):**

```c
NTSTATUS __fastcall sub_17484(PDRIVER_OBJECT DriverObject, unsigned __int16 *a2)
{
  // ... initialization code ...
  
  RtlInitUnicodeString(&DestinationString, L"\\Device\\TfSysMon");
  result = IoCreateDevice(DriverObject, 0, &DestinationString, 0x22u, 0x100u, 0, &DeviceObject);
  if ( result < 0 )
    return result;
    
  qword_1D5D8 = 0;
  dword_1D5D0 = 1;
  DriverObject->MajorFunction[15] = (PDRIVER_DISPATCH)&sub_17694;
  DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_17694;
  DriverObject->MajorFunction[18] = (PDRIVER_DISPATCH)&sub_17694;
  DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_17694;
  DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_17694;
  
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\TfSysMon");
  v6 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
  // ... rest of function ...
}
```

**Key Reverse Engineering Findings:**
- **Device Name**: `\\Device\\TfSysMon` (kernel space)
- **Symbolic Link**: `\\DosDevices\\TfSysMon` (user-mode accessible as `\\.\\TfSysMon`)
- **Device Type**: `0x22` = FILE_DEVICE_UNKNOWN
- **IRP Handler**: All major functions point to `sub_17694`
- **Target Function**: MajorFunction[14] = IRP_MJ_DEVICE_CONTROL handler

### 📍 Step 3: Analyze the IRP Dispatch Function

**Navigate to the dispatch function (`sub_17694`):**

```c
__int64 __fastcall sub_17694(struct _DEVICE_OBJECT *a1, IRP *a2)
{
  struct _IO_STACK_LOCATION *CurrentStackLocation; // rdx
  unsigned int v4; // ebx
  
  if ( a1 != DeviceObject )
  {
    v4 = -1073741790;
    goto LABEL_20;
  }
  CurrentStackLocation = a2->Tail.Overlay.CurrentStackLocation;
  v4 = 0;
  if ( !CurrentStackLocation->MajorFunction )
  {
    // Handle IRP_MJ_CREATE
  }
  else if ( CurrentStackLocation->MajorFunction == 2 )
  {
    // Handle IRP_MJ_CLOSE
  }
  else if ( CurrentStackLocation->MajorFunction <= 0xDu )
  {
    goto LABEL_7;
  }
  else if ( CurrentStackLocation->MajorFunction <= 0xFu )
  {
    v4 = sub_177D8(a2);  // THIS IS THE IOCTL HANDLER
    goto LABEL_20;
  }
  // ... rest of function
}
```

**Reverse Engineering Analysis:**
- Device validation occurs first (`if ( a1 != DeviceObject )`)
- `CurrentStackLocation->MajorFunction` determines the operation type
- **CRITICAL**: MajorFunction values 14 (0xE) and 15 (0xF) call `sub_177D8`
- MajorFunction 14 = IRP_MJ_DEVICE_CONTROL = IOCTL processing
- The vulnerable code path is: **IOCTL request → sub_177D8**

### 📍 Step 4: Reverse Engineer the IOCTL Handler

**Navigate to the IOCTL processing function (`sub_177D8`):**

```c
__int64 __fastcall sub_177D8(PIRP Irp, __int64 a2, __int64 a3, __int64 a4)
{
  // ... variable declarations ...
  
  v7 = *(_DWORD *)(a2 + 24);  // Extract IOCTL code
  MasterIrp = Irp->AssociatedIrp.MasterIrp;  // Input buffer
  v9 = *(unsigned int *)(a2 + 16);  // InputBufferLength
  v10 = *(_DWORD *)(a2 + 8);  // OutputBufferLength
  
  if ( v7 > 0xB4A00070 )
  {
    if ( v7 > 0xB4A000F8 )
    {
      if ( v7 != -1264582404 )
      {
        switch ( v7 )
        {
          // ... various cases ...
          case 0xB4A00404:  // VULNERABLE IOCTL CODE
            if ( (unsigned int)v9 >= 0x18 )
              return (unsigned int)sub_1837C((__int64)Irp->AssociatedIrp.MasterIrp);
            break;
          // ... more cases ...
        }
      }
    }
  }
  // ... rest of function
}
```

**Critical Reverse Engineering Discoveries:**
- **IOCTL Extraction**: `v7 = *(_DWORD *)(a2 + 24)` gets the IOCTL code from IO_STACK_LOCATION
- **Input Buffer**: `Irp->AssociatedIrp.MasterIrp` contains user data
- **Buffer Length**: `v9 = *(unsigned int *)(a2 + 16)` gets input buffer size
- **Vulnerable IOCTL**: `0xB4A00404` leads to `sub_1837C`
- **Size Check**: Only validates buffer ≥ 0x18 (24 bytes) - minimal validation!

### 📍 Step 5: Analyze the Vulnerable Function

**Navigate to the process termination function (`sub_1837C`):**

```c
__int64 __fastcall sub_1837C(__int64 a1)
{
  unsigned int v2; // ebx
  void *v3; // rax
  unsigned int v4; // edi
  NTSTATUS v6; // eax
  // ... variable declarations ...
  
  v2 = 0;
  if ( MmIsAddressValid((PVOID)a1) )
  {
    v3 = *(void **)(a1 + 4);  // EXTRACT PID FROM OFFSET +4
    v4 = 0;
    if ( !v3 )
      return 3221225485LL;
    memset(&ObjectAttributes.RootDirectory, 0, 20);
    ObjectAttributes.SecurityDescriptor = 0;
    ObjectAttributes.SecurityQualityOfService = 0;
    ClientId.UniqueThread = 0;
    ObjectAttributes.Length = 48;
    ClientId.UniqueProcess = v3;  // SET TARGET PID
    while ( 1 )
    {
      v6 = ZwOpenProcess(&ProcessHandle, 1u, &ObjectAttributes, &ClientId);
      v7 = v6 < 0;
      v2 = v6;
      if ( !v6 )
        break;
      v8 = v4++;
      if ( v8 >= 3 )
      {
        v7 = v6 < 0;
        break;
      }
    }
    if ( !v7 )
    {
      v9 = 0;
      do
      {
        v2 = ZwTerminateProcess(ProcessHandle, 0);  // TERMINATE PROCESS
        if ( !v2 )
          break;
        v10 = v9++;
      }
      while ( v10 < 3 );
      ZwClose(ProcessHandle);
    }
  }
  return v2;
}
```

**Function Analysis:**
- **Input Structure**: From the driver code analysis, we determined the buffer layout where PID is at offset +4
- **Input Parsing**: `v3 = *(void **)(a1 + 4)` extracts PID from input buffer at offset +4
- **Process Opening**: `ZwOpenProcess` with minimal access rights (1u = PROCESS_TERMINATE)
- **No Security Checks**: No validation of caller privileges or target process protection
- **Process Termination**: Direct call to `ZwTerminateProcess` 
- **Retry Logic**: Multiple attempts for both opening and termination
- **Any Process**: Can terminate any process accessible to SYSTEM account

### 📍 Step 6: Map the Complete Attack Chain

**Complete Reverse Engineering Flow:**
1. **Entry Point**: User calls `DeviceIoControl` on `\\.\\TfSysMon`
2. **IRP Creation**: I/O Manager creates IRP with MajorFunction = 14
3. **Dispatch**: `sub_17694` routes to `sub_177D8` for IOCTL processing
4. **IOCTL Check**: `sub_177D8` validates IOCTL code `0xB4A00404` and buffer size ≥ 24 bytes
5. **Execution**: Calls `sub_1837C` with user input buffer
6. **Termination**: `sub_1837C` extracts PID from offset +4 and terminates process via `ZwTerminateProcess`

**Input Buffer Structure (from driver reverse engineering):**
```
Offset 0x00-0x03: [padding] - 4 bytes
Offset 0x04-0x07: [Target Process ID] - 4 bytes (DWORD)  
Offset 0x08-0x17: [extra_padding] - 16 bytes
Total Size: 24 bytes (0x18) - matches driver's minimum size check
```


> This methodology demonstrates how to systematically reverse engineer any Windows x64 kernel driver to identify similar vulnerabilities by following the execution path from user-mode communication through to dangerous kernel operations.

## 🔗 References
- **Alice Climent-Pommeret's Blog**: [Finding and Exploiting Process Killer Drivers with LOL for $3000](https://alice.climent-pommeret.red/posts/process-killer-driver/)
- **LOLDrivers**: [A Central Repository of Known Vulnerable Drivers](https://www.loldrivers.io/)
- **Microsoft Driver Block Rules**: [Microsoft's Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
- **Windows Kernel Programming** by Pavel Yosifovich
- **Windows Internals, Part 1 & 2** by Mark E. Russinovich, Alex Ionescu, David Solomon

## ⚠️ Disclaimer
**The BYOVD Project** is for **educational and research purposes only**. The author is not responsible for any misuse or damage caused by these programs. Always seek explicit permission before using these tools on any system.

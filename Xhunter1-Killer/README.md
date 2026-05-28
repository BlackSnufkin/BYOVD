# Xhunter1-Killer

Process killer for any target, including PPL processes such as `MsMpEng.exe`, via Wellbia's `xhunter1.sys` (XIGNCODE3 anti-cheat kernel component). The legacy build documented under **CVE-2026-3609**.

The kill primitive is cmd `800` only — a `KeStackAttachProcess` handle stomp that strips `ProtectFromClose` via `ObSetHandleAttributes(KernelMode)` and `ZwClose`s every entry in the target's handle table. Once a critical kernel object is yanked, the target faults on its next I/O and exits.

**Standalone.** Does not use `byovd-lib`. `xhunter1.sys` uses `IRP_MJ_WRITE` (not `DeviceIoControl`) for its command dispatch, so the lib's `DeviceHandle` doesn't fit. Has its own `[workspace]` declaration and its own `[profile.release]`. Build directly from this directory.

**Driver:**
- `xhunter1.sys` SHA256: `e727d0753d2cd0b2f6eeba4cea53aa10b3ff3ed2afeb78f545fcf6d840f85c3e`
- Signer: `Wellbia.com Co., Ltd.` (DigiCert), version `10.0.10011.16384`
- CVE-2026-3609 (re-documented in 2026; originally written up by [Psychotropos in 2018](https://web.archive.org/web/20180820182619/https://x86.re/blog/xigncode3-xhunter1.sys-lpe/))

## What it does

1. Enable `SeDebugPrivilege` on the caller (no-op if not granted).
2. Open `\\.\xhunter1` (or whatever device path you supply with `-d`).
3. Enumerate every handle in the target's handle table via `NtQuerySystemInformation(SystemExtendedHandleInformation)`.
4. **Tier 1 — minimum privileges.** `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + probe cmd `800` with that handle.
5. **Tier 2 — fallback.** If tier 1 is denied at any point (OS-level `ACCESS_DENIED` on `OpenProcess`, or driver-level rejection of the handle inside cmd `800`), fall back to cmd `785` — the original CVE-2026-3609 primitive — to mint a kernel-mode `PROCESS_ALL_ACCESS` handle that defeats PPL.
6. Iterate cmd `800` across the rest of the handle table with whichever handle worked.

Cmd `800` is the only kill mechanism. Cmd `785` is only acquired as a handle source when the cheap path is refused. No `TerminateProcess`, no other driver opcodes.

## Why admin

`PROCESS_QUERY_LIMITED_INFORMATION` is documented as granted to all callers, but in practice:
- Non-admin contexts may have the right stripped by EDR-registered `ObRegisterCallbacks` filters on AV/EDR processes.
- Tier 2's cmd `785` handle leak needs to be reachable from your context (the legacy build has no auth gate, so any caller works — but Defender will revive itself if not running elevated when the kill triggers).

The binary calls `RtlAdjustPrivilege(SeDebugPrivilege)` at startup and prints a warning if the privilege isn't granted. Run elevated.

## Usage

Driver lifecycle is your problem — this tool does **not** install or unload the driver. Load `xhunter1.sys` yourself first via `sc.exe`, then run the exe.

```bat
:: Load
sc create xhunter1 type= kernel binPath= "C:\path\to\xhunter1.sys"
sc start  xhunter1

:: Kill
Xhunter1-Killer.exe -n MsMpEng.exe

:: Cleanup
sc stop   xhunter1
sc delete xhunter1
```

```text
> .\Xhunter1-Killer.exe -h
Process killer via xhunter1.sys cmd 800 handle stomp (legacy CVE-2026-3609 driver)

Usage: Xhunter1-Killer.exe --name <NAME> [--device <DEVICE>]

Options:
  -n, --name   <NAME>    Target process name (e.g. notepad.exe, MsMpEng.exe)
  -d, --device <DEVICE>  Driver device path. Default \\.\xhunter
  -h, --help             Print help
```

```bash
cd Xhunter1-Killer
cargo build --release
.\target\release\Xhunter1-Killer.exe -n MsMpEng.exe -d xhunter1
```

If the driver service is registered under a name other than `xhunter` (the legacy default device name `\Device\xhunter`), pass the service name with `-d` and the binary will prefix `\\.\` for you.

Tested on Windows 11 24H2 against `MsMpEng.exe` (PPL Antimalware-Light). On the first run after a long-lived Defender instance, tier 2 fires (Defender's Ob callback denies the low-priv `OpenProcess`); after the kill Defender restarts, and the next run on the new MsMpEng PID lands cleanly on tier 1.

# Viragt64-Killer
- PoC for the Viragt64 driver from Tg Soft (2016)
- viragt64.sys SHA256: `58A74DCEB2022CD8A358B92ACD1B48A5E01C524C3B0195D7033E4BD55EFF4495`
- I initially developed the POC for personal use and didn't release it because the driver is on the Microsoft recommended driver block rules and in LOLDrivers. However, upon discovering that it's being [abused](https://www.trendmicro.com/en_us/research/24/a/kasseika-ransomware-deploys-byovd-attacks-abuses-psexec-and-expl.html) in the wild, I've decided to share the POC.

Built on [`byovd-lib`](../byovd-lib/) -- implements the `DriverConfig` trait and delegates the full BYOVD flow to the shared library. Note: this driver causes a BSOD on unload, so `skip_unload` is enabled (the driver service is not cleaned up after use).

## Usage

Place `viragt64.sys` in the same directory as the executable (driver file must be named `viragt64.sys`).

```text
BYOVD process killer using viragt64 driver (Tg Soft)

Usage: Viragt64-Killer.exe --name <PROCESS_NAME>

Options:
  -n, --name <PROCESS_NAME>  Target process name (e.g., notepad.exe)
  -h, --help                 Print help
  -V, --version              Print version
```

```bash
# Build
cargo build --release -p Viragt64-Killer

# Run
.\Viragt64-Killer.exe -n notepad.exe
```

Tested on Windows 10 Pro (Up to date)

![Screenshot 2024-01-23 172046](https://github.com/BlackSnufkin/BYOVD/assets/61916899/04a9305d-4b4e-4fff-be08-848706240e38)

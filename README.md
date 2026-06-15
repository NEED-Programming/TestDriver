# Kernel Driver Analysis Toolkit

Static analysis and surface probing pipeline for Windows kernel drivers.
For security research and CTF work in controlled lab environments.

## Files

| File | Purpose |
|---|---|
| `dump_driver.sh` | Disassemble a .sys file into analysis artifacts |
| `analyze_driver.py` | Extract IOCTL surface, imports, struct hints |
| `probe_driver.c` | IOCTL prober — build with mingw, run on Windows VM |
| `read_dump.py` | Parse Windows kernel crash dumps without external libs |

## Workflow

### Step 1 — Dump

```bash
chmod +x dump_driver.sh
./dump_driver.sh target.sys
# Produces:
#   target_disasm.txt   objdump -d Intel syntax
#   target_headers.txt  objdump -x (IAT for import detection)
#   target_strings.txt  ASCII + UTF-16LE strings
#   target_rdata.txt    .rdata section hex dump
```

### Step 2 — Analyze

```bash
python3 analyze_driver.py target_disasm.txt \
    --name target \
    --headers target_headers.txt \
    --strings target_strings.txt \
    --tool
# Produces:
#   target_tool_profile.json   all IOCTLs + dangerous imports + symlink
#   target_structs_full.h      C struct skeletons for each IOCTL handler
```

### Step 3 — Build prober (once on Kali)

```bash
sudo apt install gcc-mingw-w64-x86-64
x86_64-w64-mingw32-gcc -o probe_driver.exe probe_driver.c \
    -lkernel32 -static -O2 -Wall
```

### Step 4 — Load driver on Windows VM

```cmd
:: As Administrator
sc create TARGET type= kernel start= demand binPath= C:\path\to\target.sys
sc start TARGET
sc query TARGET
```

### Step 5 — Probe

```cmd
probe_driver.exe target_tool_profile.json --verbose
```

### Step 6 — Parse crash dumps (if BSOD occurs)

```bash
python3 read_dump.py C:\Windows\Minidump\dump.dmp
# Or set dump type to Small in CrashControl for minidump format
```

## IOCTL Dispatch Pattern Detection

The analyzer handles all four compiled switch forms:

| Form | Pattern | Example |
|---|---|---|
| A | `sub base / cmp bound / jmp [table]` | GCC/clang dense switch |
| B | `cmp eax, imm32 / je handler` | Debug builds, sparse switch |
| C | `mov eax, 0x2220xx / cmp r9d, eax` | MSVC bsearch outer tree |
| D | `sub ecx, base / sub ecx, eax*N / je` | MSVC bsearch inner chain |

## Dangerous Import Tiers

| Tier | Imports | Meaning |
|---|---|---|
| T1 | MmMapIoSpace, MmGetPhysicalAddress | Physical memory access |
| T2 | MmCopyVirtualMemory, ZwMapViewOfSection | Arbitrary virtual memory |
| T3 | READ/WRITE_PORT_* | Direct hardware I/O |
| T5 | PsLookupProcessByProcessId, PsReferencePrimaryToken | Process/token manipulation |
| T6 | ExAllocatePool*, RtlCopyMemory, ProbeForRead/Write | Memory corruption surface |

T1/T2 drivers skip live probing (safe mode) — reachability + imports is sufficient confirmation.

## Windows VM Setup (one-time)

```cmd
bcdedit /set testsigning on
bcdedit /debug on
:: For small crash dumps (easier to parse):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v CrashDumpEnabled /t REG_DWORD /d 3 /f
:: Reboot
shutdown /r /t 0
```

## Known Research Targets

Public CVEs commonly used for driver research and CTF:

| Driver | CVE | Tier |
|---|---|---|
| HEVD.sys | N/A (intentional) | T6 |
| RTCore64.sys | CVE-2019-16098 | T1 |
| AsrDrv101.sys | CVE-2020-15368 | T1 |
| DBUtil_2_3.sys | CVE-2021-21551 | T1/T2 |
| WinIo64.sys | N/A | T1 |

## Dependencies

```bash
# Kali
sudo apt install binutils gcc-mingw-w64-x86-64
pip3 install pefile --break-system-packages   # optional, for PE inspection
```

No Python dependencies required for core analysis — stdlib only.

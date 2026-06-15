#!/usr/bin/env python3
"""
read_dump.py - Parse Windows kernel crash dump (PAGEDUMP64 format)
Extracts CPU context (RIP, RSP, RAX etc.) without any external libraries.

Usage: python3 read_dump.py <dump.dmp>
"""
import struct, sys

def read_dump(path):
    with open(path, 'rb') as f:
        data = f.read()

    sig = data[:4]
    print(f"Signature: {sig}")

    # PAGEDUMP64 = b'PAGE' at offset 0, valid_dump = b'DUMP' at 0x10
    if sig != b'PAGE':
        print(f"Not a kernel dump (got {sig}). Try setting dump type to 'Small' in CrashControl.")
        return

    valid = data[0x10:0x14]
    print(f"ValidDump: {valid}")

    # DUMP_HEADER64 layout (from WDK):
    # 0x000  Signature        4 bytes  'PAGE'
    # 0x004  ValidDump        4 bytes  'DUMP'
    # 0x008  MajorVersion     4 bytes
    # 0x00C  MinorVersion     4 bytes
    # 0x010  DirectoryTableBase 8 bytes
    # 0x018  PfnDataBase      8 bytes
    # 0x020  PsLoadedModuleList 8 bytes
    # 0x028  PsActiveProcessHead 8 bytes
    # 0x030  MachineImageType 4 bytes
    # 0x034  NumberProcessors 4 bytes
    # 0x038  BugCheckCode     4 bytes  <-- stop code
    # 0x03C  pad              4 bytes
    # 0x040  BugCheckParameter1-4  8 bytes each
    # 0x060  ...
    # 0x348  CONTEXT record starts here (x64 kernel dump)

    bugcheck_code = struct.unpack_from('<I', data, 0x038)[0]
    p1 = struct.unpack_from('<Q', data, 0x040)[0]
    p2 = struct.unpack_from('<Q', data, 0x048)[0]
    p3 = struct.unpack_from('<Q', data, 0x050)[0]
    p4 = struct.unpack_from('<Q', data, 0x058)[0]

    print(f"\nBugCheck Code : 0x{bugcheck_code:08X}", end="  ")
    codes = {
        0x50:  "PAGE_FAULT_IN_NONPAGED_AREA",
        0x3B:  "SYSTEM_SERVICE_EXCEPTION",
        0x139: "KERNEL_SECURITY_CHECK_FAILURE",
        0x133: "DPC_WATCHDOG_VIOLATION",
        0xD1:  "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0x7E:  "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0xC5:  "DRIVER_CORRUPTED_EXPOOL",
        0x1E:  "KMODE_EXCEPTION_NOT_HANDLED",
    }
    print(codes.get(bugcheck_code, ""))
    print(f"Parameters    : {hex(p1)} {hex(p2)} {hex(p3)} {hex(p4)}")

    # CONTEXT record in x64 kernel dump is at offset 0x348
    # x64 CONTEXT layout (partial — just what we need):
    # +0x000 ContextFlags
    # +0x030 MxCsr
    # +0x038 SegCs / SegDs / SegEs / SegFs / SegGs / SegSs / EFlags
    # +0x078 Dr0-Dr7
    # +0x0B8 Rax
    # +0x0C0 Rcx
    # +0x0C8 Rdx
    # +0x0D0 Rbx
    # +0x0D8 Rsp
    # +0x0E0 Rbp
    # +0x0E8 Rsi
    # +0x0F0 Rdi
    # +0x0F8 R8
    # +0x100 R9
    # +0x108 R10
    # +0x110 R11
    # +0x118 R12
    # +0x120 R13
    # +0x128 R14
    # +0x130 R15
    # +0x138 Rip  <-- instruction pointer at crash

    # Try a few known CONTEXT offsets for different dump subtypes
    for ctx_off in [0x348, 0x2C0, 0x500, 0x440]:
        if ctx_off + 0x140 > len(data):
            continue
        rip = struct.unpack_from('<Q', data, ctx_off + 0x138)[0]
        rsp = struct.unpack_from('<Q', data, ctx_off + 0x0D8)[0]
        rax = struct.unpack_from('<Q', data, ctx_off + 0x0B8)[0]
        # Sanity check: RIP should look like a kernel or user VA
        if rip == 0 or rip == 0xFFFFFFFFFFFFFFFF:
            continue
        # Good context found
        print(f"\nCONTEXT at offset 0x{ctx_off:X}:")
        print(f"  RIP : 0x{rip:016X}")
        print(f"  RSP : 0x{rsp:016X}")
        print(f"  RAX : 0x{rax:016X}")
        rcx = struct.unpack_from('<Q', data, ctx_off + 0x0C0)[0]
        rdx = struct.unpack_from('<Q', data, ctx_off + 0x0C8)[0]
        rbx = struct.unpack_from('<Q', data, ctx_off + 0x0D0)[0]
        rbp = struct.unpack_from('<Q', data, ctx_off + 0x0E0)[0]
        print(f"  RCX : 0x{rcx:016X}")
        print(f"  RDX : 0x{rdx:016X}")
        print(f"  RBX : 0x{rbx:016X}")
        print(f"  RBP : 0x{rbp:016X}")

        # Check if RIP looks like our cyclic pattern
        try:
            rip_bytes = struct.pack('<Q', rip)
            print(f"\n  RIP as ASCII: {rip_bytes}")
            print(f"  (If this looks like 'abcd...' it's your cyclic pattern)")
        except Exception:
            pass

        # Calculate cyclic offset if RIP is ASCII pattern
        rip_bytes = struct.pack('<Q', rip)
        if all(0x20 <= b <= 0x7e for b in rip_bytes):
            # It's printable ASCII — search in cyclic pattern
            import string
            alpha = string.ascii_lowercase
            pattern = []
            for a in alpha:
                for b in alpha:
                    for c in alpha:
                        for dd in alpha:
                            pattern.append((a+b+c+dd).encode())
                            if len(pattern) * 4 >= 0x1000:
                                break
                        else: continue
                        break
                    else: continue
                    break

            search = rip_bytes.rstrip(b'\x00')
            full_pat = b''.join(pattern)
            idx = full_pat.find(search[:4])
            if idx >= 0:
                print(f"\n  [+] Cyclic pattern found at offset: {idx} (0x{idx:X})")
                print(f"      This is your RIP offset from the start of the input buffer.")
                print(f"      Payload structure: [offset bytes of junk] + [8 bytes RIP]")
            else:
                print(f"\n  [?] RIP is ASCII but not found in cyclic — check buffer size")
        break

    print("\nDone.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 read_dump.py <crash.dmp>")
        sys.exit(1)
    read_dump(sys.argv[1])

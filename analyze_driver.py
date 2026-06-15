#!/usr/bin/env python3
"""
FINAL GENERIC Kernel Driver Analyzer v23
- Jump table / switch normalization detection (HEVD + most compiled drivers)
- Per-IOCTL function scoping for struct offsets and min_input_length
- ExAllocatePool* / RtlCopyMemory added as Tier 6 (memory-corruption primitives)
- LOW-confidence codes excluded from tool profile by default
- All v22 features retained
"""

import re
import sys
import json
import argparse
from collections import OrderedDict, defaultdict

# ====================== OPTIONAL KPH BOOST ======================
KPH_MAGIC = {0x4368704B, 0x5168704B}
BIG_OFFSETS = [0,1,2,3,4,8,10,12,16,18,20,22,24,26,28,31,32,40,44,48,56,64,72,73,74,75,76,77,78,79,80,88,96,101,104,105,112,119,120,124,128,136,140,160,164,224]

KPH_MAP = {
    "0x4368704B": {"name": "KPH_VERIFYCLIENT_MAGIC",  "struct": "KPH_VERIFY_MAGIC_IN"},
    "0x5168704B": {"name": "KPH_VERIFYCLIENT_MAGIC2", "struct": "KPH_VERIFY_MAGIC_IN"},
    "0x99992003": {"name": "KPH_GETFEATURES",         "struct": "KPH_FEATURES_IN"},
    "0x99992007": {"name": "KPH_VERIFYCLIENT",        "struct": "KPH_VERIFY_CLIENT_IN"},
    "0x9999200B": {"name": "KPH_RETRIEVEKEY",         "struct": "KPH_RETRIEVE_KEY_IN"},
    "0x999920CB": {"name": "KPH_OPENPROCESS",         "struct": "KPH_OPENPROCESS_IN"},
    "0x999920CF": {"name": "KPH_OPENPROCESSTOKEN",    "struct": "KPH_OPENPROCESSTOKEN_IN"},
    "0x999920D3": {"name": "KPH_OPENPROCESSJOB",      "struct": "KPH_OPENPROCESSJOB_IN"},
    "0x999920DF": {"name": "KPH_TERMINATEPROCESS",    "struct": "KPH_TERMINATEPROCESS_IN"},
    "0x999920EB": {"name": "KPH_READVIRTUALMEMORYUNSAFE", "struct": "KPH_READVM_IN"},
    "0x999920EF": {"name": "KPH_QUERYINFORMATIONPROCESS", "struct": "KPH_QUERYINFO_PROCESS_IN"},
    "0x999920F3": {"name": "KPH_SETINFORMATIONPROCESS",   "struct": "KPH_SETINFO_PROCESS_IN"},
}

METHOD = ["METHOD_BUFFERED", "METHOD_IN_DIRECT", "METHOD_OUT_DIRECT", "METHOD_NEITHER"]
ACCESS = ["FILE_ANY_ACCESS", "FILE_READ_ACCESS", "FILE_WRITE_ACCESS", "FILE_READ_WRITE_ACCESS"]

# ====================== DANGEROUS PRIMITIVE DETECTION ======================
DANGEROUS_IMPORTS = {
    # Tier 1 — physical memory
    "MmMapIoSpace", "MmMapIoSpaceEx",
    "MmGetPhysicalAddress", "MmAllocateContiguousMemory",
    "MmAllocateContiguousMemorySpecifyCache",
    "MmCopyMemory", "HalTranslateBusAddress",
    # Tier 2 — virtual memory / MDL
    "MmCopyVirtualMemory", "MmProbeAndLockPages",
    "MmMapLockedPagesSpecifyCache", "MmMapLockedPages",
    "ZwMapViewOfSection", "ZwOpenSection",
    "MmAllocatePagesForMdl", "MmAllocatePagesForMdlEx",
    # Tier 3 — port I/O
    "READ_PORT_UCHAR",  "READ_PORT_USHORT",  "READ_PORT_ULONG",
    "WRITE_PORT_UCHAR", "WRITE_PORT_USHORT", "WRITE_PORT_ULONG",
    "READ_REGISTER_UCHAR",  "READ_REGISTER_USHORT",  "READ_REGISTER_ULONG",
    "WRITE_REGISTER_UCHAR", "WRITE_REGISTER_USHORT", "WRITE_REGISTER_ULONG",
    # Tier 5 — process/token manipulation
    "PsLookupProcessByProcessId", "PsLookupThreadByThreadId",
    "PsReferencePrimaryToken", "SeDebugPrivilege",
    "ZwTerminateProcess",
    # Tier 6 — memory corruption primitives (NEW)
    # Presence of pool allocators + copy routines without bounds checks
    # is the fingerprint of stack/pool overflow bugs (HEVD's primary surface).
    "ExAllocatePool", "ExAllocatePool2", "ExAllocatePoolWithTag",
    "ExAllocatePoolWithQuotaTag", "ExAllocatePoolPriorityUninitialized",
    "RtlCopyMemory", "RtlMoveMemory",
    # ProbeFor* absence is the bug, but presence tells us the driver at least
    # tries to validate — useful signal either way.
    "ProbeForRead", "ProbeForWrite",
}

DANGEROUS_IMPORT_TIERS = {
    "MmMapIoSpace": 1, "MmMapIoSpaceEx": 1,
    "MmGetPhysicalAddress": 1, "MmAllocateContiguousMemory": 1,
    "MmAllocateContiguousMemorySpecifyCache": 1,
    "MmCopyMemory": 1, "HalTranslateBusAddress": 1,
    "MmCopyVirtualMemory": 2, "MmProbeAndLockPages": 2,
    "MmMapLockedPagesSpecifyCache": 2, "MmMapLockedPages": 2,
    "ZwMapViewOfSection": 2, "ZwOpenSection": 2,
    "MmAllocatePagesForMdl": 2, "MmAllocatePagesForMdlEx": 2,
    "READ_PORT_UCHAR": 3, "READ_PORT_USHORT": 3, "READ_PORT_ULONG": 3,
    "WRITE_PORT_UCHAR": 3, "WRITE_PORT_USHORT": 3, "WRITE_PORT_ULONG": 3,
    "READ_REGISTER_UCHAR": 3, "READ_REGISTER_USHORT": 3, "READ_REGISTER_ULONG": 3,
    "WRITE_REGISTER_UCHAR": 3, "WRITE_REGISTER_USHORT": 3, "WRITE_REGISTER_ULONG": 3,
    "PsLookupProcessByProcessId": 5, "PsLookupThreadByThreadId": 5,
    "PsReferencePrimaryToken": 5, "SeDebugPrivilege": 5,
    "ZwTerminateProcess": 5,
    # Tier 6 entries (NEW)
    "ExAllocatePool": 6, "ExAllocatePool2": 6, "ExAllocatePoolWithTag": 6,
    "ExAllocatePoolWithQuotaTag": 6, "ExAllocatePoolPriorityUninitialized": 6,
    "RtlCopyMemory": 6, "RtlMoveMemory": 6,
    "ProbeForRead": 6, "ProbeForWrite": 6,
}

# ====================== SURFACE VERIFICATION ======================
DEVICE_CREATE_IMPORTS = {
    "IoCreateDevice", "IoCreateDeviceSecure",
    "WdfDeviceCreate", "WdfControlDeviceInitAllocate",
    "IoCreateUnprotectedSymbolicLink",
}
SYMLINK_IMPORTS = {
    "IoCreateSymbolicLink", "IoCreateUnprotectedSymbolicLink",
    "WdfDeviceCreateSymbolicLink",
}
DISPATCH_IMPORTS = {
    "WdfIoQueueCreate", "WdfDeviceConfigureRequestDispatching",
}
NDIS_MINIPORT_IMPORTS = {
    "NdisMRegisterMiniportDriver", "NdisMSetMiniportAttributes",
}
BOGUS_DEVICE_TYPES = {
    # Obvious poison/sentinel values
    0xFFFF, 0xAAAA, 0xCCCC, 0xDEAD, 0xBA00,
    # 0xBAD0B0B0 debug sentinel (Windows internal / HEVD source)
    0xBAD0,
    # VA fragments at common kernel load bases
    0x1400, 0x1401, 0x1402, 0x1403, 0x1404, 0x1405,
    0x1C00, 0x1C01, 0x1C02, 0x1C03, 0x1C04, 0x1C05,
}

def _is_valid_ioctl_candidate(device: int, full_val: int = 0) -> bool:
    if device in BOGUS_DEVICE_TYPES:
        return False
    severity = (device >> 14) & 0x3
    if severity == 0b11:
        return False
    if severity == 0b10:
        customer_bit = (device >> 13) & 0x1
        if not customer_bit and device <= 0x800F:
            return False
    if 0x1400 <= device <= 0x1410 or 0x1C00 <= device <= 0x1C10:
        return False
    if full_val:
        bytes4 = [(full_val >> s) & 0xFF for s in (0, 8, 16, 24)]
        if all(0x20 <= b <= 0x7E for b in bytes4):
            return False
    return True


CMP_REG32_PATTERN = re.compile(
    r'cmp\s+(?:eax|ebx|ecx|edx|esi|edi|ebp|r(?:8|9|10|11|12|13|14|15)d),\s*(0x[0-9a-fA-F]{6,8})',
    re.IGNORECASE
)

DISPATCH_TABLE_PATTERN = re.compile(
    r'mov\s+QWORD\s+PTR\s+\[(?:r(?:ax|cx|dx|bx|si|di|8|9|10|11))[^]]*\+\s*0x70\]',
    re.IGNORECASE
)

# ====================== SWITCH DISPATCH PATTERNS ======================
#
# Three compiled forms of switch(ioctl_code):
#
# Form A (jump table, dense/GCC):
#   sub eax, 0x222003 / cmp eax, 0x16 / ja default / jmp [rax*8+table]
#
# Form B (direct cmp chain, debug/sparse):
#   cmp eax, 0x222003 / je handler   <- caught by CMP_REG32_PATTERN
#
# Form C (MSVC binary search tree -- HEVD 3.00 x64 release):
#   mov eax, 0x22203b    <- case constant loaded into reg
#   mov eax, 0x22201f
#   sub ecx, 0x222003    <- segment pivot
#   cmp r9d, eax         <- no immediate; value is in eax
#   ja  <next_segment>

SUB_NORMALIZE_RE = re.compile(
    r'\bsub\s+(?:eax|ecx|edx|ebx|r(?:8|9|10|11|12|13|14|15)d),\s*(0x[0-9a-fA-F]{6,8})',
    re.IGNORECASE
)

BOUND_CHECK_RE = re.compile(
    r'\bcmp\s+(?:eax|ecx|edx|ebx|r(?:8|9|10|11|12|13|14|15)d),'
    r'\s*(0x[0-9a-fA-F]{1,4}|[0-9]{1,5})\b',
    re.IGNORECASE
)

JMP_INDIRECT_RE = re.compile(
    r'\bjmp\s+(?:QWORD\s+PTR\s+)?\[',
    re.IGNORECASE
)

MOV_IMM_RE = re.compile(
    r'\bmov\s+(?:eax|ebx|ecx|edx|esi|edi|r(?:8|9|10|11|12|13|14|15)d),'
    r'\s*(0x[0-9a-fA-F]{6,8})',
    re.IGNORECASE
)

JA_RE = re.compile(r'\bj(?:a|ae|b|be|g|ge|l|le)\b', re.IGNORECASE)

# Form D: sub reg,reg and cmp reg,reg (repeated-subtraction dispatch)
SUB_REG_RE = re.compile(
    r'\bsub\s+(?:eax|ecx|edx|ebx),\s*(?:eax|ecx|edx|ebx)\b',
    re.IGNORECASE
)
JE_RE      = re.compile(r'\bj(?:e|z)\b', re.IGNORECASE)
CMP_REG_REG = re.compile(
    r'\bcmp\s+(?:eax|ecx|edx|ebx),\s*(?:eax|ecx|edx|ebx)\b',
    re.IGNORECASE
)

_JUMP_TABLE_WINDOW = 8
_BSEARCH_WINDOW    = 80


def _extract_switch_ioctls(lines):
    """
    Unified switch-dispatch extractor covering four compiled forms:

    Form A  jump table    sub base / cmp bound / jmp [table]
    Form B  cmp chain     cmp eax,imm32 / je    (CMP_REG32_PATTERN)
    Form C  bsearch tree  mov eax,0x2220xx / cmp r9d,eax (MSVC O2)
    Form D  sub chain     sub ecx,base / sub ecx,eax*N / je (HEVD 3.00)

    Returns list of (ioctl_code, source_tag) tuples, all passing
    _is_valid_ioctl_candidate().  Deduplication handled by caller.
    """
    results = []
    n = len(lines)
    seen = set()

    def _emit(val, source):
        if val in seen:
            return
        device = (val >> 16) & 0xFFFF
        if val < 0x100000 or device == 0 or device > 0xFFFF:
            return
        if not _is_valid_ioctl_candidate(device, val):
            return
        seen.add(val)
        results.append((val, source))

    for i, line in enumerate(lines):
        m_sub = SUB_NORMALIZE_RE.search(line)
        if not m_sub:
            continue
        try:
            base = int(m_sub.group(1), 16)
        except ValueError:
            continue
        if base < 0x100000:
            continue
        device = (base >> 16) & 0xFFFF
        if not _is_valid_ioctl_candidate(device, base):
            continue

        # ── Form A: look ahead for bound check + indirect jmp ────────────
        bound = None
        has_indirect_jmp = False
        has_branch = False
        for j in range(i + 1, min(i + 1 + _JUMP_TABLE_WINDOW, n)):
            m_cmp = BOUND_CHECK_RE.search(lines[j])
            if m_cmp and bound is None:
                raw = m_cmp.group(1)
                try:
                    bound = int(raw, 16) if raw.startswith('0x') else int(raw)
                except ValueError:
                    pass
            if JMP_INDIRECT_RE.search(lines[j]):
                has_indirect_jmp = True
                break
            if JA_RE.search(lines[j]):
                has_branch = True

        if bound is not None and has_indirect_jmp:
            count = bound + 1
            if 1 <= count <= 512:
                for k in range(count):
                    _emit(base + k * 4, 'jump_table')
            continue

        # ── Form D: sub-chain detection (HEVD 3.00 MSVC pattern) ────────
        # Pattern: sub ecx,BASE / je / [sub ecx,eax / je]* / cmp ecx,eax / je
        # Each sub ecx,eax subtracts eax (=4) → next IOCTL code in sequence.
        # We scan forward until we stop seeing sub-reg-reg or cmp-reg-reg pairs.
        # Guard: the step value must be 4 (mov eax,4 must appear nearby).
        #
        # Detection: look for "mov eax,0x4" or "mov eax,4" within a few lines
        # after the base sub, then count sub ecx,eax + je pairs.

        # Check for Form D: je immediately after the base sub (case 0 match)
        # and eax=4 setup nearby
        is_form_d = False
        step = 4  # CTL_CODE step is always 4

        # Look for eax=4 setup in window before or after the sub
        eax4_window = range(max(0, i-3), min(n, i+8))
        for j in eax4_window:
            # mov eax,0x4 or mov eax,4
            if re.search(r'\bmov\s+eax,\s*(?:0x4|4)\b', lines[j], re.I):
                is_form_d = True
                break

        # Also trigger Form D if we see je right after the base sub (no eax needed)
        if not is_form_d and i+1 < n and JE_RE.search(lines[i+1]):
            # Verify by checking for sub ecx,eax shortly after
            for j in range(i+2, min(n, i+6)):
                if SUB_REG_RE.search(lines[j]):
                    is_form_d = True
                    break

        if is_form_d:
            # Emit the base code
            _emit(base, 'subchain_base')
            # Walk forward counting sub ecx,eax / je pairs
            current_code = base
            j = i + 1
            while j < min(n, i + 60):
                l = lines[j]
                # sub ecx,eax → next code
                if SUB_REG_RE.search(l):
                    current_code += step
                    _emit(current_code, 'subchain_case')
                # cmp ecx,eax = final case check (same +step).
                # Two compiler forms:
                #   cmp / je  <handler>  → emit, continue (case matched by je)
                #   cmp / jne <default>  → emit, break    (case matched by fall-through)
                elif CMP_REG_REG.search(l):
                    next_line = lines[j+1] if j+1 < n else ''
                    if JE_RE.search(next_line):
                        # je form: match jumps to handler
                        current_code += step
                        _emit(current_code, 'subchain_case')
                        j += 2
                        continue
                    elif re.search(r'\bj(?:ne|nz)\b', next_line, re.I):
                        # jne form: non-match jumps to default; fall-through is the case
                        current_code += step
                        _emit(current_code, 'subchain_case')
                        break  # chain ends here
                    else:
                        break  # cmp with no recognisable branch = end of chain
                # Bare jne/jnz without a preceding cmp = chain already closed
                elif re.search(r'\bj(?:ne|nz)\b', l, re.I):
                    break
                j += 1
            continue  # Form D handled; skip Form C for this sub

        # ── Form C: mov-loaded constants in a bsearch window ─────────────
        win_start = max(0, i - _BSEARCH_WINDOW // 2)
        win_end   = min(n, i + _BSEARCH_WINDOW // 2)
        window_has_branch = has_branch
        mov_codes = []
        for j in range(win_start, win_end):
            if JA_RE.search(lines[j]):
                window_has_branch = True
            m_mov = MOV_IMM_RE.search(lines[j])
            if m_mov:
                try:
                    val = int(m_mov.group(1), 16)
                    dev = (val >> 16) & 0xFFFF
                    if _is_valid_ioctl_candidate(dev, val) and val >= 0x100000:
                        mov_codes.append(val)
                except ValueError:
                    pass

        if not window_has_branch:
            continue

        _emit(base, 'bsearch_base')
        for val in mov_codes:
            _emit(val, 'bsearch_mov')

    return results


def parse_imports_from_headers(headers_path):
    imports = set()
    try:
        with open(headers_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = re.search(r'<none>\s+[0-9a-f]+\s+([A-Za-z_][A-Za-z0-9_@]*)', line)
                if m:
                    imports.add(m.group(1))
    except OSError:
        pass
    return imports


class SurfaceReport:
    def __init__(self):
        self.has_device_create    = False
        self.has_symlink          = False
        self.has_dispatch_slot    = False
        self.has_wdf              = False
        self.is_pure_ndis         = False
        self.device_create_import = None
        self.symlink_import       = None
        self.evidence             = []
        self.headers_used         = False
        self.dangerous_imports    = []

    @property
    def has_ioctl_surface(self):
        if self.is_pure_ndis:
            return False
        if self.has_wdf and self.has_device_create:
            return True
        if self.has_device_create and (self.has_symlink or self.has_dispatch_slot):
            return True
        return False

    def summary(self):
        src = "IAT (headers file)" if self.headers_used else "disasm call targets"
        lines = ["[*] IOCTL surface pre-flight:"]
        lines.append(f"    Import source                   : {src}")
        lines.append(f"    IoCreateDevice/WdfDeviceCreate  : {'YES (' + self.device_create_import + ')' if self.has_device_create else 'NO'}")
        lines.append(f"    Symbolic link creation          : {'YES (' + self.symlink_import + ')' if self.has_symlink else 'NO'}")
        lines.append(f"    MajorFunction[14] assignment    : {'YES' if self.has_dispatch_slot else 'NO'}")
        lines.append(f"    WDF driver                      : {'YES' if self.has_wdf else 'NO'}")
        lines.append(f"    Pure NDIS miniport              : {'YES' if self.is_pure_ndis else 'NO'}")
        if self.dangerous_imports:
            lines.append(f"    Dangerous imports (T1=phys,T2=virt,T3=portio,T5=proc,T6=memcorrupt):")
            for name, tier in sorted(self.dangerous_imports, key=lambda x: x[1]):
                lines.append(f"      [T{tier}] {name}")
        else:
            lines.append(f"    Dangerous imports               : NONE")
        if self.evidence:
            lines.append("    Evidence found:")
            for e in self.evidence:
                lines.append(f"      - {e}")
        lines.append(f"    → Has real IOCTL surface        : {'YES' if self.has_ioctl_surface else 'NO'}")
        return "\n".join(lines)


def _apply_import_signals(imports, report):
    for imp in imports:
        if imp in DEVICE_CREATE_IMPORTS:
            report.has_device_create = True
            report.device_create_import = imp
            report.evidence.append(f"Device-create import: {imp}")
        if imp in SYMLINK_IMPORTS:
            report.has_symlink = True
            report.symlink_import = imp
            report.evidence.append(f"Symlink import: {imp}")
        if imp in DISPATCH_IMPORTS:
            report.has_wdf = True
            report.evidence.append(f"WDF dispatch import: {imp}")
        if imp.startswith("Wdf"):
            report.has_wdf = True
        if imp in DANGEROUS_IMPORTS:
            tier = DANGEROUS_IMPORT_TIERS.get(imp, 0)
            report.dangerous_imports.append((imp, tier))

    ndis_hits = imports & NDIS_MINIPORT_IMPORTS
    if ndis_hits and not report.has_device_create:
        report.is_pure_ndis = True
        report.evidence.append(
            f"NDIS miniport imports (no IoCreateDevice): {', '.join(sorted(ndis_hits))}"
        )


def verify_ioctl_surface(lines, headers_path=None, strings_path=None):
    report = SurfaceReport()

    if headers_path:
        iat_imports = parse_imports_from_headers(headers_path)
        if iat_imports:
            report.headers_used = True
            _apply_import_signals(iat_imports, report)

    call_target_re = re.compile(
        r'call\s+.*?<([A-Za-z_][A-Za-z0-9_@]*)>', re.IGNORECASE
    )
    disasm_imports = set()

    for line in lines:
        for m in call_target_re.finditer(line):
            disasm_imports.add(m.group(1))
        if DISPATCH_TABLE_PATTERN.search(line):
            if not report.has_dispatch_slot:
                report.has_dispatch_slot = True
            report.evidence.append(f"MajorFunction[14] write: {line.strip()}")

    if not report.headers_used:
        _apply_import_signals(disasm_imports, report)

    if strings_path:
        try:
            with open(strings_path, encoding="utf-8", errors="ignore") as sf:
                for sline in sf:
                    s = sline.strip()
                    if re.match(r'\\Device\\[A-Za-z0-9_]+$', s):
                        if not report.has_device_create:
                            report.has_device_create = True
                            report.device_create_import = f"string:{s}"
                        report.evidence.append(f"Device path string: {s}")
                    if (re.match(r'\\DosDevices\\[A-Za-z0-9_]+$', s) or
                            re.match(r'\\\\\.\\.+', s)):
                        if not report.has_symlink:
                            report.has_symlink = True
                            report.symlink_import = f"string:{s}"
                        report.evidence.append(f"Symlink path string: {s}")
        except OSError:
            pass

    return report


# ====================== IOCTL EXTRACTION ======================

class DriverAnalyzer:
    def __init__(self, name, tool_mode=False, force_kph=False):
        self.driver_name  = name
        self.tool_mode    = tool_mode
        self.force_kph    = force_kph
        self.is_kph       = False
        self.ioctls       = OrderedDict()
        self.surface      = None
        # NEW: track jump-table groups for reporting
        self.switch_sources = {}  # tag -> list of codes

    def verify(self, lines, headers_path=None, strings_path=None):
        self.surface = verify_ioctl_surface(
            lines, headers_path=headers_path, strings_path=strings_path
        )
        return self.surface.has_ioctl_surface

    def analyze(self, lines):
        # ── Pass 1: per-function tracking ────────────────────────────────────
        # We need to know which handler function each IOCTL cmp lives in so we
        # can assign the right struct offsets and min_input_length to each code.
        #
        # v22 bug: current_func was read at *assignment* time (end of loop),
        # so all IOCTLs got the offsets from the last function seen.
        #
        # Fix: store "_func" at *discovery* time inside the ioctls dict, then
        # do a second pass to compute per-function metrics and stamp each entry.

        # func_name → {"min_size": int, "offsets": set()}
        func_meta   = defaultdict(lambda: {"min_size": 0, "offsets": set()})
        current_func = None

        CMP_LINE_RE = re.compile(
            r'^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s+cmp\b', re.IGNORECASE
        )

        # ── Pass 1a: jump-table extraction (NEW) ─────────────────────────────
        switch_hits = _extract_switch_ioctls(lines)
        for val, source in switch_hits:
                device = (val >> 16) & 0xFFFF
                if val not in self.ioctls:
                    self.ioctls[val] = {
                        "decoded":    self.decode_ioctl(val),
                        "confidence": "HIGH",
                        "_func":      None,
                        "_from_jt":   source,
                    }
                else:
                    self.ioctls[val]["confidence"] = "HIGH"
                if val in KPH_MAGIC or device == 0x9999:
                    self.is_kph = True

        # ── Pass 1b: cmp-pattern extraction ──────────────────────────────────
        for line in lines:
            m = re.match(r'^([0-9a-f]+) <(.+?)>:', line, re.I)
            if m:
                current_func = m.group(2)

            # HIGH confidence: dedicated cmp-register pattern
            for m in CMP_REG32_PATTERN.finditer(line):
                try:
                    val = int(m.group(1), 16)
                    if val < 0x100000 or val == 0xFFFFFFFF:
                        continue
                    device = (val >> 16) & 0xFFFF
                    if device == 0 or device > 0xFFFF:
                        continue
                    if not _is_valid_ioctl_candidate(device, val):
                        continue
                    if val not in self.ioctls:
                        self.ioctls[val] = {
                            "decoded":    self.decode_ioctl(val),
                            "confidence": "HIGH",
                            "_func":      current_func,
                            "_from_jt":   False,
                        }
                    else:
                        self.ioctls[val]["confidence"] = "HIGH"
                        # Fill in func if jump-table pass left it None
                        if self.ioctls[val].get("_func") is None:
                            self.ioctls[val]["_func"] = current_func
                    if val in KPH_MAGIC or device == 0x9999:
                        self.is_kph = True
                except Exception:
                    continue

            # LOW confidence: inline hex scanner, cmp lines only
            if CMP_LINE_RE.match(line):
                for m in re.finditer(r'0x[0-9a-fA-F]{6,8}', line, re.I):
                    try:
                        val = int(m.group(0), 16)
                        if val < 0x100000 or val == 0xFFFFFFFF:
                            continue
                        device = (val >> 16) & 0xFFFF
                        if device == 0 or device > 0xFFFF:
                            continue
                        if not _is_valid_ioctl_candidate(device, val):
                            continue
                        if val not in self.ioctls:
                            self.ioctls[val] = {
                                "decoded":    self.decode_ioctl(val),
                                "confidence": "LOW",
                                "_func":      current_func,
                                "_from_jt":   False,
                            }
                        if val in KPH_MAGIC or device == 0x9999:
                            self.is_kph = True
                    except Exception:
                        continue

            # Per-function struct offset and min-size tracking
            if current_func:
                for m in re.finditer(
                    r'(?:cmp|ja|jb|jbe|mov|test|lea).*?'
                    r'(?:Length|size|Buffer|cb|InputBufferLength).*?,\s*(0x[0-9a-f]+)',
                    line, re.I
                ):
                    try:
                        size = int(m.group(1), 16)
                        if 0 < size < 0x10000:
                            func_meta[current_func]["min_size"] = max(
                                func_meta[current_func]["min_size"], size
                            )
                    except Exception:
                        pass

                # Capture only buffer-relative field accesses.
                # rdx/r8/r9 hold user input buffer pointers (from IoStackLocation
                # Parameters.DeviceIoControl.Type3InputBuffer or SystemBuffer).
                # rcx = IRP, rsp = stack frame, rax/rbx/r10/r11 = temporaries
                # that frequently point into IRP or kernel structs — excluding
                # these eliminates the 0x088/0x0C8/0x0D8 IRP field offsets that
                # were polluting every struct definition.
                for m in re.finditer(
                    r'\[(?:rdx|r8|r9)\s*\+\s*(0x[0-9a-f]+)\]',
                    line, re.I
                ):
                    off = int(m.group(1), 16)
                    if off < 0x1000:   # sane struct field range (<4K)
                        func_meta[current_func]["offsets"].add(off)

        # ── Pass 2: stamp each IOCTL with its handler's metrics ───────────────
        # For jump-table IOCTLs whose _func is still None (the sub instruction
        # appeared before any function label), fall back to the dispatch function
        # that contains the sub — find it by scanning once more.
        _jt_func = self._find_switch_func(lines)

        use_kph = self.force_kph or self.is_kph
        for code, data in self.ioctls.items():
            func = data.get("_func") or _jt_func or ""
            meta = func_meta.get(func, {"min_size": 0, "offsets": set()})

            kph = KPH_MAP.get(data["decoded"]["raw"], {}) if use_kph else {}
            data["name"] = kph.get(
                "name",
                f"IOCTL_{data['decoded']['device_type']['name']}_{data['decoded']['function']:X}"
            )
            data["risk"]           = kph.get("risk", "MEDIUM")
            data["struct_hint"]    = kph.get("struct", "INPUT_STRUCT")
            data["min_input_length"] = meta["min_size"]
            data["struct_offsets"] = (
                BIG_OFFSETS if (use_kph and kph) else sorted(list(meta["offsets"]))
            )

    def _find_switch_func(self, lines):
        """
        Return the name of the function that contains the first SUB_NORMALIZE_RE
        match.  Used as fallback when jump-table IOCTLs have no _func set.
        """
        current_func = None
        for line in lines:
            m = re.match(r'^([0-9a-f]+) <(.+?)>:', line, re.I)
            if m:
                current_func = m.group(2)
            if SUB_NORMALIZE_RE.search(line):
                return current_func
        return None

    def decode_ioctl(self, code: int):
        device = (code >> 16) & 0xFFFF
        access = (code >> 14) & 3
        func   = (code >> 2)  & 0xFFF
        method = code & 3
        dev_name = "KPROCESSHACKER" if device == 0x9999 else f"0x{device:04X}"
        return {
            "raw": f"0x{code:08X}",
            "device_type": {"value": hex(device), "name": dev_name},
            "function": func,
            "method":   {"value": method, "name": METHOD[method]},
            "access":   {"value": access, "name": ACCESS[access]},
            "ctl_code_macro": (
                f"CTL_CODE(0x{device:X}, 0x{func:X}, {METHOD[method]}, {ACCESS[access]})"
            ),
        }

    def to_json(self):
        profile = {
            "driver":              self.driver_name,
            "is_kprocesshacker":   self.is_kph,
            "switch_sources": {tag: [f"0x{v:08X}" for v in codes] for tag, codes in self.switch_sources.items()},
            "ioctls": [],
        }
        for code in sorted(self.ioctls):
            d = self.ioctls[code]
            entry = {
                "ioctl":            d["decoded"]["raw"],
                "name":             d["name"],
                "confidence":       d.get("confidence", "LOW"),
                "dispatch_source":  d.get("_from_jt", "cmp"),  # jump_table|bsearch_base|bsearch_mov|cmp
                "decoded":          d["decoded"],
                "min_input_length": d["min_input_length"],
                "struct_offsets":   d["struct_offsets"],
                "risk":             d["risk"],
                "struct_hint":      d["struct_hint"],
            }
            profile["ioctls"].append(entry)
        return profile


def generate_tool_profile(analyzer, base_name):
    # Only use HIGH-confidence codes for the tool profile.
    # LOW codes from cmp-line scanner are noisy and not suitable for probing.
    all_candidates = sorted(
        [(code, d) for code, d in analyzer.ioctls.items()
         if d.get("confidence") == "HIGH"],
        key=lambda x: (
            x[1]["min_input_length"],
            len(x[1].get("struct_offsets", [])),
            -x[1]["decoded"]["method"]["value"]
        ),
        reverse=True,
    )

    if not all_candidates:
        print("[!] No HIGH-confidence IOCTLs found — tool profile not generated.")
        print("    Re-run with --headers to improve confidence, or check for jump-table pattern.")
        return

    read_code = all_candidates[0][0]
    write_code = all_candidates[1][0] if len(all_candidates) > 1 else read_code
    read_d  = all_candidates[0][1]
    write_d = all_candidates[1][1] if len(all_candidates) > 1 else read_d

    high_buf_sizes = [d["min_input_length"] for _, d in all_candidates if d["min_input_length"] > 0]
    max_buf = max(high_buf_sizes) if high_buf_sizes else 128
    if max_buf < 64:
        max_buf = 128

    read_method  = read_d.get("decoded", {}).get("method", {}).get("name", "neither").lower().replace("method_", "")
    write_method = write_d.get("decoded", {}).get("method", {}).get("name", "neither").lower().replace("method_", "")

    if read_method == "buffered":
        read_addr, read_size, read_val = 0, 8, 16
    else:
        read_addr, read_size, read_val = 8, 24, 16

    if write_method == "buffered":
        write_addr, write_size, write_val = 0, 8, 16
    else:
        write_addr, write_size, write_val = 8, 16, 0

    symlink = f"\\\\.\\{base_name}"
    if analyzer.surface:
        for ev in analyzer.surface.evidence:
            if ev.startswith("Symlink path string:"):
                raw = ev.split(":", 1)[1].strip()
                symlink = raw.replace("\\DosDevices\\", "\\\\.\\")
                break

    dangerous = []
    if analyzer.surface and analyzer.surface.dangerous_imports:
        for name, tier in sorted(analyzer.surface.dangerous_imports, key=lambda x: x[1]):
            dangerous.append({"name": name, "tier": tier})

    tool_profile = {
        "name":        base_name.upper(),
        "description": f"Auto-generated profile for {base_name}",
        "cve":         "N/A",
        "service":     base_name,
        "symlink":     symlink,
        "sys_path":    "",
        "dangerous_imports": dangerous,
        "can_read":    True,
        "can_write":   True,
        "chunked_rw":  True,
        "max_rw_size": 8,
        "read": {
            "code":             f"0x{read_code:08X}",
            "buffer_size":      max_buf,
            "address_offset":   read_addr,
            "size_offset":      read_size,
            "value_offset":     read_val,
            "value_size":       8,
            "output_mode":      "inplace",
            "out_buffer_size":  0,
            "out_value_offset": 0,
            "method":           read_method,
            "pads":             [],
        },
        "write": {
            "code":             f"0x{write_code:08X}",
            "buffer_size":      max_buf,
            "address_offset":   write_addr,
            "size_offset":      write_size,
            "value_offset":     write_val,
            "value_size":       8,
            "output_mode":      "inplace",
            "out_buffer_size":  0,
            "out_value_offset": 0,
            "method":           write_method,
            "pads":             [],
        },
    }

    # Embed the full IOCTL list so probe_driver.c and manual inspection
    # can enumerate all codes without needing the separate full-profile JSON.
    tool_profile["ioctls"] = []
    for code in sorted(analyzer.ioctls):
        d = analyzer.ioctls[code]
        if d.get("confidence") != "HIGH":
            continue
        tool_profile["ioctls"].append({
            "ioctl":           d["decoded"]["raw"],
            "name":            d["name"],
            "confidence":      d["confidence"],
            "dispatch_source": d.get("_from_jt", "cmp"),
            "decoded":         d["decoded"],
            "min_input_length": d["min_input_length"],
            "struct_offsets":  d["struct_offsets"],
            "risk":            d["risk"],
            "struct_hint":     d["struct_hint"],
        })

    with open(f"{base_name}_tool_profile.json", "w", encoding="utf-8") as f:
        json.dump(tool_profile, f, indent=2)
    print(f"[+] Tool-ready profile ({len(tool_profile['ioctls'])} IOCTLs) → {base_name}_tool_profile.json")


def generate_full_structs(profile, base_name):
    with open(f"{base_name}_structs_full.h", "w", encoding="utf-8") as f:
        f.write("// ================================================\n")
        f.write("// AUTO-GENERATED FULL STRUCTS FOR EVERY IOCTL\n")
        f.write("// ================================================\n")
        f.write("#pragma once\n#include <ntifs.h>\n\n")

        for i in profile["ioctls"]:
            clean_name = i["name"].replace("IOCTL_", "").replace("0x", "IOCTL_")
            offsets  = sorted(i.get("struct_offsets", []))
            min_size = max(i.get("min_input_length", 0), 16)

            f.write(f"// {i['name']} ({i['ioctl']}) — Min size: 0x{min_size:X}")
            if i.get("dispatch_source") and i.get("dispatch_source") != "cmp":
                f.write("  [jump-table]")
            f.write(f"\n")
            f.write(f"typedef struct _{clean_name}_IN {{\n")

            if not offsets:
                f.write(f"    UCHAR Data[0x{min_size:X}];\n")
            else:
                last = 0
                field_idx = 0
                for off in offsets:
                    gap = off - last
                    if gap > 0:
                        if gap >= 8:   f.write(f"    ULONG64 field_{field_idx}_0x{last:03X}; // offset 0x{last:03X}\n")
                        elif gap >= 4: f.write(f"    ULONG   field_{field_idx}_0x{last:03X}; // offset 0x{last:03X}\n")
                        elif gap >= 2: f.write(f"    USHORT  field_{field_idx}_0x{last:03X}; // offset 0x{last:03X}\n")
                        else:          f.write(f"    UCHAR   field_{field_idx}_0x{last:03X}; // offset 0x{last:03X}\n")
                        field_idx += 1
                    last = off + 8
                if min_size > last:
                    f.write(f"    UCHAR padding[0x{min_size:X} - 0x{last:X}];\n")

            f.write(f"}} {clean_name}_IN, *P{clean_name}_IN;\n\n")

    print(f"[+] Full struct typedefs → {base_name}_structs_full.h")


def main():
    parser = argparse.ArgumentParser(
        description="FINAL GENERIC Kernel Driver Analyzer v23"
    )
    parser.add_argument("disasm",               help="objdump -d disassembly file")
    parser.add_argument("--name",  default="driver", help="Driver base name (no extension)")
    parser.add_argument("--headers",            help="objdump -x headers file (strongly recommended)")
    parser.add_argument("--strings",            help="strings file (optional)")
    parser.add_argument("--tool",  action="store_true", help="Output tool-ready profile JSON")
    parser.add_argument("--kph",   action="store_true", help="Enable KPH enhancements")
    parser.add_argument("--force", action="store_true", help="Skip surface check")
    args = parser.parse_args()

    with open(args.disasm, encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    analyzer = DriverAnalyzer(args.name, args.tool, args.kph)

    if not args.headers:
        print("[~] TIP: pass --headers <n>_headers.txt for reliable surface detection.")
        print("    (Full IAT scan — catches indirect calls missed by disasm scanning.)\n")

    surface_ok = analyzer.verify(lines, headers_path=args.headers, strings_path=args.strings)
    print(analyzer.surface.summary())

    if not surface_ok:
        if args.force:
            print("[!] WARNING: No IOCTL surface detected but --force given. Results may be garbage.")
        else:
            print()
            print("[!] ABORTING: No IRP_MJ_DEVICE_CONTROL surface detected.")
            if analyzer.surface.is_pure_ndis:
                print("    • Pure NDIS miniport — uses OID requests, not IOCTLs.")
            if not analyzer.surface.has_device_create:
                print("    • No IoCreateDevice / WdfDeviceCreate import found.")
            if not analyzer.surface.has_symlink and not analyzer.surface.has_dispatch_slot:
                print("    • No symbolic link and no MajorFunction[14] assignment found.")
            print("\n    Re-run with --force to bypass, or add --headers for better detection.")
            sys.exit(1)

    print()

    analyzer.analyze(lines)

    # Report jump-table finds
    if analyzer.switch_sources:
        print(f"[+] Jump-table switch detected:")
        for tag, codes in analyzer.switch_sources.items():
            print(f"    [{tag}] {len(codes)} code(s)")

    if analyzer.is_kph:
        print("[+] KProcessHacker auto-detected!")

    n_high = sum(1 for d in analyzer.ioctls.values() if d.get("confidence") == "HIGH")
    n_low  = sum(1 for d in analyzer.ioctls.values() if d.get("confidence") == "LOW")
    n_jt   = sum(1 for d in analyzer.ioctls.values() if d.get("_from_jt"))
    n_total = n_high + n_low
    print(f"[+] {n_total} IOCTL(s) extracted — HIGH:{n_high}  LOW:{n_low}  (jump-table:{n_jt})")

    if n_low > 0 and n_high == 0:
        print("[~] All extractions are LOW confidence — review manually.")
    if n_total == 0:
        print("[~] No IOCTLs extracted. Check for obfuscation or unsupported dispatch pattern.")

    profile = analyzer.to_json()

    if args.tool:
        generate_tool_profile(analyzer, args.name)
    else:
        out_path = f"{args.name}_profile.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
        print(f"[+] Full profile → {out_path}")

    generate_full_structs(profile, args.name)
    print("[+] Done.")


if __name__ == "__main__":
    main()

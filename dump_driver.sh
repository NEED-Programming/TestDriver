#!/bin/bash
# dump_driver.sh — Disassemble a Windows kernel driver into analysis artifacts
# Usage: ./dump_driver.sh <driver.sys>

DRIVER="$1"
[ -z "$DRIVER" ] || [ ! -f "$DRIVER" ] && {
    echo "Usage: $0 <driver.sys>"
    exit 1
}

BASE=$(basename "$DRIVER" .sys)
echo "[+] Dumping $DRIVER ..."
file "$DRIVER"

# ASCII + UTF-16LE strings (min length 8)
strings -a -n 8 "$DRIVER" > "${BASE}_strings.txt"
echo "--- UTF-16LE strings ---" >> "${BASE}_strings.txt"
strings -el -n 8 "$DRIVER" >> "${BASE}_strings.txt"

# Full headers (IAT — critical for import detection)
objdump -x "$DRIVER" > "${BASE}_headers.txt"

# Intel-syntax disassembly
objdump -d -M intel "$DRIVER" > "${BASE}_disasm.txt"

# .rdata section (string literals, vtables)
objdump -s -j .rdata "$DRIVER" > "${BASE}_rdata.txt"

echo "[+] Done!"
echo ""
echo "Next:"
echo "    python3 analyze_driver.py ${BASE}_disasm.txt --name ${BASE} --headers ${BASE}_headers.txt --strings ${BASE}_strings.txt"
echo "    python3 analyze_driver.py ${BASE}_disasm.txt --name ${BASE} --headers ${BASE}_headers.txt --strings ${BASE}_strings.txt --tool"

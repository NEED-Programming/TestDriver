# Makefile — build probe_driver.exe on Kali
# Requires: sudo apt install gcc-mingw-w64-x86-64

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra -static
LDFLAGS = -lkernel32

.PHONY: all clean check-deps

all: check-deps probe_driver.exe

check-deps:
	@which $(CC) > /dev/null 2>&1 || \
		(echo "[!] Missing: sudo apt install gcc-mingw-w64-x86-64" && exit 1)

probe_driver.exe: probe_driver.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "[+] Built: $@"
	@file $@

clean:
	rm -f probe_driver.exe *.json *.h

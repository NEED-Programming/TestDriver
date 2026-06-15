/*
 * probe_driver.c — IOCTL Surface Prober v2.0
 *
 * Reads a tool_profile.json (either tool or full format) and probes
 * ALL extracted IOCTLs, not just read/write pair.
 *
 * Build on Kali:
 *   x86_64-w64-mingw32-gcc -o probe_driver.exe probe_driver.c \
 *       -lkernel32 -static -O2 -Wall
 *
 * Usage:
 *   probe_driver.exe <tool_profile.json> [--verbose] [--force-pattern]
 *
 * Exit codes:
 *   0 = device not reachable
 *   1 = reachable, no suspicious responses
 *   2 = reachable, at least one STATUS_SUCCESS on null/pattern buffer
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_IOCTLS     128
#define MAX_SYMLINK    256
#define MAX_NAME       128
#define PROBE_BUF_SIZE 512

/* ── minimal JSON helpers ────────────────────────────────────────── */

static const char *json_find_key(const char *json, const char *key)
{
    char search[MAX_NAME + 4];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static int json_get_string(const char *json, const char *key,
                            char *dest, size_t dest_size)
{
    const char *p = json_find_key(json, key);
    if (!p || *p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < dest_size - 1) {
        if (*p == '\\') p++;
        dest[i++] = *p++;
    }
    dest[i] = '\0';
    return 1;
}

static int json_get_hex(const char *json, const char *key, uint32_t *out)
{
    const char *p = json_find_key(json, key);
    if (!p || *p != '"') return 0;
    p++;
    *out = (uint32_t)strtoul(p, NULL, 16);
    return 1;
}

static int json_get_int(const char *json, const char *key, int *out)
{
    const char *p = json_find_key(json, key);
    if (!p) return 0;
    *out = (int)strtol(p, NULL, 10);
    return 1;
}

/* ── profile ─────────────────────────────────────────────────────── */

typedef struct {
    uint32_t code;
    char     name[MAX_NAME];
    char     method[32];
    char     source[32];   /* dispatch_source tag */
    int      buf_size;
} IoctlEntry;

typedef struct {
    char        symlink[MAX_SYMLINK];
    char        driver_name[MAX_NAME];
    IoctlEntry  ioctls[MAX_IOCTLS];
    int         n_ioctls;
    int         tier_flags;
} Profile;

/* Walk the ioctls JSON array and populate profile */
static int parse_ioctls_array(const char *arr_start, Profile *p)
{
    const char *arr = strchr(arr_start, '[');
    if (!arr) return 0;
    arr++;

    while (*arr && *arr != ']' && p->n_ioctls < MAX_IOCTLS) {
        const char *obj = strchr(arr, '{');
        if (!obj) break;

        int depth = 1;
        const char *end = obj + 1;
        while (*end && depth > 0) {
            if (*end == '{') depth++;
            else if (*end == '}') depth--;
            end++;
        }

        size_t len = end - obj;
        char *copy = (char *)malloc(len + 1);
        if (!copy) break;
        memcpy(copy, obj, len);
        copy[len] = '\0';

        uint32_t code = 0;
        if (json_get_hex(copy, "ioctl", &code) && code != 0 && code != 0xBAD0B0B0) {
            int idx = p->n_ioctls;
            p->ioctls[idx].code = code;
            p->ioctls[idx].buf_size = 256;

            json_get_string(copy, "name",             p->ioctls[idx].name,   MAX_NAME);
            json_get_string(copy, "dispatch_source",  p->ioctls[idx].source, 32);

            /* method is nested inside decoded.method.name */
            const char *dec = strstr(copy, "\"decoded\"");
            if (dec) {
                const char *meth = strstr(dec, "\"method\"");
                if (meth) {
                    const char *mname = strstr(meth + 8, "\"name\"");
                    if (mname) {
                        char mstr[64] = {0};
                        json_get_string(mname, "name", mstr, sizeof(mstr));
                        /* normalise to short form */
                        if (strstr(mstr, "BUFFERED"))    strcpy(p->ioctls[idx].method, "buffered");
                        else if (strstr(mstr, "NEITHER")) strcpy(p->ioctls[idx].method, "neither");
                        else if (strstr(mstr, "IN_DIRECT")) strcpy(p->ioctls[idx].method, "in_direct");
                        else if (strstr(mstr, "OUT_DIRECT")) strcpy(p->ioctls[idx].method, "out_direct");
                        else strcpy(p->ioctls[idx].method, "neither");
                    }
                }
            }
            if (p->ioctls[idx].method[0] == '\0')
                strcpy(p->ioctls[idx].method, "neither");

            int bsz = 0;
            json_get_int(copy, "min_input_length", &bsz);
            if (bsz > 16 && bsz <= PROBE_BUF_SIZE) p->ioctls[idx].buf_size = bsz;

            p->n_ioctls++;
        }
        free(copy);
        arr = end;
    }
    return p->n_ioctls;
}

static int load_profile(const char *path, Profile *p)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[!] Cannot open: %s\n", path); return 0; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 4 * 1024 * 1024) {
        fclose(f); fprintf(stderr, "[!] Profile too large or empty\n"); return 0;
    }

    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return 0; }
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);

    memset(p, 0, sizeof(*p));
    json_get_string(buf, "name", p->driver_name, MAX_NAME);

    /* Symlink normalisation */
    char raw[MAX_SYMLINK] = {0};
    if (json_get_string(buf, "symlink", raw, MAX_SYMLINK) && strlen(raw) > 0) {
        const char *dev = raw;
        while (*dev == '\\' || *dev == '.') dev++;
        if (*dev)
            snprintf(p->symlink, MAX_SYMLINK, "\\\\.\\%s", dev);
        else
            snprintf(p->symlink, MAX_SYMLINK, "\\\\.\\%s", p->driver_name);
    } else {
        snprintf(p->symlink, MAX_SYMLINK, "\\\\.\\%s", p->driver_name);
    }

    /* Parse ioctls array — present in both tool_profile and full_profile */
    const char *ioctl_key = strstr(buf, "\"ioctls\"");
    if (ioctl_key) {
        parse_ioctls_array(ioctl_key + 8, p);
    }

    /* Fallback: tool_profile read/write pair if no ioctls array */
    if (p->n_ioctls == 0) {
        const char *read_obj  = strstr(buf, "\"read\"");
        const char *write_obj = strstr(buf, "\"write\"");
        if (read_obj) {
            const char *rb = strchr(read_obj + 6, '{');
            if (rb) {
                int dep = 1; const char *re = rb+1;
                while (*re && dep>0) { if(*re=='{')dep++; else if(*re=='}')dep--; re++; }
                size_t l = re-rb; char *o = (char*)malloc(l+1);
                if (o) { memcpy(o,rb,l); o[l]=0;
                    uint32_t code=0;
                    if (json_get_hex(o,"code",&code) && code && code!=0xBAD0B0B0) {
                        int idx=p->n_ioctls;
                        p->ioctls[idx].code=code;
                        strcpy(p->ioctls[idx].name,"READ");
                        json_get_string(o,"method",p->ioctls[idx].method,32);
                        p->n_ioctls++;
                    }
                    free(o);
                }
            }
        }
        if (write_obj) {
            const char *wb = strchr(write_obj + 7, '{');
            if (wb) {
                int dep=1; const char *we=wb+1;
                while (*we && dep>0) { if(*we=='{')dep++; else if(*we=='}')dep--; we++; }
                size_t l=we-wb; char *o=(char*)malloc(l+1);
                if (o) { memcpy(o,wb,l); o[l]=0;
                    uint32_t code=0;
                    if (json_get_hex(o,"code",&code) && code && code!=0xBAD0B0B0) {
                        int dup=0;
                        for(int i=0;i<p->n_ioctls;i++) if(p->ioctls[i].code==code){dup=1;break;}
                        if (!dup) {
                            int idx=p->n_ioctls;
                            p->ioctls[idx].code=code;
                            strcpy(p->ioctls[idx].name,"WRITE");
                            json_get_string(o,"method",p->ioctls[idx].method,32);
                            p->n_ioctls++;
                        }
                    }
                    free(o);
                }
            }
        }
    }

    /* Dangerous imports tier flags */
    p->tier_flags = 0;
    const char *di = strstr(buf, "\"dangerous_imports\"");
    if (di) {
        const char *as = strchr(di, '[');
        if (as) {
            const char *ap = as+1;
            while (*ap && *ap!=']') {
                const char *ob=strchr(ap,'{'); if(!ob||ob>strchr(ap,']')) break;
                int dep=1; const char *oe=ob+1;
                while(*oe&&dep>0){if(*oe=='{')dep++;else if(*oe=='}')dep--;oe++;}
                size_t ol=oe-ob; char *ent=(char*)malloc(ol+1);
                if(ent){memcpy(ent,ob,ol);ent[ol]=0;
                    int tier=0;
                    if(json_get_int(ent,"tier",&tier)&&tier>=1&&tier<=6)
                        p->tier_flags|=(1<<tier);
                    free(ent);}
                ap=oe;
            }
        }
    }

    free(buf);
    return p->n_ioctls > 0;
}

/* ── NTSTATUS helpers ────────────────────────────────────────────── */

static const char *ntstatus_str(DWORD err)
{
    switch(err) {
        case 0x00000000: return "STATUS_SUCCESS";
        case 0xC0000005: return "STATUS_ACCESS_VIOLATION";
        case 0xC000000D: return "STATUS_INVALID_PARAMETER";
        case 0xC0000010: return "STATUS_INVALID_DEVICE_REQUEST";
        case 0xC0000022: return "STATUS_ACCESS_DENIED";
        case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
        case 0xC00000BB: return "STATUS_NOT_SUPPORTED";
        case 0xC0000001: return "STATUS_UNSUCCESSFUL";
        case 0xC0000023: return "STATUS_BUFFER_TOO_SMALL";
        case 0x80000005: return "STATUS_BUFFER_OVERFLOW";
        case 0xC0000017: return "STATUS_NO_MEMORY";
        case 0xC0000185: return "STATUS_IO_DEVICE_ERROR";
        default: { static char tmp[32]; snprintf(tmp,sizeof(tmp),"0x%08X",(unsigned)err); return tmp; }
    }
}

static DWORD get_status(BOOL ok)
{
    if (ok) return 0;
    DWORD e = GetLastError();
    switch(e) {
        case ERROR_INVALID_PARAMETER:   return 0xC000000D;
        case ERROR_ACCESS_DENIED:       return 0xC0000022;
        case ERROR_INVALID_FUNCTION:    return 0xC0000010;
        case ERROR_NOT_SUPPORTED:       return 0xC00000BB;
        case ERROR_INSUFFICIENT_BUFFER: return 0xC0000023;
        case ERROR_IO_DEVICE:           return 0xC0000185;
        default: return (DWORD)(0xC0000000|(e&0xFFFF));
    }
}

/* ── probe one IOCTL ─────────────────────────────────────────────── */

typedef struct {
    DWORD status_null;
    DWORD status_pattern;
    BOOL  success_null;
    BOOL  success_pattern;
    DWORD bytes_returned;
} ProbeResult;

static ProbeResult probe_ioctl(HANDLE dev, uint32_t code,
                                int buf_size, int verbose)
{
    ProbeResult r = {0};
    if (buf_size <= 0 || buf_size > PROBE_BUF_SIZE) buf_size = PROBE_BUF_SIZE;

    BYTE in_buf[PROBE_BUF_SIZE]  = {0};
    BYTE out_buf[PROBE_BUF_SIZE] = {0};
    DWORD bytes = 0;

    /* Null probe */
    memset(in_buf, 0x00, buf_size);
    BOOL ok = DeviceIoControl(dev, (DWORD)code,
                              in_buf, buf_size,
                              out_buf, buf_size,
                              &bytes, NULL);
    r.status_null  = get_status(ok);
    r.success_null = (r.status_null == 0);
    r.bytes_returned = bytes;
    if (verbose)
        printf("      [null]    -> %s (bytes=%lu)\n", ntstatus_str(r.status_null), bytes);

    /* Pattern probe */
    memset(in_buf, 0x00, buf_size);
    for (int i = 0; i < buf_size; i++) in_buf[i] = (BYTE)(0xAA ^ (i & 0xFF));
    /* Put a safe non-null address at offset 0 and 8 in case driver dereferences */
    uint64_t safe = 0x0000000100000000ULL;
    memcpy(in_buf + 0, &safe, 8);
    memcpy(in_buf + 8, &safe, 8);

    bytes = 0;
    memset(out_buf, 0x00, buf_size);
    ok = DeviceIoControl(dev, (DWORD)code,
                         in_buf, buf_size,
                         out_buf, buf_size,
                         &bytes, NULL);
    r.status_pattern  = get_status(ok);
    r.success_pattern = (r.status_pattern == 0);
    if (verbose)
        printf("      [pattern] -> %s (bytes=%lu)\n", ntstatus_str(r.status_pattern), bytes);

    return r;
}

/* ── main ─────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    int verbose       = 0;
    int force_pattern = 0;
    const char *profile_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v")) verbose = 1;
        else if (!strcmp(argv[i], "--force-pattern")) force_pattern = 1;
        else profile_path = argv[i];
    }

    if (!profile_path) {
        fprintf(stderr,
            "probe_driver.exe <profile.json> [--verbose] [--force-pattern]\n"
            "\n"
            "  Probes ALL IOCTLs extracted by analyze_driver.py.\n"
            "  Reads both tool_profile.json and full_profile.json formats.\n"
            "\n"
            "  --verbose        Show per-probe status codes\n"
            "  --force-pattern  Send pattern buffer even for T1/T2 drivers\n"
            "\n"
            "  Exit: 0=not reachable  1=reachable/clean  2=suspicious responses\n");
        return 0;
    }

    Profile prof;
    if (!load_profile(profile_path, &prof)) {
        fprintf(stderr, "[!] Failed to load profile: %s\n", profile_path);
        return 0;
    }

    printf("=============================================================\n");
    printf(" probe_driver v2.0\n");
    printf(" Driver  : %s\n", prof.driver_name);
    printf(" Symlink : %s\n", prof.symlink);
    printf(" IOCTLs  : %d\n", prof.n_ioctls);
    printf("=============================================================\n\n");

    /* Layer 1 */
    printf("[*] Layer 1 -- Device reachability\n");
    HANDLE dev = CreateFileA(prof.symlink,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (dev == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        switch(err) {
            case ERROR_FILE_NOT_FOUND:
            case ERROR_PATH_NOT_FOUND:
                printf("    [-] Device not found -- driver not loaded\n");
                return 0;
            case ERROR_ACCESS_DENIED:
                printf("    [-] Access denied -- restrictive ACL\n");
                return 0;
            default:
                printf("    [-] CreateFile failed: 0x%08X\n", (unsigned)err);
                return 0;
        }
    }
    printf("    [+] Device opened from current privilege level\n");
    printf("    [+] Handle: %p\n\n", (void*)dev);

    /* T1/T2 safe mode */
    int has_t1 = (prof.tier_flags & (1<<1)) != 0;
    int has_t2 = (prof.tier_flags & (1<<2)) != 0;
    int safe_mode = !force_pattern && (has_t1 || has_t2);

    if (safe_mode) {
        printf("[*] Probing SKIPPED -- T1/T2 physical/virtual memory driver\n");
        printf("    Device reachable from low priv + dangerous imports = exploitable.\n");
        printf("    Use --force-pattern to probe anyway (BSOD risk).\n");
        CloseHandle(dev);
        return 2;
    }

    /* Layer 2+3: probe all IOCTLs */
    printf("[*] Layer 2/3 -- Probing %d IOCTL(s)\n\n", prof.n_ioctls);

    int suspicious = 0, total_null = 0, total_pat = 0;
    int n_padding  = 0;

    for (int i = 0; i < prof.n_ioctls; i++) {
        uint32_t code = prof.ioctls[i].code;

        /* Skip obvious padding/sentinel codes */
        if (code == 0xBAD0B0B0 || code == 0xFFFFFFFF) {
            n_padding++;
            continue;
        }

        printf("    [0x%08X] %-40s\n", code, prof.ioctls[i].name);
        if (verbose)
            printf("      src=%-16s method=%-12s buf=%d\n",
                   prof.ioctls[i].source,
                   prof.ioctls[i].method,
                   prof.ioctls[i].buf_size);

        ProbeResult r = probe_ioctl(dev, code,
                                    prof.ioctls[i].buf_size, verbose);

        printf("      null=%-34s  pattern=%s\n",
               ntstatus_str(r.status_null),
               ntstatus_str(r.status_pattern));

        if (r.success_null) {
            printf("      [!!!] STATUS_SUCCESS on null buffer\n");
            total_null++;
            suspicious++;
        }
        if (r.success_pattern && !r.success_null) {
            printf("      [!!]  STATUS_SUCCESS on pattern buffer\n");
            total_pat++;
            suspicious++;
        }
        if (r.status_null == 0xC0000005 || r.status_pattern == 0xC0000005)
            printf("      [!]   ACCESS_VIOLATION -- possible crash risk\n");
        printf("\n");
    }

    CloseHandle(dev);

    printf("=============================================================\n");
    printf(" RESULTS\n");
    printf("=============================================================\n");
    printf(" Device reachable        : YES\n");
    printf(" IOCTLs probed           : %d  (skipped padding: %d)\n",
           prof.n_ioctls - n_padding, n_padding);
    printf(" SUCCESS on null buffer  : %d\n", total_null);
    printf(" SUCCESS on pattern      : %d\n", total_pat);
    printf(" Suspicious responses    : %d\n", suspicious);

    if (suspicious > 0) {
        printf("\n [!!!] REVIEW MANUALLY\n");
        printf("       IOCTLs above accepted dangerous input.\n");
        return 2;
    } else {
        printf("\n [ok]  No suspicious responses.\n");
        return 1;
    }
}

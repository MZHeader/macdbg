#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>
#include <crt_externs.h>
#include <dlfcn.h>
#include <IOKit/IOKitLib.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <unistd.h>

static const char *bad_env[] = {
    "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_PRINT_LIBRARIES", "DYLD_PRINT_INITIALIZERS", "DYLD_PRINT_BINDINGS",
    "DYLD_IMAGE_SUFFIX", "MallocStackLogging", "MallocStackLoggingNoCompact",
    "NSZombieEnabled", NULL
};

static const char *tool_markers[] = {
    "lldb", "debugserver", "lldb-rpc-server", "frida-server", "frida-trace",
    "hopper", "radare2", "r2", "cutter", "ghidra", "x64dbgi",
    "binaryninja", "gdb", "class-dump", "mitmproxy", "charles", "proxyman",
    "objection", "jtool2", "dtrace", "fs_usage", NULL
};

static const char *image_markers[] = {
    "frida", "Frida", "FridaGadget", "substrate", "Substrate",
    "MobileSubstrate", "SBInjector", "libcycript", "libReveal",
    "RevealServer", "Dobby", "fishhook", "Cycript", "SSLKillSwitch",
    NULL
};

static int marker_boundary(char c) {
    return c == '\0' || c == '/' || c == '\\' || c == '.' || c == '_' || c == '-';
}

static int contains_tool_marker(const char *value) {
    size_t value_len = strlen(value);
    for (int i = 0; tool_markers[i]; i++) {
        const char *marker = tool_markers[i];
        size_t marker_len = strlen(marker);
        for (size_t at = 0; at + marker_len <= value_len; at++) {
            size_t j = 0;
            while (j < marker_len &&
                   tolower((unsigned char)value[at + j]) ==
                   tolower((unsigned char)marker[j]))
                j++;
            if (j != marker_len)
                continue;
            if (marker_len > 2 ||
                (marker_boundary(at == 0 ? '\0' : value[at - 1]) &&
                 marker_boundary(value[at + marker_len])))
                return 1;
        }
    }
    return 0;
}

static int contains_image_marker(const char *value) {
    for (int i = 0; image_markers[i]; i++) {
        const char *marker = image_markers[i];
        size_t marker_len = strlen(marker);
        size_t value_len = strlen(value);
        for (size_t at = 0; at + marker_len <= value_len; at++) {
            size_t j = 0;
            while (j < marker_len &&
                   tolower((unsigned char)value[at + j]) ==
                   tolower((unsigned char)marker[j]))
                j++;
            if (j == marker_len)
                return 1;
        }
    }
    return 0;
}

static int check_environment(void) {
    int bad = 0;
    for (int i = 0; bad_env[i]; i++) bad |= getenv(bad_env[i]) != NULL;
    char **entries = *_NSGetEnviron();
    for (char **p = entries; p && *p; p++)
        for (int i = 0; bad_env[i]; i++) {
            size_t n = strlen(bad_env[i]);
            bad |= strncmp(*p, bad_env[i], n) == 0 && (*p)[n] == '=';
        }
    return bad;
}

static int check_parent(void) {
    pid_t ppid = getppid();
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    struct kinfo_proc info = {0};
    size_t size = sizeof(info);
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, ppid};
    int bad = 0;

    if (proc_pidpath(ppid, path, sizeof(path)) > 0)
        bad |= contains_tool_marker(path);
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0)
        bad |= contains_tool_marker(info.kp_proc.p_comm);
    return bad;
}

static int check_sysctl(void) {
    int hv = -1;
    size_t hvn = sizeof(hv);
    char model[128] = {0};
    char cpu[128] = {0};
    size_t modeln = sizeof(model);
    size_t cpun = sizeof(cpu);

    sysctlbyname("kern.hv_vmm_present", &hv, &hvn, NULL, 0);
    sysctlbyname("hw.model", model, &modeln, NULL, 0);
    sysctlbyname("machdep.cpu.brand_string", cpu, &cpun, NULL, 0);

    int bad = hv != 0 || strcmp(model, "Mac14,6") ||
              strcmp(cpu, "Apple M2 Pro");
    printf("SYSCTL:%s hv=%d model=%s cpu=%s\n",
           bad ? "DETECTED" : "clean", hv, model, cpu);
    return bad;
}

static int copy_cfstring_property(io_registry_entry_t service,
                                  CFStringRef key,
                                  char *output,
                                  size_t output_size) {
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        service, key, kCFAllocatorDefault, 0);
    if (!value || CFGetTypeID(value) != CFStringGetTypeID()) {
        if (value) CFRelease(value);
        return 0;
    }
    Boolean copied = CFStringGetCString(
        (CFStringRef)value, output, output_size, kCFStringEncodingUTF8);
    CFRelease(value);
    return copied;
}

static int check_iokit(void) {
    io_registry_entry_t service = IOServiceGetMatchingService(
        kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
    char serial[128] = {0};
    char uuid[128] = {0};
    int readable = service &&
        copy_cfstring_property(service, CFSTR("IOPlatformSerialNumber"),
                               serial, sizeof(serial)) &&
        copy_cfstring_property(service, CFSTR("IOPlatformUUID"),
                               uuid, sizeof(uuid));
    if (service) IOObjectRelease(service);

    int bad = !readable || strcmp(serial, "C02ZQ0ABC123") ||
              strcmp(uuid, "8D4C7A12-3F65-4B90-A2DE-61C8E5079F34");
    printf("IOKIT:%s serial=%s uuid=%s\n",
           bad ? "DETECTED" : "clean", serial, uuid);
    return bad;
}

static int check_images(const char *path) {
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 2;
    }

    int bad = 0;
    const char *detected = "";
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const char *name = _dyld_get_image_name(index);
        if (name && contains_image_marker(name)) {
            bad = 1;
            detected = name;
            break;
        }
    }
    printf("IMAGES:%s%s%s\n", bad ? "DETECTED" : "clean",
           bad ? " path=" : "", detected);
    dlclose(handle);
    return bad;
}

__attribute__((used, noinline)) void integrity_breakpoint_site(void) {
    __asm__ volatile(".rept 32\n\tnop\n\t.endr");
}

__attribute__((used, noinline)) void integrity_syscall_site(void) {
    __asm__ volatile("svc #0x80");
}

#ifdef CLOAK_INLINE_INTEGRITY
__attribute__((always_inline)) static inline int check_integrity(const char *expected) {
#else
static int check_integrity(const char *expected) {
#endif
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    const struct load_command *command = (const void *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const void *)command;
            const struct section_64 *section = (const void *)(segment + 1);
            for (uint32_t j = 0; j < segment->nsects; j++, section++) {
                if (strcmp(section->segname, "__TEXT") ||
                    strcmp(section->sectname, "__text")) continue;
                unsigned char digest[CC_SHA256_DIGEST_LENGTH];
                char hex[65];
                CC_SHA256((const void *)(section->addr + _dyld_get_image_vmaddr_slide(0)),
                          (CC_LONG)section->size, digest);
                for (int n = 0; n < CC_SHA256_DIGEST_LENGTH; n++)
                    snprintf(hex + 2 * n, 3, "%02x", digest[n]);
                int bad = strcmp(hex, expected) != 0;
                printf("INTEGRITY:%s digest=%s\n", bad ? "DETECTED" : "clean", hex);
                return bad;
            }
        }
        command = (const void *)((const char *)command + command->cmdsize);
    }
    return 66;
}

__attribute__((noinline)) static int check_slow_integrity(const char *digest) {
    sleep(3);
    return check_integrity(digest);
}

static int check_timing(void) {
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || !timebase.denom)
        return 2;
    struct kinfo_proc info = {0};
    size_t n = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    uint64_t start = mach_absolute_time();
    int rc = sysctl(mib, 4, &info, &n, NULL, 0);
    uint64_t end = mach_absolute_time();
    uint64_t ns = (end - start) * timebase.numer / timebase.denom;
    int bad = rc != 0 || ns > 5000000;
    printf("TIMING:%s delta_ns=%llu\n", bad ? "DETECTED" : "clean",
           (unsigned long long)ns);
    return bad;
}

static int check_ptraced(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info = {0};
    size_t n = sizeof(info);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    long rc = syscall(202, mib, 4, &info, &n, NULL, 0);
#pragma clang diagnostic pop
    int bad = rc != 0 || n < sizeof(info) || (info.kp_proc.p_flag & P_TRACED) != 0;
    printf("P_TRACED:%s rc=%ld\n", bad ? "DETECTED" : "clean", rc);
    return bad;
}

static int check_exec(void) {
    /* Harmless even if interception regresses; its final marker proves that
       disk dumps preserve bytes beyond the preview's 200-byte limit. */
    char command[512] = "printf '%s\\n' '";
    for (int i = 0; i < 32; i++) strcat(command, "0123456789");
    strcat(command, "-COMMAND-END'");
    int rc = system(command);
    printf("EXEC:%s rc=%d\n", rc == 0 ? "fake-or-allowed" : "blocked", rc);
    return rc == 0 ? 0 : 1;
}

static uint32_t rotl32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
#define QR(a,b,c,d) do { \
    a += b; d ^= a; d = rotl32(d,16); \
    c += d; b ^= c; b = rotl32(b,12); \
    a += b; d ^= a; d = rotl32(d, 8); \
    c += d; b ^= c; b = rotl32(b, 7); \
} while (0)

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void store32(uint8_t *p, uint32_t v) {
    p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}
static void chacha20_block(uint8_t out[64], const uint8_t key[32],
                           uint32_t counter, const uint8_t nonce[12]) {
    static const uint32_t c[4] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};
    uint32_t s[16], x[16];
    memcpy(s, c, sizeof c);
    for (int i = 0; i < 8; i++) s[4+i] = load32(key + 4*i);
    s[12] = counter;
    for (int i = 0; i < 3; i++) s[13+i] = load32(nonce + 4*i);
    memcpy(x, s, sizeof x);
    for (int i = 0; i < 10; i++) {
        QR(x[0],x[4],x[8],x[12]); QR(x[1],x[5],x[9],x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8],x[13]); QR(x[3],x[4],x[9],x[14]);
    }
    for (int i = 0; i < 16; i++) store32(out + 4*i, x[i] + s[i]);
}
static void chacha20_xor(uint8_t *data, size_t n, const uint8_t key[32]) {
    const uint8_t nonce[12] = {0};
    uint8_t stream[64];
    for (uint32_t block = 0; n; block++) {
        chacha20_block(stream, key, block + 1, nonce);
        size_t take = n < sizeof stream ? n : sizeof stream;
        for (size_t i = 0; i < take; i++) data[i] ^= stream[i];
        data += take; n -= take;
    }
}

static int check_combined(const char *digest, const char *dylib) {
    static const char plaintext[] = "macdbg analysis cloak recovered this payload";
    const uint8_t password[32] = "macdbg-fixture-password-v1";
    uint8_t candidate[32], key[32], payload[sizeof(plaintext) - 1];
    memcpy(candidate, password, sizeof(candidate));
    memcpy(payload, plaintext, sizeof(payload));
    CC_SHA256(password, sizeof(password), key);
    chacha20_xor(payload, sizeof(payload), key);

    int failures[8];
    failures[0] = check_environment();
    printf("ENV:%s\n", failures[0] ? "DETECTED" : "clean");
    failures[1] = check_parent();
    printf("PARENT:%s\n", failures[1] ? "DETECTED" : "clean");
    failures[2] = check_sysctl();
    failures[3] = check_iokit();
    failures[4] = check_images(dylib);
    failures[5] = check_integrity(digest);
    failures[6] = check_timing();
    failures[7] = check_ptraced();
    for (int i = 0; i < 8; i++)
        if (failures[i]) candidate[i] ^= (uint8_t)(0x31 + i);
    CC_SHA256(candidate, sizeof(candidate), key);
    chacha20_xor(payload, sizeof(payload), key);
    if (memcmp(payload, plaintext, sizeof(payload)) != 0) {
        puts("PAYLOAD:unavailable");
        return 1;
    }
    printf("PAYLOAD:%.*s\n", (int)sizeof(payload), payload);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 64;
    if (strcmp(argv[1], "timing") == 0) return check_timing();
    if (strcmp(argv[1], "ptraced") == 0) return check_ptraced();
    if (strcmp(argv[1], "exec") == 0) return check_exec();
    if (strcmp(argv[1], "combined") == 0)
        return argc == 4 ? check_combined(argv[2], argv[3]) : 64;
    if (strcmp(argv[1], "integrity") == 0)
        return argc == 3 ? check_integrity(argv[2]) : 64;
    if (strcmp(argv[1], "integrity_slow") == 0)
        return argc == 3 ? check_slow_integrity(argv[2]) : 64;
    if (strcmp(argv[1], "env") == 0) {
        int bad = check_environment();
        printf("ENV:%s\n", bad ? "DETECTED" : "clean");
        return bad;
    }
    if (strcmp(argv[1], "parent") == 0) {
        int bad = check_parent();
        printf("PARENT:%s\n", bad ? "DETECTED" : "clean");
        return bad;
    }
    if (strcmp(argv[1], "sysctl") == 0)
        return check_sysctl();
    if (strcmp(argv[1], "iokit") == 0)
        return check_iokit();
    if (strcmp(argv[1], "images") == 0)
        return argc == 3 ? check_images(argv[2]) : 64;
    return 65;
}

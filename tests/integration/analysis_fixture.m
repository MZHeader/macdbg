#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <CoreFoundation/CoreFoundation.h>
#include <crt_externs.h>
#include <dlfcn.h>
#include <IOKit/IOKitLib.h>
#include <libproc.h>
#include <mach-o/dyld.h>
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

int main(int argc, char **argv) {
    if (argc < 2) return 64;
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

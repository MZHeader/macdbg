#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <crt_externs.h>
#include <libproc.h>
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

int main(int argc, char **argv) {
    if (argc != 2) return 64;
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
    return 65;
}

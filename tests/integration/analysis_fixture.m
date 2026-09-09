#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crt_externs.h>

static const char *bad_env[] = {
    "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
    "DYLD_PRINT_LIBRARIES", "DYLD_PRINT_INITIALIZERS", "DYLD_PRINT_BINDINGS",
    "DYLD_IMAGE_SUFFIX", "MallocStackLogging", "MallocStackLoggingNoCompact",
    "NSZombieEnabled", NULL
};

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

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    if (strcmp(argv[1], "env") == 0) {
        int bad = check_environment();
        printf("ENV:%s\n", bad ? "DETECTED" : "clean");
        return bad;
    }
    return 65;
}

/* A benign, linked host double: deterministic sysctl lengths, not injection. */
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

int sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                 void *newp, size_t newlen) {
    int model = strcmp(name, "hw.model") == 0;
    int cpu = strcmp(name, "machdep.cpu.brand_string") == 0;
    int hv = strcmp(name, "kern.hv_vmm_present") == 0;
    int hostuuid = strcmp(name, "kern.hostuuid") == 0;
    if (!model && !cpu && !hv && !hostuuid) {
        int (*real_query)(const char *, void *, size_t *, void *, size_t) =
            dlsym(RTLD_NEXT, "sysctlbyname");
        return real_query(name, oldp, oldlenp, newp, newlen);
    }
    if (newp || newlen || !oldlenp) {
        errno = newp ? EPERM : newlen ? EINVAL : EFAULT;
        return -1;
    }
    const char *forced_error = getenv("MACDBG_TEST_SYSCTL_ERROR");
    if (forced_error && atoi(forced_error)) {
        errno = atoi(forced_error);
        return -1;
    }

    const char *scenario = getenv("MACDBG_TEST_SYSCTL_HOST");
    size_t real_size = hv ? 4 : hostuuid ? 37 : model ? 8 : 13;
    if (!hv && scenario && strcmp(scenario, "shorter") == 0) real_size = 2;
    if (!hv && scenario && strcmp(scenario, "longer") == 0)
        real_size = model || hostuuid ? 64 : 80;
    unsigned char value[80];
    memset(value, 'H', real_size);
    value[real_size - 1] = 0;
    if (hv) { uint32_t present = 1; memcpy(value, &present, sizeof(present)); }

    size_t capacity = oldp ? *oldlenp : 0;
    int rc = oldp && capacity < real_size ? -1 : 0;
    if (rc) {
        *oldlenp = 0;  /* Match the real Darwin short-string query result. */
    } else {
        if (oldp) memcpy(oldp, value, real_size);
        *oldlenp = real_size;
    }
    printf("HOST-SYSCTL:%s real=%zu capacity=%zu rc=%d\n",
           name, real_size, capacity, rc);
    if (rc) errno = ENOMEM;
    return rc;
}

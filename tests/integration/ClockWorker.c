#include <mach/mach_time.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>

void *clock_worker(void *opaque) {
    unsigned rounds = *(unsigned *)opaque;
    uint64_t previous = 0;
    for (unsigned i = 0; i < rounds; ++i) {
        uint64_t now = mach_absolute_time();
        if (now < previous) return (void *)(uintptr_t)1;
        previous = now;
        struct timespec value;
        if (clock_gettime(CLOCK_MONOTONIC, &value)) return (void *)(uintptr_t)2;
    }
    return NULL;
}

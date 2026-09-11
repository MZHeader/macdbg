#include <dlfcn.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void *local_clock_worker(void *opaque) {
    unsigned rounds = *(unsigned *)opaque;
    uint64_t previous = 0, previous_ns = 0;
    for (unsigned i = 0; i < rounds; ++i) {
        uint64_t now = mach_absolute_time();
        if (now < previous) return (void *)(uintptr_t)1;
        previous = now;
        struct timespec value;
        if (clock_gettime(CLOCK_MONOTONIC, &value)) return (void *)(uintptr_t)2;
        uint64_t ns = (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
        if (ns < previous_ns) return (void *)(uintptr_t)3;
        previous_ns = ns;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    void *image = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!image) return 3;
    void *(*worker)(void *) = dlsym(image, "clock_worker");
    if (!strcmp(argv[1], "local")) worker = local_clock_worker;
    if (!worker) return 4;
    unsigned rounds = argc > 3 ? (unsigned)strtoul(argv[3], NULL, 10) : 64;
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; ++i)
        if (pthread_create(&threads[i], NULL, worker, &rounds)) return 5;
    int bad = 0;
    for (unsigned i = 0; i < 4; ++i) {
        void *result;
        if (pthread_join(threads[i], &result)) return 6;
        if (result) {
            printf("WORKER:%u error=%lu\n", i, (unsigned long)result);
            bad = 1;
        }
    }
    dlclose(image);
    printf("CONTENTION:%s\n", bad ? "failed" : "clean");
    return bad;
}

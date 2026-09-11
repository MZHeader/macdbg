/* Benign timing regression fixture: arithmetic, local clocks and stdout only. */
#include <dlfcn.h>
#include <errno.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

extern uint32_t timing_result(uint64_t);
extern uint32_t timing_mask(uint64_t);
extern uint32_t timing_branch(uint64_t);
extern uint64_t timing_clock_probe(void);
static const char *clock_source, *decision_style;
static unsigned delay_us;
static int use_max;
static mach_timebase_info_data_t timebase;
static uint64_t (*dynamic_clock)(void);

__attribute__((noinline)) void timing_pause(void) {
    __asm__ volatile("nop");
}

static uint64_t now(void) {
    if (!strcmp(clock_source, "monotonic")) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts)) abort();
        return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
    }
    if (!strcmp(clock_source, "wall")) {
        struct timeval tv;
        if (gettimeofday(&tv, NULL)) abort();
        return (uint64_t)tv.tv_sec * 1000000000 + (uint64_t)tv.tv_usec * 1000;
    }
    uint64_t ticks;
    if (!strcmp(clock_source, "counter") || !strcmp(clock_source, "physical")) {
        uint64_t frequency;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
        if (!strcmp(clock_source, "physical"))
            __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(ticks) :: "memory");
        else
            __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(ticks) :: "memory");
        if (!frequency) abort();
        return (uint64_t)((__uint128_t)ticks * 1000000000 / frequency);
    }
    else if (!strcmp(clock_source, "dynamic")) ticks = dynamic_clock();
    else if (!strcmp(clock_source, "continuous")) ticks = mach_continuous_time();
    else if (!strcmp(clock_source, "probe")) ticks = timing_clock_probe();
    else ticks = mach_absolute_time();
    return (uint64_t)((__uint128_t)ticks * timebase.numer / timebase.denom);
}

static void *exercise(void *unused) {
    (void)unused;
    uint64_t selected = use_max ? 0 : UINT64_MAX;
    for (unsigned pass = 0; pass != 3; ++pass) {
        uint64_t start = now();
        volatile uint32_t accumulator = 0;
        for (uint32_t i = 0; i != 12000; ++i) accumulator ^= i;
        timing_pause();
        if (delay_us) usleep(delay_us);
        uint64_t duration = now() - start;
        if (use_max ? duration > selected : duration < selected) selected = duration;
    }
    uint32_t state;
    if (!strcmp(decision_style, "mask")) state = timing_mask(selected);
    else if (!strcmp(decision_style, "branch")) state = timing_branch(selected);
    else state = timing_result(selected);
    /* A nonzero timing contribution changes the key and the recovered text. */
    uint32_t key = state ^ 0x40000000;
    char recovered[] = "local timing fixture recovered";
    for (size_t i = 0; i != sizeof(recovered) - 1; ++i)
        recovered[i] ^= (uint8_t)key;
    int clean = key == 0 && !strcmp(recovered, "local timing fixture recovered");
    printf("TIMING:%s source=%s aggregate=%s ns=%llu state=%08x\n",
           clean ? "clean" : "detected", clock_source, use_max ? "max" : "min",
           (unsigned long long)selected, state);
    if (clean) puts("PAYLOAD:local timing fixture recovered");
    return (void *)(uintptr_t)!clean;
}

static uint64_t mach_ns(uint64_t ticks) {
    return (uint64_t)((__uint128_t)ticks * timebase.numer / timebase.denom);
}

static int clock_contracts(void) {
    uint64_t previous = mach_absolute_time();
    timing_pause();
    uint64_t current = mach_absolute_time();
    if (current < previous) return 1;
    previous = current;
    for (unsigned i = 0; i != 24; ++i) {
        current = mach_absolute_time();
        if (current < previous) return 1;
        previous = current;
    }
    uint64_t start = mach_absolute_time();
    usleep(30000);
    uint64_t slept = mach_ns(mach_absolute_time() - start);
    start = mach_absolute_time();
    uint64_t delta = (uint64_t)((__uint128_t)30000000 * timebase.denom / timebase.numer);
    if (mach_wait_until(start + delta)) return 1;
    uint64_t waited = mach_ns(mach_absolute_time() - start);
    struct timespec ts = {17, 23};
    errno = 0;
    if (clock_gettime((clockid_t)-1, &ts) != -1 || errno != EINVAL) return 1;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts)) return 1;
    errno = EDOM;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) || errno != EDOM) return 1;
    struct { struct timeval tv; uint64_t guard; } output = {{0, 0}, 0x12345678};
    if (gettimeofday(&output.tv, NULL) || output.guard != 0x12345678) return 1;
    if (slept < 20000000 || waited < 20000000) return 1;
    printf("CONTRACTS:clean sleep_ns=%llu wait_ns=%llu\n",
           (unsigned long long)slept, (unsigned long long)waited);
    return 0;
}

int main(int argc, char **argv) {
    clock_source = argc > 1 ? argv[1] : "mach";
    delay_us = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 0) : 0;
    if (delay_us > 100000) return 2;
    decision_style = argc > 3 ? argv[3] : "penalty";
    use_max = argc > 4 && !strcmp(argv[4], "max");
    if (mach_timebase_info(&timebase) || !timebase.denom) return 2;
    dynamic_clock = (uint64_t (*)(void))dlsym(RTLD_DEFAULT, "mach_absolute_time");
    if (!dynamic_clock) return 2;
    if (!strcmp(clock_source, "contracts")) return clock_contracts();
    if (argc > 5 && !strcmp(argv[5], "threads")) {
        pthread_t workers[2];
        for (unsigned i = 0; i != 2; ++i)
            if (pthread_create(&workers[i], NULL, exercise, NULL)) return 2;
        uintptr_t failed = 0;
        for (unsigned i = 0; i != 2; ++i) {
            void *result;
            if (pthread_join(workers[i], &result)) return 2;
            failed |= (uintptr_t)result;
        }
        return (int)failed;
    }
    return (int)(uintptr_t)exercise(NULL);
}

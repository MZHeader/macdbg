/* Host-only counter reader; loaded into the debugger, never the target. */
#include <stdint.h>

uint64_t macdbg_cntvct(void) {
    uint64_t value;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(value) :: "memory");
    return value;
}

uint64_t macdbg_cntpct(void) {
    uint64_t value;
    __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(value) :: "memory");
    return value;
}

uint64_t macdbg_cntfrq(void) {
    uint64_t value;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
    return value;
}

#include <os/lock.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile sig_atomic_t seen;
static void trap_handler(int signo) {
    seen = signo == SIGTRAP;
    __asm__ volatile("mov x8, #0x99\nmovi v0.16b, #0x33" ::: "x8", "v0");
}

extern unsigned long trap_context_probe(void);
__asm__(".text\n.align 2\n.globl _trap_context_probe\n_trap_context_probe:\n"
        "stp x29, x30, [sp, #-16]!\nmov x29, sp\n"
        "mov x0, #0x1234\nmov x8, #0x5678\n"
        "movi v0.16b, #0x5a\ncmp xzr, x0\n"
        "brk #0\nb.pl 1f\numov w9, v0.b[0]\ncmp w9, #0x5a\nb.ne 1f\n"
        "add x0, x0, x8\nb 2f\n1: mov x0, #0\n2:\n"
        "ldp x29, x30, [sp], #16\nret\n");

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "unhandled";
    if (!strcmp(mode, "system")) {
        os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
        os_unfair_lock_lock(&lock);
        os_unfair_lock_lock(&lock);
        return 3;
    }
    if (!strcmp(mode, "handler") || !strcmp(mode, "context") || !strcmp(mode, "masked")) {
        struct sigaction action = {0};
        action.sa_handler = trap_handler;
        if (!strcmp(mode,"masked")) sigaddset(&action.sa_mask,SIGUSR1);
        if (sigaction(SIGTRAP, &action, NULL)) return 2;
    }
    if (!strcmp(mode, "context")) {
        unsigned long value = trap_context_probe();
        printf("TRAP:context=%lx handler=%d\n", value, seen);
        return value != 0x68ac || !seen;
    }
    __asm__ volatile("brk #0");
    printf("TRAP:handler=%d\n", (int)seen);
    return seen ? 0 : 1;
}

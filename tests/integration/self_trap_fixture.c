#include <os/lock.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static volatile sig_atomic_t seen;
static void trap_handler(int signo) { seen = signo == SIGTRAP; }

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "unhandled";
    if (!strcmp(mode, "system")) {
        os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
        os_unfair_lock_lock(&lock);
        os_unfair_lock_lock(&lock);
        return 3;
    }
    if (!strcmp(mode, "handler")) {
        struct sigaction action = {0};
        action.sa_handler = trap_handler;
        if (sigaction(SIGTRAP, &action, NULL)) return 2;
    }
    __asm__ volatile("brk #0");
    printf("TRAP:handler=%d\n", (int)seen);
    return seen ? 0 : 1;
}

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((constructor)) static void initializer(void) {
    if (getenv("MACDBG_TEST_EARLY_PTRACE")) {
        puts("INITIALIZER"); fflush(stdout);
        if (!strcmp(getenv("MACDBG_TEST_EARLY_PTRACE"), "syscall"))
            syscall(SYS_ptrace, (long)PT_DENY_ATTACH, 0L, 0L, 0L);
        else
            ptrace(PT_DENY_ATTACH, 0, 0, 0);
    }
}
__attribute__((noinline)) void workflow_marker(void) { __asm__ volatile("nop"); }
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "io";
    if (!strcmp(mode, "exec")) return system("printf 'BENIGN_EXECUTED\\n'");
    if (!strcmp(mode, "fork")) {
        if (fork() == 0) { puts("BENIGN_CHILD_PATH"); fflush(stdout); _exit(0); }
        return 0;
    }
    if (!strcmp(mode, "wait")) { sleep(60); return 0; }
    if (!strcmp(mode, "create")) {
        if (argc != 3) return 64;
        umask(0);
        int fd = open(argv[2], O_CREAT | O_EXCL | O_WRONLY, 0600);
        struct stat st;
        if (fd < 0 || fstat(fd, &st)) return 2;
        printf("mode=%04o\n", st.st_mode & 07777);
        errno = E2BIG;
        if (write(fd, "x", 1) != 1) return 3;
        printf("success_errno=%d\n", errno);
        errno = 0;
        if (write(fd, (const void *)1, 1) != -1) return 4;
        printf("fault_errno=%d\n", errno);
        close(fd);
        errno = 0;
        if (open((const char *)1, O_RDONLY) != -1) return 5;
        printf("open_errno=%d\n", errno);
        return 0;
    }
    int fd = open(argv[0], O_RDONLY);
    struct stat st;
    char buffer[16];
    if (fd < 0 || fstat(fd, &st) || read(fd, buffer, sizeof buffer) < 0) return 2;
    close(fd);
    workflow_marker();
    puts("WORKFLOW_COMPLETE");
    return 0;
}

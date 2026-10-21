#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <SystemConfiguration/SystemConfiguration.h>

static volatile sig_atomic_t handled;
static void handler(int sig, siginfo_t *info, void *context) {
    handled = sig == SIGUSR1 && info && context;
}
__attribute__((noinline)) void environment_marker(void) { __asm__ volatile("nop"); }
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct sigaction action = {.sa_sigaction=handler, .sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR1, &action, NULL);
    if (!strcmp(argv[1], "reachability")) {
        SCNetworkReachabilityRef reference=SCNetworkReachabilityCreateWithName(NULL,"connectivity.macdbg.invalid");
        if (!reference) return 14;
        SCNetworkReachabilityFlags flags=0;
        Boolean success=SCNetworkReachabilityGetFlags(reference,&flags);
        CFRelease(reference);
        printf("REACHABLE:%u flags=%u\n",success,flags);
        return success && flags==kSCNetworkReachabilityFlagsReachable ? 0 : 15;
    }
    if (!strcmp(argv[1], "trace")) {
        char byte;
        ssize_t result=read(-1,&byte,1);
        environment_marker();
        return result==-1?0:13;
    }
    if (!strcmp(argv[1], "signal")) {
        raise(SIGUSR1);
        printf("CONTEXT:%d\n", handled);
        return handled ? 0 : 3;
    }
    if (!strcmp(argv[1], "network")) {
        struct addrinfo hints = {.ai_family=AF_INET, .ai_socktype=SOCK_STREAM}, *result = NULL;
        int error = getaddrinfo("connectivity.macdbg.invalid", "80", &hints, &result);
        if (error) { printf("DNS:%d\n", error); return 4; }
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(fd, result->ai_addr, result->ai_addrlen)) { perror("connect"); freeaddrinfo(result); close(fd); return 5; }
        freeaddrinfo(result);
        const char request[] = "GET /online HTTP/1.0\r\nHost: connectivity.macdbg.invalid\r\n\r\n";
        send(fd, request, sizeof(request)-1, 0);
        char response[4096]; size_t size=0; ssize_t got;
        while (size<sizeof(response)-1 && (got=recv(fd,response+size,sizeof(response)-size-1,0))>0) size+=(size_t)got;
        response[size]=0; close(fd);
        printf("HTTP:%s\n", response);
        return strstr(response," 200 ") && strstr(response,"fixture-online") ? 0 : 6;
    }
    if (!strcmp(argv[1], "mapping")) {
        void *code=mmap(NULL, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        if (code==MAP_FAILED) return 7;
        const uint32_t instructions[]={0xd2800290,0xd4001001,0xd65f03c0}; /* getpid, svc #0x80, ret */
        memcpy(code,instructions,sizeof(instructions));
        if(mprotect(code,16384,PROT_READ|PROT_EXEC)) { munmap(code,16384); return 8; }
        environment_marker();
        int observed=((int(*)(void))code)();
        munmap(code,16384);
        printf("MAPPING:%d\n",observed==getpid());
        return observed==getpid()?0:9;
    }
    if (!strcmp(argv[1], "child")) {
        pid_t child=fork();
        if (child<0) return 10;
        if (!child) { while(!handled) usleep(10000); _exit(0); }
        printf("CHILD:%d\n", child); fflush(stdout);
        environment_marker();
        kill(child,SIGUSR1); int status=0; waitpid(child,&status,0);
        return WIFEXITED(status)?WEXITSTATUS(status):11;
    }
    return 12;
}

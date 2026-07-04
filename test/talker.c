// talker.c — exercises file, process, and network APIs the tracer watches.
// Debuggable (not SIP-protected). Doesn't send anything sensitive.
//
// Build: clang -O0 -g talker.c -o talker

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    // --- FILE: open/read/close --------------------------------------------
    int fd = open("/etc/hosts", 0);            // O_RDONLY
    if (fd >= 0) {
        char buf[128];
        ssize_t n = read(fd, buf, sizeof(buf));
        printf("read %zd bytes from /etc/hosts\n", n);
        close(fd);
    }

    // --- FILE: fopen/fread/fclose (higher-level) --------------------------
    FILE *f = fopen("/etc/services", "r");
    if (f) {
        char line[128];
        if (fgets(line, sizeof(line), f)) {
            printf("first line of /etc/services: %s", line);
        }
        fclose(f);
    }

    // --- PROC: popen ------------------------------------------------------
    FILE *p = popen("uname -a", "r");
    if (p) {
        char buf[256];
        if (fgets(buf, sizeof(buf), p)) {
            printf("uname: %s", buf);
        }
        pclose(p);
    }

    // --- NET: getaddrinfo + socket + connect + send + recv ----------------
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo("example.com", "80", &hints, &res);
    if (rc == 0 && res) {
        int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s >= 0 && connect(s, res->ai_addr, res->ai_addrlen) == 0) {
            const char *req =
                "GET / HTTP/1.0\r\nHost: example.com\r\nUser-Agent: talker/0.1\r\n\r\n";
            send(s, req, strlen(req), 0);
            char resp[512];
            ssize_t rn = recv(s, resp, sizeof(resp) - 1, 0);
            if (rn > 0) {
                resp[rn] = '\0';
                // just print the first line
                char *nl = strchr(resp, '\n');
                if (nl) *nl = '\0';
                printf("http: %s\n", resp);
            }
            close(s);
        }
        freeaddrinfo(res);
    }
    return 0;
}

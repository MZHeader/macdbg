// DYLD interposer for tracing the whole fork tree, which lldb can't follow on
// macOS. DYLD_INSERT_LIBRARIES is inherited across fork, so this rides into
// every child that isn't a SIP-protected binary and writes each call, pid-
// tagged, to MACDBG_TRACE_OUT for macdbg to tail.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DYLD_INTERPOSE(_repl, _orig) \
  __attribute__((used)) static struct { const void *r; const void *o; } \
  _interpose_##_orig __attribute__((section("__DATA,__interpose"))) = \
  { (const void *)(unsigned long)&_repl, (const void *)(unsigned long)&_orig };

static int trace_fd = -2;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static int out_fd(void) {
    if (trace_fd == -2) {
        // macdbg opens the trace file at a fixed fd (MACDBG_TRACE_FD) so the
        // lldb tracer can skip it; fall back to opening a path ourselves.
        const char *fdstr = getenv("MACDBG_TRACE_FD");
        if (fdstr) {
            trace_fd = atoi(fdstr);
        } else {
            const char *path = getenv("MACDBG_TRACE_OUT");
            trace_fd = path ? open(path, O_WRONLY | O_APPEND | O_CREAT, 0644) : -1;
        }
    }
    return trace_fd;
}

// One record per line. Buffers are hex so binary traffic survives the text
// channel; macdbg decodes them on the far side.
static void emit(const char *rec) {
    int fd = out_fd();
    if (fd < 0) return;
    pthread_mutex_lock(&lock);
    write(fd, rec, strlen(rec));
    pthread_mutex_unlock(&lock);
}

static void hexpreview(char *dst, size_t dstsz, const void *buf, size_t n) {
    size_t cap = n < 64 ? n : 64;
    size_t o = 0;
    const unsigned char *b = (const unsigned char *)buf;
    for (size_t i = 0; i < cap && o + 2 < dstsz; i++)
        o += snprintf(dst + o, dstsz - o, "%02x", b[i]);
    dst[o] = 0;
}

static void emit_io(const char *fn, int fd, const void *buf, size_t n) {
    if (fd == out_fd()) return;  // never trace our own trace-channel writes
    char hex[160], rec[320];
    hexpreview(hex, sizeof hex, buf, n);
    snprintf(rec, sizeof rec, "%d\t%s\tfd=%d\tn=%zu\t%s\n", getpid(), fn, fd, n, hex);
    emit(rec);
}

ssize_t my_read(int fd, void *buf, size_t n) {
    ssize_t r = read(fd, buf, n);
    if (r > 0) emit_io("read", fd, buf, (size_t)r);
    return r;
}
ssize_t my_write(int fd, const void *buf, size_t n) {
    emit_io("write", fd, buf, n);
    return write(fd, buf, n);
}
ssize_t my_send(int s, const void *buf, size_t n, int flags) {
    emit_io("send", s, buf, n);
    return send(s, buf, n, flags);
}
ssize_t my_recv(int s, void *buf, size_t n, int flags) {
    ssize_t r = recv(s, buf, n, flags);
    if (r > 0) emit_io("recv", s, buf, (size_t)r);
    return r;
}

int my_connect(int s, const struct sockaddr *addr, socklen_t len) {
    char host[64] = "?";
    int port = 0;
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
        port = ntohs(a->sin_port);
    } else if (addr && addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
        port = ntohs(a->sin6_port);
    }
    char rec[160];
    snprintf(rec, sizeof rec, "%d\tconnect\tfd=%d\t%s:%d\n", getpid(), s, host, port);
    emit(rec);
    return connect(s, addr, len);
}

int my_open(const char *path, int flags, ...) {
    char rec[1200];
    snprintf(rec, sizeof rec, "%d\topen\t%s\tflags=%d\n", getpid(), path ? path : "?", flags);
    emit(rec);
    return open(path, flags);
}

DYLD_INTERPOSE(my_read, read)
DYLD_INTERPOSE(my_write, write)
DYLD_INTERPOSE(my_send, send)
DYLD_INTERPOSE(my_recv, recv)
DYLD_INTERPOSE(my_connect, connect)
DYLD_INTERPOSE(my_open, open)

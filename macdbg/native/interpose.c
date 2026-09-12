// DYLD interposer for tracing the whole fork tree, which lldb can't follow on
// macOS. DYLD_INSERT_LIBRARIES is inherited across fork, so this rides into
// every child that isn't a SIP-protected binary and writes each call, pid-
// tagged, to MACDBG_TRACE_OUT for macdbg to tail.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <errno.h>
#include <stdint.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DYLD_INTERPOSE(_repl, _orig) \
  __attribute__((used)) static struct { const void *r; const void *o; } \
  _interpose_##_orig __attribute__((section("__DATA,__interpose"))) = \
  { (const void *)(unsigned long)&_repl, (const void *)(unsigned long)&_orig };

static _Atomic int trace_fd = -2;

static int safe_copy(void *destination, const void *source, size_t size) {
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)source,
        size, (mach_vm_address_t)destination, &copied) == KERN_SUCCESS && copied == size;
}

static void path_preview(char *destination, size_t capacity, const char *path) {
    size_t offset = 0;
    while (offset + 1 < capacity) {
        uintptr_t address = (uintptr_t)path + offset;
        size_t size = vm_page_size - address % vm_page_size;
        if (size > capacity - offset - 1) size = capacity - offset - 1;
        if (!safe_copy(destination + offset, (const void *)address, size)) {
            snprintf(destination, capacity, "<unreadable>");
            return;
        }
        if (memchr(destination + offset, 0, size)) return;
        offset += size;
    }
    destination[offset] = 0;
}

static int out_fd(void) {
    int fd = atomic_load(&trace_fd);
    if (fd == -2) {
        // macdbg opens the trace file at a fixed fd (MACDBG_TRACE_FD) so the
        // lldb tracer can skip it; fall back to opening a path ourselves.
        const char *fdstr = getenv("MACDBG_TRACE_FD");
        if (fdstr) {
            fd = atoi(fdstr);
        } else {
            const char *path = getenv("MACDBG_TRACE_OUT");
            fd = path ? open(path, O_WRONLY | O_APPEND | O_CREAT, 0600) : -1;
        }
        int expected = -2;
        if (!atomic_compare_exchange_strong(&trace_fd, &expected, fd)) {
            if (!fdstr && fd >= 0) close(fd);
            fd = expected;
        }
    }
    return fd;
}

// One record per line. Buffers are hex so binary traffic survives the text
// channel; macdbg decodes them on the far side.
static void emit(const char *rec) {
    int saved_errno = errno;
    int fd = out_fd();
    // Each record is one write. No userspace lock is inherited locked by fork.
    if (fd >= 0) write(fd, rec, strlen(rec));
    errno = saved_errno;
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
    int saved_errno = errno;
    if (fd == out_fd()) { errno = saved_errno; return; }
    char hex[160], rec[320];
    hexpreview(hex, sizeof hex, buf, n);
    snprintf(rec, sizeof rec, "%d\t%s\tfd=%d\tn=%zu\t%s\n", getpid(), fn, fd, n, hex);
    emit(rec);
    errno = saved_errno;
}

ssize_t my_read(int fd, void *buf, size_t n) {
    ssize_t r = read(fd, buf, n);
    if (r > 0) emit_io("read", fd, buf, (size_t)r);
    return r;
}
ssize_t my_write(int fd, const void *buf, size_t n) {
    ssize_t r = write(fd, buf, n);
    if (r > 0) emit_io("write", fd, buf, (size_t)r);
    return r;
}
ssize_t my_send(int s, const void *buf, size_t n, int flags) {
    ssize_t r = send(s, buf, n, flags);
    if (r > 0) emit_io("send", s, buf, (size_t)r);
    return r;
}
ssize_t my_recv(int s, void *buf, size_t n, int flags) {
    ssize_t r = recv(s, buf, n, flags);
    if (r > 0) emit_io("recv", s, buf, (size_t)r);
    return r;
}

int my_connect(int s, const struct sockaddr *addr, socklen_t len) {
    int result = connect(s, addr, len);
    int saved_errno = errno;
    struct sockaddr_storage copy;
    size_t size = len < sizeof(copy) ? len : sizeof(copy);
    addr = size && safe_copy(&copy, addr, size) ? (const struct sockaddr *)&copy : NULL;
    char host[64] = "?";
    int port = 0;
    if (addr && len >= sizeof(struct sockaddr_in) && addr->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &a->sin_addr, host, sizeof host);
        port = ntohs(a->sin_port);
    } else if (addr && len >= sizeof(struct sockaddr_in6) && addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &a->sin6_addr, host, sizeof host);
        port = ntohs(a->sin6_port);
    }
    char rec[160];
    snprintf(rec, sizeof rec, "%d\tconnect\tfd=%d\t%s:%d\n", getpid(), s, host, port);
    emit(rec);
    errno = saved_errno;
    return result;
}

int my_open(const char *path, int flags, ...) {
    int result;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        result = open(path, flags, mode);
    } else {
        result = open(path, flags);
    }
    int saved_errno = errno;
    char preview[1024];
    path_preview(preview, sizeof(preview), path);
    char rec[1200];
    snprintf(rec, sizeof rec, "%d\topen\t%s\tflags=%d\n", getpid(), preview, flags);
    emit(rec);
    errno = saved_errno;
    return result;
}

DYLD_INTERPOSE(my_read, read)
DYLD_INTERPOSE(my_write, write)
DYLD_INTERPOSE(my_send, send)
DYLD_INTERPOSE(my_recv, recv)
DYLD_INTERPOSE(my_connect, connect)
DYLD_INTERPOSE(my_open, open)

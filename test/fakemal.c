// fakemal.c — benign malware-shaped test target for lldb-wrapper.
// XOR-encrypted "strings", a decrypt loop worth stepping through,
// a fake C2 beacon, a worker thread, and a config struct on the heap.
//
// Build:
//   clang -O0 -g -pthread fakemal.c -o fakemal

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// --- "encrypted" blobs -----------------------------------------------------
// Each is plaintext XOR'd byte-by-byte with 0x5A. Length is stored explicitly
// so we don't leak null-terminator info. Values were generated so that
// plaintext is readable after decrypt_string().

#define KEY 0x5A

// "http://c2.evil.example/beacon"
static const uint8_t ENC_C2_URL[] = {0x32,0x2e,0x2e,0x2a,0x60,0x75,0x75,0x39,0x68,0x74,0x3f,0x2c,0x33,0x36,0x74,0x3f,0x22,0x3b,0x37,0x2a,0x36,0x3f,0x75,0x38,0x3f,0x3b,0x39,0x35,0x34};
static const size_t ENC_C2_URL_LEN = sizeof(ENC_C2_URL);

// "GET /cmd?id=%08x HTTP/1.1"
static const uint8_t ENC_REQ_FMT[] = {0x1d,0x1f,0x0e,0x7a,0x75,0x39,0x37,0x3e,0x65,0x33,0x3e,0x67,0x7f,0x6a,0x62,0x22,0x7a,0x12,0x0e,0x0e,0x0a,0x75,0x6b,0x74,0x6b};
static const size_t ENC_REQ_FMT_LEN = sizeof(ENC_REQ_FMT);

// "AllYourFilesBelongToUs.locked"
static const uint8_t ENC_MARKER[] = {0x1b,0x36,0x36,0x03,0x35,0x2f,0x28,0x1c,0x33,0x36,0x3f,0x29,0x18,0x3f,0x36,0x35,0x34,0x3d,0x0e,0x35,0x0f,0x29,0x74,0x36,0x35,0x39,0x31,0x3f,0x3e};
static const size_t ENC_MARKER_LEN = sizeof(ENC_MARKER);

// --- runtime config on the heap (nice thing to inspect in Memory pane) ----

typedef struct {
    uint32_t magic;        // 0xDEADC0DE — obvious in hex dump
    uint32_t victim_id;
    char     c2_url[64];
    char     req_fmt[64];
    char     marker[64];
    uint64_t next_beacon;  // fake timer
} config_t;

// --- decrypt loop: this is what you want to step through ------------------

__attribute__((noinline))
static void decrypt_string(const uint8_t *enc, size_t n, char *out) {
    // Each iteration puts fresh values into registers — great pane to watch.
    for (size_t i = 0; i < n; i++) {
        uint8_t b = enc[i];
        uint8_t k = KEY;
        out[i] = (char)(b ^ k);
    }
    out[n] = '\0';
}

// --- fake C2 beacon (no real network I/O; just prints what it "would" send)

__attribute__((noinline))
static void beacon(config_t *cfg) {
    char req[256];
    snprintf(req, sizeof(req), cfg->req_fmt, cfg->victim_id);
    // Two "interesting" pointer values live here at the same time.
    printf("[beacon] POST %s\n", cfg->c2_url);
    printf("[beacon]   req: %s\n", req);
    printf("[beacon]   marker: %s\n", cfg->marker);
    fflush(stdout);
}

// --- worker thread so the threads pane has >1 entry -----------------------

static void *worker(void *arg) {
    config_t *cfg = (config_t *)arg;
    for (int i = 0; i < 3; i++) {
        cfg->next_beacon = 0x1000 + i;   // visible in memory dump
        usleep(200 * 1000);
    }
    return NULL;
}

// --- entrypoint -----------------------------------------------------------

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    config_t *cfg = (config_t *)calloc(1, sizeof(*cfg));
    cfg->magic = 0xDEADC0DE;
    cfg->victim_id = 0x1337BEEF;

    // Decrypt the three strings straight into the config.
    // Set a breakpoint on decrypt_string to watch bytes change in registers.
    decrypt_string(ENC_C2_URL,  ENC_C2_URL_LEN,  cfg->c2_url);
    decrypt_string(ENC_REQ_FMT, ENC_REQ_FMT_LEN, cfg->req_fmt);
    decrypt_string(ENC_MARKER,  ENC_MARKER_LEN,  cfg->marker);

    printf("[main] config at %p, magic=0x%08x, victim=0x%08x\n",
           (void *)cfg, cfg->magic, cfg->victim_id);
    fflush(stdout);

    pthread_t th;
    pthread_create(&th, NULL, worker, cfg);

    for (int i = 0; i < 2; i++) {
        beacon(cfg);
        usleep(300 * 1000);
    }

    pthread_join(th, NULL);
    free(cfg);
    return 0;
}

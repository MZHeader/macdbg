#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned char *review_region;
char review_text[64] = "before local decoding";
__attribute__((noinline)) void memory_ready(void) { __asm__ volatile("nop"); }
__attribute__((noinline)) void memory_changed(void) { __asm__ volatile("nop"); }

int main(void) {
    size_t size = (size_t)getpagesize();
    review_region = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (review_region == MAP_FAILED) return 2;
    /* Benign generated ARM64 code: nop; mov w0, #42; ret. */
    const unsigned code[] = {0xd503201f, 0x52800540, 0xd65f03c0, 0xd4001001}; /* svc after ret is never executed */
    memcpy(review_region, code, sizeof code);
    __builtin___clear_cache((char *)review_region, (char *)review_region + sizeof code);
    if (mprotect(review_region, size, PROT_READ | PROT_EXEC)) return 3;
    memory_ready();
    strcpy(review_text, "after local decoding");
    memory_changed();
    int result = ((int (*)(void))(review_region + 4))();
    printf("MEMORY_ANALYSIS: %d %s\n", result, review_text);
    munmap(review_region, size);
    return result != 42;
}

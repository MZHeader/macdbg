#include <stdint.h>
#include <stdio.h>

char ui_buffer[64] = "editable local text";
volatile uint64_t ui_watched;
extern uint64_t ui_load(uint64_t *);
extern uint64_t ui_branch(uint64_t);
extern uint64_t ui_indirect(void *);
extern uint64_t ui_destination(void);
__attribute__((noinline)) void ui_marker(void) { __asm__ volatile("nop"); }
int main(void) {
    uint64_t pair[] = {3,0x1122334455667788ULL};
    uint64_t loaded = ui_load(pair);
    uint64_t branched = ui_branch(0);
    uint64_t indirect = ui_indirect(ui_destination);
    ui_marker();
    ui_watched = 7;
    printf("UI_FIXTURE:%llx %llu %llu %s\n",loaded,branched,indirect,ui_buffer);
    return 0;
}

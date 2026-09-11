.text
.p2align 2
.globl _timing_result, _timing_decision, _timing_mask, _timing_mask_decision
.globl _timing_branch, _timing_branch_decision, _timing_branch_clean
.globl _timing_clock_probe, _timing_clock_call, _timing_clock_return

_timing_clock_probe:
    .cfi_startproc
    stp fp, lr, [sp, #-16]!
    .cfi_def_cfa_offset 16
    .cfi_offset w29, -16
    .cfi_offset w30, -8
    mov fp, sp
    .cfi_endproc
_timing_clock_call:
    .cfi_startproc
    .cfi_def_cfa_offset 16
    .cfi_offset w29, -16
    .cfi_offset w30, -8
    bl _mach_absolute_time
    .cfi_endproc
_timing_clock_return:
    .cfi_startproc
    .cfi_def_cfa_offset 16
    .cfi_offset w29, -16
    .cfi_offset w30, -8
    ldp fp, lr, [sp], #16
    .cfi_def_cfa_offset 0
    .cfi_restore w29
    .cfi_restore w30
    ret
    .cfi_endproc

// Explicit instruction sites keep the register contracts stable across builds.
_timing_result:
    mov x9, #20000
    mov x10, #1000
    mul x9, x9, x10
    cmp x0, x9
    mov w8, #0x1357
    csel w8, w8, wzr, hi
_timing_decision:
    mov w9, #0x40000000
    eor w0, w9, w8
    ret

_timing_mask:
    mov x9, #20000
    mov x10, #1000
    mul x9, x9, x10
    cmp x0, x9
    mov w8, #0x1357
    csel w8, w8, wzr, hi
    orr w8, w8, #0x40000000
_timing_mask_decision:
    mov w0, w8
    ret

_timing_branch:
    mov x9, #20000
    mov x10, #1000
    mul x9, x9, x10
    cmp x0, x9
    cset w8, hi
_timing_branch_decision:
    cbz w8, _timing_branch_clean
    mov w0, #0x1357
    orr w0, w0, #0x40000000
    ret
_timing_branch_clean:
    mov w0, #0x40000000
    ret

.text
.align 2
.globl _ui_load
_ui_load:
    ldr x0, [x0, #8]
    ret
.globl _ui_branch
_ui_branch:
    cbz x0, Lui_zero
    mov w0, #2
    ret
Lui_zero:
    mov w0, #1
    ret
.globl _ui_indirect
_ui_indirect:
    br x0
.globl _ui_destination
_ui_destination:
    mov w0, #7
    ret

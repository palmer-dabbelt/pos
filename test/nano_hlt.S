.global _start
_start:
    mov $60, %rax
    mov  $0, %rdi
    /*
     * POS uses "hlt" from the kernel (ie, ring 0), but some programs use "hlt"
     * from userspace as a last-ditch attempt at aborting.  We don't want those
     * halts to trigger an arbitrary syscall, so here we set up all the
     * conditions for "exit(0)" and then "hlt" instead of "syscall" and then
     * XFAIL the test.
     */
    hlt

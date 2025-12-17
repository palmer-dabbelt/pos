#if defined(__x86_64__)
.global _start
_start:
    mov $60, %rax
    mov  $0, %rdi
    syscall
#endif

#if defined(__aarch64__)
.global start
start:
    movz x8, 60
    movz x0, 0
    svc 0
#endif

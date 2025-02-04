#include <elf.h>

extern __thread int testval0 __attribute((tls_model("initial-exec")));
extern __thread int testval1 __attribute((tls_model("initial-exec")));

extern int _testval0;
extern int _testval1;

__asm__ (
".text\n"
".global _start\n"
"_start:\n"

/* We begin with argc, argv, and envp on the stack, as per the x86_64 psABI.
 * It's slightly easier to deal with this all in C, so just start by calling a
 * C routine to find .tdata. */
"    mov %rsp, %rdi\n"
"    call find_envp\n"
"    mov %rax, %rdi\n"
"    call find_phdr\n"
"    mov %rax, %rdi\n"
"    call find_tdata\n"
"    mov %rax, %rsi\n"

/* Set FS to the TCB, which we've found and put in RSI. */
"set_fs:\n"
"    mov $158, %rax\n"
"    mov $0x1002, %rdi\n"
"    mov %rsi, %rsi\n"
"    syscall\n"

/* Actually calls main. */
"call_main:\n"
"    call main\n"

/* exit()s with the value returned from main. */
"call_exit:\n"
"    mov %rax, %rdi\n"
"    mov  $60, %rax\n"
"    syscall\n"
);

void exit(char code_in) __attribute__((noinline));
void exit(char code_in) {
    register long nr asm("rax") = 60;
    register long code asm("rdi") = code_in;

    __asm__ volatile ("syscall" :: "r"(nr), "r"(code));
}

long  *find_envp(long *sp)
{
    if (sp == 0) exit(-2);

    /* first skip argv. */
    while (*sp != 0) sp++;
    sp++;

    /* then skip envp */
    while (*sp != 0) sp++;
    sp++;

    return sp;
}

long find_phdr(long *envp)
{
    /* now look through envp, for an entry that's what we want.  This will
     * point to the PHDR, so just go ahead and return it. */
    while (envp[0] != 3) envp += 2;
    return envp[1];
}

long get_tdata(Elf64_Phdr *phdr, long i)
{
    return phdr[i].p_vaddr + phdr[i].p_memsz;
}

int check_tdata(Elf64_Phdr *phdr, long i) __attribute__((noinline));
int check_tdata(Elf64_Phdr *phdr, long i)
{
    return phdr[i].p_type == PT_TLS;
}

long find_tdata(Elf64_Phdr *phdr)
{
    if (phdr == 0) exit(-2);

    for (long i = 0; i < 1024; ++i)
        if (check_tdata(phdr, i))
	    return get_tdata(phdr, i);

    return -1;
}

extern int func(void);

__asm__ ("func: ret");

int get_testval0(int delta) {
    return testval0 - delta;
}

int get_testval1(int delta) {
    return testval1 - delta;
}

int main() {
    func();
    return get_testval0(_testval0) + get_testval1(_testval1);
}

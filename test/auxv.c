#include <sys/auxv.h>
#include <stdio.h>

int main() {
    printf("AT_PAGESZ:       0x%016lx\n", getauxval(AT_PAGESZ));
    printf("AT_SECURE:       0x%016lx\n", getauxval(AT_SECURE));
    printf("AT_PLATFORM:     %s\n", (const char *)(getauxval(AT_PLATFORM)));
    printf("AT_HWCAP:        0x%016lx\n", getauxval(AT_HWCAP));
    printf("AT_HWCAP2:       0x%016lx\n", getauxval(AT_HWCAP2));
    printf("AT_CLKTCK:       0x%016lx\n", getauxval(AT_CLKTCK));
    printf("AT_FPUCW:        0x%016lx\n", getauxval(AT_FPUCW));
    printf("AT_RANDOM:       0x%016lx\n", getauxval(AT_RANDOM));
    printf("AT_MINSIGSTKSZ:  0x%016lx\n", getauxval(AT_MINSIGSTKSZ));
    printf("AT_SYSINFO_EHDR: 0x%016lx\n", getauxval(AT_SYSINFO_EHDR));
    printf("AT_SYSINFO:      0x%016lx\n", getauxval(AT_SYSINFO));
    return 0;
}

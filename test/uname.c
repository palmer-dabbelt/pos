#define _GNU_SOURCE

#include <stdio.h>
#include <sys/utsname.h>

int main() {
    struct utsname uts;

    if (uname(&uts) != 0)
    	return 1;

    printf("sysname:    \"%s\"\n", uts.sysname);
    printf("nodename:   \"%s\"\n", uts.nodename);
    printf("release:    \"%s\"\n", uts.release);
    printf("version:    \"%s\"\n", uts.version);
    printf("machine:    \"%s\"\n", uts.machine);
    printf("domainname: \"%s\"\n", uts.domainname);

    return 0;
}

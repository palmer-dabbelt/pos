// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS_DEBUG_KVM
#define POS_DEBUG_KVM 0
#endif

#ifndef POS_DEBUG_SYSCALLS
#define POS_DEBUG_SYSCALLS 1
#endif

#include "thread.h++"
#include <linux/kvm.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
using namespace pos::kernel;

#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 9)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE (1U <<  0)
#define EFER_LME (1U <<  8)
#define EFER_LMA (1U << 10)

#define XCR0_X87        (1U << 0)
#define XCR0_SSE        (1U << 1)
#define XCR0_AVX        (1U << 2)
#define XCR0_BNDREG     (1U << 3)
#define XCR0_BNDCSR     (1U << 4)
#define XCR0_OPMASK     (1U << 5)
#define XCR0_ZMM_HI256  (1U << 6)
#define XCR0_HI16_ZMM   (1U << 7)

template <int N> struct kvm_msrs_wrapper {
    __u32 nmsrs;
    __u32 pad;
    struct kvm_msr_entry entries[N];

    kvm_msrs_wrapper(void)
    : nmsrs(N)
    {}

    struct kvm_msrs *kvm_ptr(void) const { return (struct kvm_msrs *)&nmsrs; }
};

/*
 * From https://wiki.osdev.org/Getting_to_Ring_3
 */
struct gdt_entry_bits {
	unsigned int limit_low              : 16;
	unsigned int base_low               : 24;
	unsigned int accessed               :  1;
	unsigned int read_write             :  1; // readable for code, writable for data
	unsigned int conforming_expand_down :  1; // conforming for code, expand down for data
	unsigned int code                   :  1; // 1 for code, 0 for data
	unsigned int code_data_segment      :  1; // should be 1 for everything but TSS and LDT
	unsigned int DPL                    :  2; // privilege level
	unsigned int present                :  1;
	unsigned int limit_high             :  4;
	unsigned int available              :  1; // only used in software; has no effect on hardware
	unsigned int long_mode              :  1;
	unsigned int big                    :  1; // 32-bit opcodes for code, uint32_t stack for data
	unsigned int gran                   :  1; // 1 to use 4k page addressing, 0 for byte addressing
	unsigned int base_high              :  8;
} __attribute__((packed));

void thread::kvm::thread_main(void)
{
    /*
     * Wait to make sure the thread constructor has filled out all the relevant
     * bits.
     */
    wait_for_state(thread_state::INIT);
    state_lock.lock();

    kvm_fd = open("/dev/kvm", O_RDWR);
    if (kvm_fd < 0) abort();

    int version = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
    if (version != KVM_API_VERSION) abort();

    vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    if (vm_fd < 0) abort();

    {
        struct kvm_userspace_memory_region m;

        m.slot = 0;
        m.flags = 0;
        m.guest_phys_addr = memory.pa_base();
        m.memory_size = memory.pa_size_bytes();
        m.userspace_addr = (uint64_t)(memory.ha_base());

        int kvmm = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &m);
        if (kvmm < 0) {
            perror("KVM_SET_USER_MEMORY_REGION");
            abort();
        }
    }

    cpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    if (cpu_fd < 0) abort();

    auto run = [&]() {
        size_t s = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
        if (s <= 0) abort();

        auto m = mmap(NULL, s, PROT_READ | PROT_WRITE, MAP_SHARED, cpu_fd, 0);
        if (!m) abort();
        return (struct kvm_run *)m;
    }();

    regs.rflags = 2;

    auto r = ioctl(cpu_fd, KVM_GET_SREGS, &sregs);
    if (r < 0) abort();

    sregs.cr0  = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    sregs.cr3  = memory.ptbr_pa();
    sregs.cr4  = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE;
    sregs.efer = EFER_LME | EFER_LMA | EFER_SCE;

    sregs.cs = [](){
        struct kvm_segment s;
        memset(&s, 0, sizeof(s));
        s.base = 0;
        s.limit = 0xffffffff;
        s.selector = 3 << 3;
        s.present = 1;
        s.type = 11;
        s.dpl = 3;
        s.db = 0;
        s.s = 1;
        s.l = 1;
        s.g = 1;
        return s;
    }();
    sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = [&](){
        struct kvm_segment s = sregs.cs;
        s.type = 3;
        s.selector = 4 << 3;
        return s;
    }();

    r = ioctl(cpu_fd, KVM_SET_SREGS, &sregs);
    if (r < 0) abort();

    if (ioctl(kvm_fd, KVM_CAP_XCRS)) {
        struct kvm_xcrs xcrs;

        xcrs.nr_xcrs = 1;
        xcrs.flags = 0;
        xcrs.xcrs[0].xcr = 0;
        xcrs.xcrs[0].value = XCR0_X87 | XCR0_SSE | XCR0_AVX | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;

        r = ioctl(cpu_fd, KVM_SET_XCRS, &xcrs);
        if (r < 0) {
            perror("Unable to SET_XCRS");
            int xcr0;
            __asm__ volatile ("xgetbv" : "=a" (xcr0) : "c" (0) : "%edx");
            fprintf(stderr, "XCR0: 0x%08x\n", xcr0);
        }
    } else
        abort();

    /*
     * In order to handle SYSCALL we need a GDT, because
     */
    auto gdt_va = 0x10000000;
    memory.map(gdt_va, 4096, 1, 1, 1);
    sregs.gdt.base = gdt_va;
    sregs.gdt.limit = (4096/8);

    auto gdt_ha = (struct gdt_entry_bits *)(memory.virt2host(gdt_va));
    memset(gdt_ha, 0, 4096);
    gdt_ha[1].limit_low = 0xFFFF;
    gdt_ha[1].base_low = 0;
    gdt_ha[1].accessed = 0;
    gdt_ha[1].read_write = 1;
    gdt_ha[1].conforming_expand_down = 0;
    gdt_ha[1].code = 1;
    gdt_ha[1].code_data_segment = 1;
    gdt_ha[1].DPL = 0;
    gdt_ha[1].present = 1;
    gdt_ha[1].limit_high = 0xF;
    gdt_ha[1].available = 1;
    gdt_ha[1].long_mode = 1;
    gdt_ha[1].big = 1;
    gdt_ha[1].gran = 1;
    gdt_ha[1].base_high = 0;

    gdt_ha[2] = gdt_ha[1];
    gdt_ha[2].code = 0;

    gdt_ha[3] = gdt_ha[1];
    gdt_ha[3].DPL = 3;

    gdt_ha[4] = gdt_ha[4];
    gdt_ha[4].code = 0;

    /*
     * This is really just a shim that turns any syscall from the guest into a
     * hypervisor call, so we can deal with it via our syscall emulation code.
     * KVM already gives us access to the relevant registers, so we can just
     * sysret right after that.
     */
    auto kernel_va = 0x20000000;
    memory.map(kernel_va, 4096, 1, 1, 1);
    memory.writeb(kernel_va + 0, 0x90); /* nop */
    memory.writeb(kernel_va + 1, 0xf4); /* hlt */
    memory.writeb(kernel_va + 2, 0x48); /* sysretq */
    memory.writeb(kernel_va + 3, 0x0f);
    memory.writeb(kernel_va + 4, 0x07);

    {
        kvm_msrs_wrapper<2> m;
        m.entries[0].index = 0xC0000081;
        m.entries[0].data = ((1UL << 3) << 48) | ((2UL << 3) << 32);
        m.entries[1].index = 0xC0000082;
        m.entries[1].data = kernel_va;

        auto r = ioctl(cpu_fd, KVM_SET_MSRS, m.kvm_ptr());
        if (r != 2) {
            perror("unable to set LSTAR");
            abort();
        }
    }

    /*
     * Just copy Linux's VDSO over to the guest.  This is obviously garbage, I
     * just want something here so I can at least get a properly formatted SO.
     */
    auto vdso_va = 0x40000000;
    auto vdso_size = 0x5000;
    memory.map_all(vdso_va, vdso_size, 1, 1, 1);
#if 0
    for (size_t i = 0; i < vdso_size; ++i)
        memory.writeb(vdso_va + i, ((char*)getauxval(AT_SYSINFO_EHDR))[i]);
#endif

    /*
     * Userspace expects that the kernel sets up a stack, so just map one of an
     * arbitrary size.  The stack grows towards numerically smaller addresses
     * on x86, so start at the top.  argv, envp, auxv, and the associated
     * strings are all pushed to the stack before executing the program.
     */
    auto stack_va   = 0x30000000;
    auto stack_size = 0x00010000;
    memory.map_all(stack_va, stack_size, 1, 1, 1);
    regs.rsp = stack_va + stack_size - 8;

    {
        auto balign_up = [](long l, long b) { return (l + b - 1) & ~(b - 1); };

        auto onstack_str = [&](std::string s) {
            auto length = balign_up(s.length() + 1, 8);
            regs.rsp -= length;
            memory.copy_to_va_all(regs.rsp,
                                  (uint8_t*)(s.c_str()),
                                  s.length() + 1);
            return regs.rsp;
        };

        auto onstack_long = [&](long v) {
            regs.rsp -= 8;
            memory.writeq(regs.rsp, v);
            return regs.rsp;
        };

        auto onstack_auxv = [&](long type, long val) {
            onstack_long(val);
            onstack_long(type);
        };

        auto onstack_envp = [&](auto addr) { return onstack_long(addr); };
        auto onstack_argv = [&](auto addr) { return onstack_long(addr); };
        auto onstack_argc = [&](long argc) { return onstack_long(argc); };

        if (phdr == 0 || phent == 0) {
            fprintf(stderr, "no PHDR on PHENT\n");
            abort();
        }

        auto argv_0 = onstack_str("FIXME_program_name");
        auto random = onstack_long(4); /* FIXME: not random */
        auto platform = onstack_str("x86_64");
        onstack_auxv(0, 0);
        onstack_auxv(3, phdr);     /* AT_PHDR */
        onstack_auxv(4, phent);    /* AT_PHENT */
        onstack_auxv(5, phnum);    /* AT_PHNUM */
        onstack_auxv(6, 4096);     /* AT_PAGESZ */
        onstack_auxv(9, regs.rip); /* AT_ENTRY */
        onstack_auxv(11, 0);       /* AT_UID */
        onstack_auxv(12, 0);       /* AT_EUID */
        onstack_auxv(13, 0);       /* AT_GID */
        onstack_auxv(14, 0);       /* AT_EGID */
        onstack_auxv(15, platform);
        onstack_auxv(16, 0x6);     /* AT_HWCAP */
        onstack_auxv(17, 0x64);    /* AT_CLKTCK */
        onstack_auxv(18, 0);       /* AT_FPUCW */
        onstack_auxv(23, 0);       /* AT_SECURE */
        onstack_auxv(25, random);  /* AT_RANDOM */
        onstack_auxv(26, 0x2);     /* AT_HWCAP2 */
        onstack_auxv(33, vdso_va); /* AT_SYSINFO_EHDR */
        onstack_auxv(51, 0);       /* AT_MINSIGSTKSZ */
        onstack_envp(0);
        onstack_argv(0);
        onstack_argv(argv_0);
        onstack_argc(1);
    }

    /*
     * Userspace also expects that RDX contains the atexit() pointer, which is
     * a special magic argument that plums in through the dynamic linker.  I
     * found this mentioned in glibc's start.S, but I can't find it in the ABI
     * doc.
     */
    regs.rdx = 0;

    /*
     * KVM has been set up, so we can get on with processing commands from the
     * rest of the system.
     */
    state = thread_state::READY;
    state_lock.unlock();
    state_signal.notify_all();

    state_lock.lock();
    do {
        state_lock.unlock();
        wait_for_state(thread_state::RUNNING);

#if POS_DEBUG_KVM
        fprintf(stderr, "KVM running at 0x%016llx\n", regs.rip);

        for (size_t i = 0; i < 16; ++i) {
            auto va = regs.rip + i;
            fprintf(stderr, "M[0x%016llx] = 0x%02x\n", va, memory.readb(va));
        }

        fprintf(stderr, "%%rip: 0x%016llx\n", regs.rip);
        fprintf(stderr, "%%rax: 0x%016llx\n", regs.rax);
        fprintf(stderr, "%%rcx: 0x%016llx\n", regs.rcx);
        fprintf(stderr, "%%rdx: 0x%016llx\n", regs.rdx);
        fprintf(stderr, "%%rbx: 0x%016llx\n", regs.rbx);
        fprintf(stderr, "%%rsp: 0x%016llx\n", regs.rsp);
        fprintf(stderr, "%%rbp: 0x%016llx\n", regs.rbp);
        fprintf(stderr, "%%rsi: 0x%016llx\n", regs.rsi);
        fprintf(stderr, "%%rdi: 0x%016llx\n", regs.rdi);
        fprintf(stderr, "%%r8:  0x%016llx\n", regs.r8);
        fprintf(stderr, "%%r9:  0x%016llx\n", regs.r9);
        fprintf(stderr, "%%r10: 0x%016llx\n", regs.r10);
        fprintf(stderr, "%%r11: 0x%016llx\n", regs.r11);
        fprintf(stderr, "%%r12: 0x%016llx\n", regs.r12);
        fprintf(stderr, "%%r13: 0x%016llx\n", regs.r13);
        fprintf(stderr, "%%r14: 0x%016llx\n", regs.r14);
        fprintf(stderr, "%%r15: 0x%016llx\n", regs.r15);
#endif

        auto r = ioctl(cpu_fd, KVM_SET_REGS, &regs);
        if (r < 0) abort();
        r = ioctl(cpu_fd, KVM_SET_SREGS, &sregs);
        if (r < 0) abort();

#if POS_DEBUG_KVM
        {
            struct kvm_guest_debug d;
            d.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
            auto r = ioctl(cpu_fd, KVM_SET_GUEST_DEBUG, &d);
            if (r < 0) abort();
        }
#endif

        r = ioctl(cpu_fd, KVM_RUN, 0);
        if (r < 0) abort();

        r = ioctl(cpu_fd, KVM_GET_REGS, &regs);
        if (r < 0) abort();
        r = ioctl(cpu_fd, KVM_GET_SREGS, &sregs);
        if (r < 0) abort();

        switch (run->exit_reason) {
        case KVM_EXIT_SHUTDOWN:
            fprintf(stderr, "KVM_EXIT_SHUTDOWN: pc=0x%016llx\n", regs.rip);
            abort();
            break;

        case KVM_EXIT_DEBUG:
            fprintf(stderr, "KVM_EXIT_DEBUG\n");
            break;

        case KVM_EXIT_HLT:
        {
            regs.rax = handle_syscall(regs.rax, regs.rdi, regs.rsi, regs.rdx,
                                      regs.r10, regs.r8, regs.r9);
#ifdef POS_DEBUG_SYSCALLS
            fprintf(stderr, "    ==> 0x%016llx\n", regs.rax);
#endif
            break;
        }

        case KVM_EXIT_FAIL_ENTRY:
        {
            fprintf(stderr, "KVM_EXIT_FAIL_ENTRY: hw=0x%016llx\n",
                    run->fail_entry.hardware_entry_failure_reason);
            abort();
            break;
        }

        default:
            fprintf(stderr, "KVM halted with %d\n", run->exit_reason);
            abort();
            break;
        }

        state_lock.lock();
    } while (state != thread_state::DONE);
    state_lock.unlock();
}

uint64_t thread::kvm::handle_syscall(uint64_t nr, uint64_t arg0,
                                     uint64_t arg1, uint64_t arg2,
                                     uint64_t arg3, uint64_t arg4,
                                     uint64_t arg5)
{
    switch (nr) {
    case 1: /* write */
    {
        auto file = files.mutable_ref(arg0);
        if (file == nullptr) abort();

        auto buf = new uint8_t[arg2];
        memory.copy_from_va_all(buf, arg1, arg2);
        file->write_all(buf, arg2);
        delete[] buf;

        return arg2;
    }

    case 9:   /* mmap */
    {
#ifdef POS_DEBUG_SYSCALLS
        fprintf(stderr, "mmap(0x%016lx, 0x%016lx, ...)\n", arg0, arg1);
#endif

        /* Unpack "prot", so we can map with the correct permissions. */
        bool r = !!(arg2 & 0x1);
        bool w = !!(arg2 & 0x2);
        bool x = !!(arg2 & 0x4);

        /*
         * FIXME: We don't support shared file-based writable mappings, so just
         * stop now to avoid any cleanup.  We'll eventually need to support
         * these, but for now just return an error -- maybe we'll get lucky and
         * userspace will tolerate that sort of thing.
         * */
        if (w && (arg3 & 0x1) && !(arg3 & 0x20)) {
            fprintf(stderr, "shared file-based writable mappings aren't supported\n");
            return -1;
        }

        /* Mappings with a target VA of NULL should just pick one. */
        auto va = [&](){
            if (arg0 == 0) {
                return memory.alloc_user(arg1, r, w, x);
            } else {
                memory.map_all(arg0, arg1, r, w, x);
                return arg0;
            }
        }();

        /* File-backed mappings need to have their initial contents populated. */
        if (!(arg3 & 0x20)) {
            auto f = files.nonmutable_ref(arg4);
            f->seek_absolute(arg5);
            auto copied = f->read_va_all(memory, va, arg1);
            if (copied < arg1)
                memory.zero_va_all(va + copied, arg1 - copied);
        } else {
            memory.zero_va_all(va, arg1);
        }

        return va;
    }

    case 12: /* brk */
        /*
         * Here we're implementing the Linux syscall's behavior, which slightly
         * differs from the glibc routine: here we must return the new value of
         * brk(), only updating it when
         */
#ifdef POS_DEBUG_SYSCALLS
        fprintf(stderr, "brk(0x%016lx)\n", arg0);
#endif
        return memory.update_brk(arg0);

    case 20:  /* writev */
    {
#ifdef POS_DEBUG_SYSCALLS
        fprintf(stderr, "writev(...)\n", arg0);
#endif

        auto file = files.mutable_ref(arg0);
        if (file == nullptr) abort();
        ssize_t count = 0;

        for (size_t i = 0; i < arg2; ++i) {
            auto iov_base = memory.readq(arg1 + 16 * i + 0);
            auto iov_len  = memory.readq(arg1 + 16 * i + 8);

            auto buf = new uint8_t[iov_len];
            memory.copy_from_va_all(buf, iov_base, iov_len);
            file->write_all(buf, iov_len);
            count += iov_len;
            delete[] buf;
        }

        return count;
    }

    case 60: /* exit */
    case 231: /* exit_group */
#ifdef POS_DEBUG_SYSCALLS
        fprintf(stderr, "exit(%ld)\n", arg0);
#endif

        state = thread_state::DONE;
        state_signal.notify_all();
        return -1;

    case 63:  /* uname */
#ifdef POS_DEBUG_SYSCALLS
        fprintf(stderr, "uname(...)\n", arg0);
#endif

        /*
         * This is a new_utsname, so it has 6 fields.  glibc checks the kernel
         * version during startup, so we need to set that.  The rest are set to
         * something that looks sort of like Linux, just in case.
         */
        memory.zero_va_all(arg0, 6*65);
        memory.strcpy_va(arg0 + 0*65, "Linux");
        memory.strcpy_va(arg0 + 1*65, "(none)");
        memory.strcpy_va(arg0 + 2*65, "4.10.0-pos-r0");
        memory.strcpy_va(arg0 + 3*65, "#1 SMP");
        memory.strcpy_va(arg0 + 4*65, "x86_64");
        memory.strcpy_va(arg0 + 5*65, "(none)");
        return 0;

    /*
     * All of these are fake, we're just pretending that we're not root and
     * that nothing special is going on.
     */
    case 102: /* getuid */
    case 104: /* getgid */
    case 107: /* geteuid */
    case 108: /* getegid */
#ifdef POS_DEBUG_SYSCALLS
        fprintf(stderr, "get*id(...)\n", arg0);
#endif

        return 1000;

    case 158: /* arch_prctl */
        switch (arg0) {
        case 0x1002:
#ifdef POS_DEBUG_SYSCALLS
            fprintf(stderr, "arch_prctl(ARCH_SETFS, 0x%016lx)\n", arg1);
#endif
            sregs.fs.base = arg1;
            return 0;

        default:
            fprintf(stderr, "unknown arch_prctl %lu\n", arg0);
            abort();
        }
        break;

    default:
        fprintf(stderr, "unknown syscall %lu\n", nr);
        return -1;
        abort();
    }
}

int thread::join(void)
{
    vm.run();
    vm.wait_for_state(kvm::thread_state::DONE);
    return vm.regs.rdi;
}

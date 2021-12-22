// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include "thread.h++"
#include <linux/kvm.h>
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
#define CR4_OSFXSR (1U << 8)
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
     * We're still blocking the constructor at this point so it's not strictly
     * necessary to hold this lock, but it makes the wakeup logic a bit easier.
     */
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

    memset(&regs, '\0', sizeof(regs));
    regs.rflags = 2;

    auto r = ioctl(cpu_fd, KVM_GET_SREGS, &sregs);
    if (r < 0) abort();

    sregs.cr0  = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    sregs.cr3  = memory.ptbr_pa();
    sregs.cr4  = CR4_PAE;
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
            regs.rax = handle_syscall(regs.rax, regs.rdi);
            break;

        default:
            fprintf(stderr, "KVM halted with %d\n", run->exit_reason);
            abort();
            break;
        }

        state_lock.lock();
    } while (state != thread_state::DONE);
    state_lock.unlock();
}

uint64_t thread::kvm::handle_syscall(uint64_t nr, uint64_t arg0)
{
    switch (nr) {
    case 60: /* exit() */
        state = thread_state::DONE;
        state_signal.notify_all();
        return -1;

    default:
        fprintf(stderr, "unknown syscall %lx\n", nr);
        abort();
    }
}

int thread::join(void)
{
    vm.run();
    vm.wait_for_state(kvm::thread_state::DONE);
    return vm.regs.rdi;
}

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

#define EFER_LME (1U <<  8)
#define EFER_LMA (1U << 10)

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
        m.memory_size = memory.pa_bound();
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
    sregs.efer = EFER_LME | EFER_LMA;

    sregs.cs = [](){
        struct kvm_segment s;
        memset(&s, 0, sizeof(s));
        s.base = 0;
        s.limit = 0xffffffff;
        s.selector = 1 << 3;
        s.present = 1;
        s.type = 11;
        s.dpl = 0;
        s.db = 0;
        s.s = 1;
        s.l = 1;
        s.g = 1;
        return s;
    }();
    sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = [&](){
        struct kvm_segment s = sregs.cs;
        s.type = 3;
        s.selector = 2 << 3;
        return s;
    }();

    {
        struct kvm_guest_debug d;
        d.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
        auto r = ioctl(cpu_fd, KVM_SET_GUEST_DEBUG, &d);
        if (r < 0) abort();
    }

    /*
     * KVM has been set up, so we can get on with processing commands from the
     * rest of the system.
     */
    fprintf(stderr, "KVM set to ready\n");
    state = thread_state::READY;
    state_lock.unlock();
    state_signal.notify_all();

    state_lock.lock();
    do {
        state_lock.unlock();
        wait_for_state(thread_state::RUNNING);

        fprintf(stderr, "KVM running at 0x%016lx\n", regs.rip);

        auto r = ioctl(cpu_fd, KVM_SET_REGS, &regs);
        if (r < 0) abort();

        r = ioctl(cpu_fd, KVM_SET_SREGS, &sregs);
        if (r < 0) abort();

        r = ioctl(cpu_fd, KVM_RUN, 0);
        if (r < 0) abort();

        switch (run->exit_reason) {
        case KVM_EXIT_SHUTDOWN:
            fprintf(stderr, "KVM_EXIT_SHUTDOWN\n");
            abort();
            break;

        case KVM_EXIT_DEBUG:
            fprintf(stderr, "KVM_EXIT_DEBUG\n");
            abort();
            break;

        default:
            fprintf(stderr, "KVM halted with %d\n", run->exit_reason);
            abort();
            break;
        }

        r = ioctl(cpu_fd, KVM_GET_REGS, &regs);
        if (r < 0) abort();

        r = ioctl(cpu_fd, KVM_GET_SREGS, &sregs);
        if (r < 0) abort();

        state_lock.lock();
    } while (state != thread_state::KILLED);
    state_lock.unlock();
}

int thread::join(void)
{
    vm.run();
    vm.wait_for_state(kvm::thread_state::DONE);
    fprintf(stderr, "VM is done\n");
    return vm.regs.rdi;
}

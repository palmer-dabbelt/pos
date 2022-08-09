// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__THREAD_HXX
#define POS__KERNEL__THREAD_HXX

#include "address_space.h++"
#include "files.h++"
#include <linux/kvm.h>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace pos {
    namespace kernel {
        /*
         * The actual state behind a guest thread that is executing within this
         * local POS instance.
         */
        class thread {
        private:
            class kvm {
            public:
                enum class thread_state {
                    CREATED,
                    INIT,
                    READY,
                    RUNNING,
                    DONE,
                };

            private:
                address_space& memory;
                kernel::files& files;

                thread_state state;
                std::mutex state_lock;
                std::condition_variable state_signal;

                std::thread kvm_thread;
                int kvm_fd, vm_fd, cpu_fd;

            public:
                struct kvm_regs regs;
                struct kvm_sregs sregs;
                uint64_t phdr, phent;

            public:
                kvm(address_space& _memory, decltype(files)& _files)
                : memory(_memory),
                  files(_files),
                  state(thread_state::CREATED),
                  state_lock(),
                  kvm_thread(thread_main_wrapper, this),
                  phdr(-1)
                {
                }

                ~kvm(void)
                {
                    kvm_thread.join();
                }

                void wait_for_state(thread_state s)
                {
                    auto l = std::unique_lock(state_lock);
                    while (state != s)
                        state_signal.wait(l, [&]{ return state == s; });
                }

                void done_with_init(void)
                {
                    state_lock.lock();
                    if (state == thread_state::CREATED)
                        state = thread_state::INIT;
                    else
                        abort();
                    state_lock.unlock();
                    state_signal.notify_all();
                }

                void run(void)
                {
                    state_lock.lock();
                    if (state == thread_state::READY)
                        state = thread_state::RUNNING;
                    else
                        abort();
                    state_lock.unlock();
                    state_signal.notify_all();
                }

            private:
                static void thread_main_wrapper(kvm* that)
                { return that->thread_main(); }
                void thread_main(void);
                uint64_t handle_syscall(uint64_t nr, uint64_t arg0,
                                        uint64_t arg1, uint64_t arg2,
                                        uint64_t arg3, uint64_t arg4,
                                        uint64_t arg5);
            };

            address_space memory;
            kernel::files files;

            kvm vm;

        public:
            thread(void)
            : memory(),
              files(0, 1, 2),
              vm(memory, files)
            {}

        public:
            auto& mem(void) { return memory; }
            int join(void);
            void set_pc(uint64_t pc) { vm.regs.rip = pc; }
            void set_phdr(uint64_t phdr) { vm.phdr = phdr; }
            void set_phent(uint64_t phent) { vm.phent = phent; }
            void done_with_init(void) {
                vm.done_with_init();
                vm.wait_for_state(kvm::thread_state::READY);
            }
        };
    }
}

#endif

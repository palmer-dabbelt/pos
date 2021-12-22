// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__THREAD_HXX
#define POS__KERNEL__THREAD_HXX

#include "address_space.h++"
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
                    INIT,
                    READY,
                    RUNNING,
                    DONE,
                };

            private:
                address_space& memory;

                thread_state state;
                std::mutex state_lock;
                std::condition_variable state_signal;

                std::thread kvm_thread;
                int kvm_fd, vm_fd, cpu_fd;

            public:
                struct kvm_regs regs;
                struct kvm_sregs sregs;

            public:
                kvm(address_space& _memory)
                : memory(_memory),
                  state(thread_state::INIT),
                  state_lock(),
                  kvm_thread(thread_main_wrapper, this)
                {
                    wait_for_state(thread_state::READY);
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

                void run(void)
                {
                    state_lock.lock();
                    if (state == thread_state::READY)
                        state = thread_state::RUNNING;
                    state_lock.unlock();
                    state_signal.notify_all();
                }

            private:
                static void thread_main_wrapper(kvm* that)
                { return that->thread_main(); }
                void thread_main(void);
                uint64_t handle_syscall(uint64_t nr, uint64_t arg0);
            };

            address_space memory;
            kvm vm;

        public:
            thread(void)
            : memory(),
              vm(memory)
            {}

        public:
            auto& mem(void) { return memory; }
            int join(void);
            void set_pc(uint64_t pc) { vm.regs.rip = pc; }
        };
    }
}

#endif

// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__THREAD_HXX
#define POS__KERNEL__THREAD_HXX

#include "address_space.h++"

namespace pos {
    namespace kernel {
        /*
         * The actual state behind a guest thread that is executing within this
         * local POS instance.
         */
        class thread {
        private:
            address_space memory;
            int kvm_fd;

        public:
            thread(void)
            : memory(),
              kvm_fd(start_kvm_thread(memory))
            {}

        public:
            auto& mem(void) { return memory; }
            int join(void);

        private:
            static int start_kvm_thread(address_space& mem);
        };
    }
}

#endif

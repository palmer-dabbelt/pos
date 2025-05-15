// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__GDB_HXX
#define POS__KERNEL__GDB_HXX

#include "thread.h++"

namespace pos {
    namespace kernel {
        /*
         * A debug monitor for the program running inside POS.  This speaks
         * gdbserver to an external GDB instance.
         */
        class gdbserver {
        private:
            int _port;
            std::thread _main;

        public:
            gdbserver(std::shared_ptr<thread>& t, int port)
            : _port(port),
              _main(thread_main_wrapper, this)
            {}

        public:
            /*
             * Allows the monitor to control execution until it's done, either
             * from an external use case
             */
            void join(void) { _main.join(); }

        private:
            void main(void);
            static void thread_main_wrapper(gdbserver *that) { return that->main(); }
        };
    }
}

#endif

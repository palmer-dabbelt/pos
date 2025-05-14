// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__ELF_HXX
#define POS__KERNEL__ELF_HXX

#include "thread.h++"
#include <memory>
#include <vector>

namespace pos {
    namespace kernel {
        /*
         * Tools to manage ELF binaries, which the kernel needs to be able to
         * load.
         */
        class elf {
        private:
            const std::string path;
            std::vector<std::string> argv_prefix;

        public:
            elf(const std::string& path_)
            : path(path_)
            {}

            bool load(address_space& mem, uint64_t& entry, uint64_t& phdr,
                      uint64_t& phent, uint64_t& phnum, size_t offset=0);
            std::shared_ptr<thread> create_init_thread(const std::vector<std::string>& argv);

        public:
            /*
             * Opens an ELF from a path in the host filesystem.  This should
             * probably go away, but it's convenient for now.
             */
            static std::shared_ptr<elf> load(const std::string& path)
            { return std::make_shared<elf>(path); }
        };
    }
}

#endif

// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__ADDRESS_SPACE_HXX
#define POS__KERNEL__ADDRESS_SPACE_HXX

#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace pos {
    namespace kernel {
        class address_space {
        public:
            using va_t = uint64_t;
            using pa_t = uint64_t;
            using ha_t = uint8_t *;

        private:
            struct page_state {
                bool allocated;
            };

            static const size_t bytes_per_page = 4096;

        private:
            size_t pages;
            ha_t backing_store;
            page_state *state;
            size_t state_uninitialized;
            pa_t ptbr;

        public:
            address_space(size_t bytes=128*1024*1024)
            : pages(bytes / bytes_per_page),
              backing_store((ha_t)malloc(bytes)),
              state(new page_state[bytes / bytes_per_page]),
              state_uninitialized(0),
              ptbr(palloc())
            {}

        public:
            ssize_t map(va_t vaddr, size_t bytes, bool r, bool w, bool x);
            pa_t virt2phys(va_t vaddr) const;
            ha_t virt2host(va_t va) const { return backing_store + virt2phys(va); }

            ssize_t copy_to_va(va_t vaddr, uint8_t *data, size_t bytes);
            ssize_t zero_va(va_t vaddr, size_t bytes);

        private:
            pa_t palloc(void);
        };
    }
}

#endif

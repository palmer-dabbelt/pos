// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__ADDRESS_SPACE_HXX
#define POS__KERNEL__ADDRESS_SPACE_HXX

#include <sys/mman.h>
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
            pa_t ptbr;

        public:
            address_space(size_t bytes=128*1024*1024)
            : pages(bytes / bytes_per_page),
              backing_store((ha_t)mmap(NULL,
                                       pages * bytes_per_page,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                                       -1,
                                       0)),
              state(allocate_page_state(pages)),
              ptbr(palloc())
            {}

            ~address_space(void)
            {
                delete[] state;
                munmap(backing_store, pages * bytes_per_page);
            }

        public:
            pa_t   pa_base      (void) const { return 0x10000; }
            size_t pa_size_bytes(void) const { return pages * bytes_per_page; }
            ha_t   ha_base      (void) const { return backing_store; }
            size_t ha_size_bytes(void) const { return pa_size_bytes(); }

            pa_t ptbr_pa(void) const { return ptbr; }

            ssize_t map(va_t vaddr, size_t bytes, bool r, bool w, bool x);
            pa_t virt2phys(va_t vaddr) const;
            ha_t phys2host(pa_t pa) const { return ha_base() + pa - pa_base(); }
            ha_t virt2host(va_t va) const { return phys2host(virt2phys(va)); }

            ssize_t copy_to_va(va_t vaddr, uint8_t *data, size_t bytes);
            ssize_t zero_va(va_t vaddr, size_t bytes);

            uint8_t readb(va_t va) const { return virt2host(va)[0];}
            void writeb(va_t va, uint8_t d) { virt2host(va)[0] = d; }

        private:
            pa_t palloc(void);

            static struct page_state *allocate_page_state(size_t pages);
        };
    }
}

#endif

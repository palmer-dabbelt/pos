// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__ADDRESS_SPACE_HXX
#define POS__KERNEL__ADDRESS_SPACE_HXX

#include <sys/mman.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

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
            va_t brk;
            va_t user;

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
              ptbr(palloc()),
              brk (0x60000000),
              user(0x70000000)
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

            ssize_t copy_to_va(va_t vaddr, const uint8_t *data, size_t bytes);
            ssize_t copy_from_va(uint8_t *data, va_t vaddr, size_t bytes);

            bool mapped(va_t va) const;
            uint8_t readb(va_t va) const { return virt2host(va)[0];}
            uint8_t readq(va_t va) const { return ((uint64_t*)(virt2host(va)))[0];}
            void writeb(va_t va, uint8_t d) { virt2host(va)[0] = d; }
            void writeq(va_t va, uint64_t d) { ((uint64_t*)(virt2host(va)))[0] = d; }

            void map_all(va_t vaddr, size_t bytes, bool r, bool w, bool x)
            {
                while (bytes > 0) {
                    auto mapped = map(vaddr, bytes, r, w, x);
                    if (mapped < 0) abort();
                    vaddr += mapped;
                    if (bytes < mapped)
                        break;
                    bytes -= mapped;
                }
            }

            va_t update_brk(va_t new_brk);

            void copy_to_va_all(va_t vaddr, uint8_t *data, size_t bytes)
            {
                while (bytes > 0) {
                    auto copied = copy_to_va(vaddr, data, bytes);
                    if (copied < 0) abort();
                    vaddr += copied;
                    data += copied;
                    bytes -= copied;
                }
            }

            void copy_from_va_all(uint8_t *data, va_t vaddr, size_t bytes)
            {
                while (bytes > 0) {
                    auto copied = copy_from_va(data, vaddr, bytes);
                    if (copied < 0) abort();
                    vaddr += copied;
                    data += copied;
                    bytes -= copied;
                }
            }

            void memset_va_all(va_t vaddr, uint8_t datum, size_t bytes)
            {
                for (size_t i = 0; i < bytes; ++i)
                    writeb(vaddr + i, datum);
            }

            void zero_va_all(va_t vaddr, size_t bytes)
            {
                return memset_va_all(vaddr, 0, bytes);
            }

            va_t alloc_user(size_t bytes, bool r, bool w, bool x);

            void strcpy_va(va_t vaddr, std::string s)
            {
                copy_to_va_all(vaddr, (uint8_t *)(s.c_str()), s.length() + 1);
            }

        private:
            pa_t palloc(void);

            static struct page_state *allocate_page_state(size_t pages);
        };
    }
}

#endif

// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include "address_space.h++"
#include <cstdio>
#include <cstring>
using namespace pos::kernel;

ssize_t address_space::map(va_t vaddr, size_t bytes, bool r, bool w, bool x)
{
    pa_t pml4p = ptbr & ~0xFFF;
    pa_t pml4o = (vaddr >> 39) & 0x1FF;
    uint64_t *pml4e = (uint64_t*)phys2host(pml4p + pml4o * 8);
    if (!(*pml4e & 1)) {
        pa_t page = palloc();
        *pml4e = page | 0x7;
    }

    pa_t pdpp = *pml4e & ~0xFFF;
    pa_t pdpo = (vaddr >> 30) & 0x1FF;
    uint64_t *pdpe = (uint64_t*)phys2host(pdpp + pdpo * 8);
    if (!(*pdpe & 1)) {
        pa_t page = palloc();
        *pdpe = page | 0x7;
    }

    pa_t pdp = *pdpe & ~0xFFF;
    pa_t pdo = (vaddr >> 21) & 0x1FF;
    uint64_t *pde = (uint64_t*)phys2host(pdp + pdo * 8);
    if (!(*pde & 1)) {
        pa_t page = palloc();
        *pde = page | 0x7;
    }

    pa_t ptp = *pde & ~0xFFF;
    pa_t pto = (vaddr >> 12) & 0x1FF;
    uint64_t *pte = (uint64_t*)phys2host(ptp + pto * 8);
    if (!(*pte & 1)) {
        pa_t page = palloc();
        *pte = page | 0x7;
    }

    pa_t ppp = *pte & ~0xFFF;
    pa_t ppo = vaddr & 0xFFF;

    if (ppp + ppo != virt2phys(vaddr)) {
        fprintf(
            stderr,
            "mapping failed 0x%016lx => 0x%016lx <= 0x%016lx\n",
            ppp + ppo,
            vaddr,
            virt2phys(vaddr)
        );
        abort();
    }

    return 4096 - ppo;
}

address_space::pa_t address_space::virt2phys(va_t vaddr) const
{
    pa_t pml4p = ptbr & ~0xFFF;
    pa_t pml4o = (vaddr >> 39) & 0x1FF;
    uint64_t *pml4e = (uint64_t*)phys2host(pml4p + pml4o * 8);
    if (!(*pml4e & 1))
        return -1;

    pa_t pdpp = *pml4e & ~0xFFF;
    pa_t pdpo = (vaddr >> 30) & 0x1FF;
    uint64_t *pdpe = (uint64_t*)phys2host(pdpp + pdpo * 8);
    if (!(*pdpe & 1))
        return -2;

    pa_t pdp = *pdpe & ~0xFFF;
    pa_t pdo = (vaddr >> 21) & 0x1FF;
    uint64_t *pde = (uint64_t*)phys2host(pdp + pdo * 8);
    if (!(*pde & 1))
        return -3;

    pa_t ptp = *pde & ~0xFFF;
    pa_t pto = (vaddr >> 12) & 0x1FF;
    uint64_t *pte = (uint64_t*)phys2host(ptp + pto * 8);
    if (!(*pte & 1))
        return -4;

    pa_t ppp = *pte & ~0xFFF;
    pa_t ppo = vaddr & 0xFFF;
    return ppp + ppo;
}

bool address_space::mapped(va_t vaddr) const
{
    pa_t pml4p = ptbr & ~0xFFF;
    pa_t pml4o = (vaddr >> 39) & 0x1FF;
    uint64_t *pml4e = (uint64_t*)phys2host(pml4p + pml4o * 8);
    if (!(*pml4e & 1))
        return false;

    pa_t pdpp = *pml4e & ~0xFFF;
    pa_t pdpo = (vaddr >> 30) & 0x1FF;
    uint64_t *pdpe = (uint64_t*)phys2host(pdpp + pdpo * 8);
    if (!(*pdpe & 1))
        return false;

    pa_t pdp = *pdpe & ~0xFFF;
    pa_t pdo = (vaddr >> 21) & 0x1FF;
    uint64_t *pde = (uint64_t*)phys2host(pdp + pdo * 8);
    if (!(*pde & 1))
        return false;

    pa_t ptp = *pde & ~0xFFF;
    pa_t pto = (vaddr >> 12) & 0x1FF;
    uint64_t *pte = (uint64_t*)phys2host(ptp + pto * 8);
    if (!(*pte & 1))
        return false;

    return true;
}

address_space::pa_t address_space::palloc(void)
{
    for (size_t i = 0; i < pages; ++i) {
        if (state[i].allocated)
            continue;

        state[i].allocated = true;
        pa_t pa = pa_base() + (i * bytes_per_page);
        ha_t ha = phys2host(pa);
        memset(ha, 0, bytes_per_page);
        return pa;
    }

    return -1;
}

ssize_t address_space::copy_to_va(va_t vaddr, const uint8_t *data, size_t bytes)
{
    for (size_t i = 0; i < bytes; ++i) {
        auto ha = virt2host(vaddr + i);
        *ha = data[i];
    }

    return bytes;
}

ssize_t address_space::copy_from_va(uint8_t *data, va_t vaddr, size_t bytes)
{
    for (size_t i = 0; i < bytes; ++i) {
        auto ha = virt2host(vaddr + i);
        data[i] = *ha;
    }

    return bytes;
}

struct address_space::page_state *address_space::allocate_page_state(size_t pages)
{
    auto out = new page_state[pages];
    for (size_t i = 0; i < pages; ++i)
        out[i].allocated = false;
    return out;
}

address_space::va_t address_space::update_brk(va_t new_brk)
{
    if (new_brk > brk) {
        map_all(brk, new_brk - brk, 1, 1, 1);
        brk = new_brk;
    }

    return brk;
}

address_space::va_t address_space::alloc_user(size_t bytes, bool r, bool w, bool x)
{
    auto out = user;
    user += bytes;
    map_all(out, bytes, r, w, x);
    return out;
}

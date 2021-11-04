// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include "address_space.h++"
using namespace pos::kernel;

ssize_t address_space::map(va_t vaddr, size_t bytes, bool r, bool w, bool x)
{
    pa_t pml4p = ptbr & ~0xFFF;
    pa_t pml4o = (vaddr & (0x1FFLL << 39)) & 0x1FF;
    uint64_t *pml4e = (uint64_t*)(pml4p + pml4o);
    if (!(*pml4e & 1)) {
        pa_t page = palloc();
        *pml4e = page & 1;
    }

    pa_t pdpp = *pml4e & ~0xFFF;
    pa_t pdpo = (vaddr & (0x1FFLL << 30)) & 0x1FF;
    uint64_t *pdpe = (uint64_t*)(pdpp + pdpo);
    if (!(*pdpe & 1)) {
        pa_t page = palloc();
        *pml4e = page & 1;
    }

    pa_t pdp = *pdpe & ~0xFFF;
    pa_t pdo = (vaddr & (0x1FFLL << 21)) & 0x1FF;
    uint64_t *pde = (uint64_t*)(pdp + pdo);
    if (!(*pde & 1)) {
        pa_t page = palloc();
        *pml4e = page & 1;
    }

    pa_t ptp = *pdpe & ~0xFFF;
    pa_t pto = (vaddr & (0x1FFLL << 12)) & 0x1FF;
    uint64_t *pte = (uint64_t*)(ptp + pto);
    if (!(*pte & 1)) {
        pa_t page = palloc();
        *pml4e = page & 1;
    }

    pa_t ppo = vaddr & 0xFFF;
    return 0xFFF - ppo;
}

address_space::pa_t address_space::virt2phys(va_t vaddr) const
{
    pa_t pml4p = ptbr & ~0xFFF;
    pa_t pml4o = (vaddr & (0x1FFLL << 39)) & 0x1FF;
    uint64_t *pml4e = (uint64_t*)(pml4p + pml4o);
    if (!(*pml4e & 1))
        return -1;

    pa_t pdpp = *pml4e & ~0xFFF;
    pa_t pdpo = (vaddr & (0x1FFLL << 30)) & 0x1FF;
    uint64_t *pdpe = (uint64_t*)(pdpp + pdpo);
    if (!(*pdpe & 1))
        return -1;

    pa_t pdp = *pdpe & ~0xFFF;
    pa_t pdo = (vaddr & (0x1FFLL << 21)) & 0x1FF;
    uint64_t *pde = (uint64_t*)(pdp + pdo);
    if (!(*pde & 1))
        return -1;

    pa_t ptp = *pdpe & ~0xFFF;
    pa_t pto = (vaddr & (0x1FFLL << 12)) & 0x1FF;
    uint64_t *pte = (uint64_t*)(ptp + pto);
    if (!(*pte & 1))
        return -1;

    pa_t ppp = *pte & ~0xFFF;
    pa_t ppo = vaddr & 0xFFF;
    return ppp + ppo;
}

address_space::pa_t address_space::palloc(void)
{
    for (size_t i = 0; i < pages; ++i) {
        if (i >= state_uninitialized)
            for (size_t ii = state_uninitialized; ii <= i; ++ii)
                state[ii].allocated = false;

        if (state[i].allocated)
            continue;

        state[i].allocated = true;
        return i;
    }

    return -1;
}

ssize_t address_space::copy_to_va(va_t vaddr, uint8_t *data, size_t bytes)
{
    return 0;
}

ssize_t address_space::zero_va(va_t vaddr, size_t bytes)
{
    return 0;
}

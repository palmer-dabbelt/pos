// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include "address_space.h++"
using namespace pos::kernel;

ssize_t address_space::map(va_t vaddr, size_t bytes, bool r, bool w, bool x)
{
    
}

address_space::pa_t address_space::virt2phys(va_t vaddr) const
{
    
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

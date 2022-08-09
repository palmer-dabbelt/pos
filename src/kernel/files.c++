// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include "files.h++"
using namespace pos;
using namespace pos::kernel;

ssize_t file::read_va_all(address_space& mem, address_space::va_t va, size_t bytes)
{
    abort();
}

ssize_t local_file::read(uint8_t *buf, size_t len)
{
    return ::read(_local_fd, buf, len);
}

ssize_t local_file::write(uint8_t *buf, size_t len)
{
    return ::write(_local_fd, buf, len);
}

std::shared_ptr<file> local_file::dup(void) const
{
    return std::make_shared<local_file>(_local_fd);
}

off_t local_file::seek_absolute(off_t off)
{
    return ::lseek(_local_fd, off, SEEK_SET);
}

std::map<int, std::shared_ptr<kernel::file>> files::mktable(int sin, int sout, int serr)
{
    std::map<int, std::shared_ptr<kernel::file>> out;

    out[0] = std::make_shared<local_file>(sin);
    out[1] = std::make_shared<local_file>(sout);
    out[2] = std::make_shared<local_file>(serr);

    return out;
}

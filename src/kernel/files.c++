// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include "files.h++"
#include <fcntl.h>
using namespace pos;
using namespace pos::kernel;

ssize_t file::read_va_all(address_space& mem, address_space::va_t va, size_t bytes)
{
    uint8_t buf[4096];
    size_t total = 0;
    while (bytes > 0) {
        auto readed = read(buf, std::min(bytes, sizeof(buf)));
        if (readed == 0)
            return total;
        if (readed < 0) {
            perror("unable to read file");
            abort();
        }

        mem.copy_to_va_all(va, buf, readed);
        bytes -= readed;
        va += readed;
        total += readed;
    }
    return total;
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
    return std::make_shared<local_file>(_local_fd, -1);
}

off_t local_file::seek_absolute(off_t off)
{
    return ::lseek(_local_fd, off, SEEK_SET);
}

std::shared_ptr<file> files::open_local_by_path(std::string path, int flags, int mode)
{
    int local_fd = open(path.c_str(), flags, mode);
    return mklocal(local_fd);
}

std::shared_ptr<file> files::mklocal(int local_fd)
{
    for (size_t i = 0; i < 1024; ++i) {
        if (_fd_table.find(i) == _fd_table.end()) {
            _fd_table[i] = std::make_shared<local_file>(local_fd, i);
            return _fd_table[i];
        }
    }

    abort();
}

std::map<int, std::shared_ptr<kernel::file>> files::mktable(int sin, int sout, int serr)
{
    std::map<int, std::shared_ptr<kernel::file>> out;

    out[0] = std::make_shared<local_file>(sin, 0);
    out[1] = std::make_shared<local_file>(sout, 1);
    out[2] = std::make_shared<local_file>(serr, 2);

    return out;
}

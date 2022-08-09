// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#ifndef POS__KERNEL__FILES_HXX
#define POS__KERNEL__FILES_HXX

#include "address_space.h++"
#include <map>
#include <memory>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

namespace pos {
    namespace kernel {
        /*
         * Any file must conform to this interface.
         */
        class file {
        public:
            virtual void write_all(uint8_t *buf, size_t len)
            {
                while (len > 0) {
                    auto written = write(buf, len);
                    if (written <= 0) abort();
                    buf += written;
                    len -= written;
                }
            }

            virtual ssize_t write(uint8_t *buf, size_t len) = 0;
            virtual ssize_t read(uint8_t *buf, size_t len) = 0;
            virtual std::shared_ptr<file> dup(void) const = 0;
            virtual off_t seek_absolute(off_t off) = 0;

            virtual ssize_t read_va_all(address_space& mem, address_space::va_t va,
                                        size_t bytes);
        };

        /*
         * A file in the local filesystem, itself represented by an FD.
         */
        class local_file: public file {
        private:
            int _local_fd;

        public:
            local_file(int fd)
            : _local_fd(::dup(fd))
            {
                if (_local_fd < 0) {
                    fprintf(stderr, "unable to dup(), fd=%d\n", fd);
                    abort();
                }
            }

            ~local_file()
            {
                close(_local_fd);
            }

        protected:
            virtual ssize_t write(uint8_t *buf, size_t len) override;
            virtual ssize_t read(uint8_t *buf, size_t len) override;
            virtual std::shared_ptr<file> dup(void) const override;
            virtual off_t seek_absolute(off_t off) override;
        };

        /*
         * The mapping of FDs (in the guest) to files (in the host).
         */
        class files {
        private:
            std::map<int, std::shared_ptr<file>> _fd_table;

        public:
            files(int stdin, int stdout, int stderr)
            : _fd_table(mktable(stdin, stdout, stderr))
            {}

        public:
            std::shared_ptr<file> mutable_ref(int fd) {
                auto l = _fd_table.find(fd);
                if (l == _fd_table.end())
                    return nullptr;
                return l->second;
            }

            std::shared_ptr<file> nonmutable_ref(int fd) {
                return mutable_ref(fd)->dup();
            }

        private:
            static std::map<int, std::shared_ptr<file>> mktable(int stdin, int stdout, int stderr);
        };
    }
}

#endif

// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include <cstring>
#include <optional>
#include "kernel/elf.h++"

void help(const char *argv0)
{
    fprintf(stderr, "%s: <options> [--] <command>\n", argv0);
}

int main(int argc, char **argv)
{
    std::optional<size_t> command_offset;

    for (size_t i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--") == 0) {
            command_offset = i+1;
            break;
        } else if (strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
            return 0;
        } else if (strncmp(argv[i], "--", 2) == 0) {
            help(argv[0]);
            return 1;
        } else {
            command_offset = i;
            break;
        }
    }

    if (!command_offset.has_value()) {
        help(argv[0]);
        return 1;
    }

    auto elf = pos::kernel::elf::load(argv[command_offset.value()]);
    auto thread = elf->create_init_thread();
    return thread->join();
}

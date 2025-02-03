// SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause OR Apache-2.0

#include "elf.h++"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
using namespace pos::kernel;

std::shared_ptr<thread> elf::create_init_thread(void) const
{
    auto t = std::make_shared<thread>();
    uint64_t entry;
    uint64_t phdr;
    uint64_t phent;
    uint64_t phnum;
    if (!load(t->mem(), entry, phdr, phent, phnum))
        abort();
    t->set_pc(entry);
    t->set_phdr(phdr);
    t->set_phent(phent);
    t->set_phnum(phnum);
    t->done_with_init();
    return t;
}

bool elf::load(address_space& mem, uint64_t& entry, uint64_t& phdr_out,
               uint64_t& phent, uint64_t& phnum, size_t offset) const
{
    auto fd = open(path.c_str(), O_RDONLY);
    if (fd <= 0) {
        perror("elf::load() unable to open input file");
        return false;
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) != 0) {
        close(fd);
        return false;
    }

    uint8_t *base = (uint8_t *)mmap(0, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == nullptr) {
        close(fd);
        return false;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;

    entry = ehdr->e_entry;

    for (size_t i = 0; i < ehdr->e_phnum; ++i) {
        Elf64_Phdr *phdr = ((Elf64_Phdr *)(base + ehdr->e_phoff)) + i;

        switch (phdr->p_type) {
        case PT_LOAD:
        {
            auto r = !!(phdr->p_flags & PF_R);
            auto w = !!(phdr->p_flags & PF_W);
            auto x = !!(phdr->p_flags & PF_X);

            size_t off = 0;
            while (off < phdr->p_memsz) {
                auto vaddr = phdr->p_vaddr + off;
                auto sz = off >= phdr->p_filesz ? phdr->p_memsz : phdr->p_filesz;
                auto mapped = mem.map(vaddr, sz - off, r, w, x);

                if (mapped <= 0)
                    abort();

                if (off < phdr->p_filesz)
                    mem.copy_to_va_all(vaddr, base + phdr->p_offset + off, mapped);
                else
                    mem.zero_va_all(vaddr, mapped);

                off += mapped;
            };

            break;
        }

        case PT_DYNAMIC:
            abort();
            break;

        case PT_INTERP:
            abort();
            break;
        }
    }

    /*
     * glibc expects that it can access the program header.  There appears to
     * be a way to pass this via just mapping the ELF image in (via
     * __ehdr_start), but I can't figure out what to do with that (do I just
     * map the GNU property sections?).
     */
    phent = sizeof(Elf64_Phdr);
    phnum = ehdr->e_phnum;
    phdr_out = mem.alloc_user(phent * sizeof(Elf64_Phdr), 1, 0, 0);
    mem.copy_to_va_all(phdr_out, base + ehdr->e_phoff, phent * sizeof(Elf64_Phdr));

    munmap(base, statbuf.st_size);
    close(fd);
    return true;
}

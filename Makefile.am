CPPFLAGS += -Isrc

bin_PROGRAMS = pos
pos_SOURCES = \
	src/kernel/address_space.c++ \
	src/kernel/elf.c++ \
	src/kernel/files.c++ \
	src/kernel/thread.c++ \
	src/pos.c++

# Some simple tests for command-line argument handling
TESTS = test/pos/help.bash
XFAIL_TESTS = test/pos/noargs.bash

# A pair of super-small test cases, that just directly exit with true/false
check_PROGRAMS = check-nano_true
check_nano_true_SOURCES = test/nano_true.S
check_nano_true_CFLAGS  = -static -nostdlib -ffreestanding
TESTS += test/pos/nano_true.bash

check_PROGRAMS += check-nano_false
check_nano_false_SOURCES = test/nano_false.S
check_nano_false_CFLAGS  = -static -nostdlib -ffreestanding
XFAIL_TESTS += test/pos/nano_false.bash

check_PROGRAMS += check-nano_hlt
check_nano_hlt_SOURCES = test/nano_hlt.S
check_nano_hlt_CFLAGS  = -static -nostdlib -ffreestanding
XFAIL_TESTS += test/pos/nano_hlt.bash

check_PROGRAMS += check-nanotls_true
check_nanotls_true_SOURCES = test/nanotls_true.c test/nanotls_true-testval.c
check_nanotls_true_CFLAGS  = -static -nostdlib -ffreestanding -O3 -fpie
TESTS += test/pos/nanotls_true.bash

check_PROGRAMS += check-nanotls_false
check_nanotls_false_SOURCES = test/nanotls_false.c test/nanotls_false-testval.c
check_nanotls_false_CFLAGS  = -static -nostdlib -ffreestanding -O3 -fpie
XFAIL_TESTS += test/pos/nanotls_false.bash

TESTS += $(XFAIL_TESTS)

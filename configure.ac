AC_INIT([pos], [0.0])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_LANG([C++])
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX_17([noext])

AM_PROG_AS

AC_ARG_ENABLE(
	asan,
	[--enable-asan			Enable address sanitizer],
	[CXXFLAGS="$CXXFLAGS -fsanitize=address -g -Og -fno-omit-frame-pointer -rdynamic"]
)

AC_ARG_ENABLE(
	debug-kvm,
	[--enable-debug-kvm		Print a KVM instruction log],
	[CXXFLAGS="$CXXFLAGS -DPOS_DEBUG_KVM=1"]
)

AC_ARG_ENABLE(
	debug-syscalls,
	[--enable-debug-syscalls	Print a syscall log],
	[CXXFLAGS="$CXXFLAGS -DPOS_DEBUG_SYSCALLS=1"]
)

AC_CHECK_FILE([/System/Library/Frameworks/Hypervisor.framework],
              [has_osx_hypervisor=yes],
              [has_osx_hypervisor=no])
if test "x$has_osx_hypervisor" = "xyes"; then
    FRAMEWORKS="$FRAMEWORKS -framework Hypervisor"
    AC_DEFINE([HAVE_OSX_HYPERVISOR], [1], "Use the OSX hypervisor")
fi
AC_SUBST([FRAMEWORKS])

AC_CHECK_HEADERS([sys/auxv.h])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

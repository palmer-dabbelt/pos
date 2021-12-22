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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

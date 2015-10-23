AC_PREREQ(2.59)
AC_COPYRIGHT([Copyright (c) 2015 UPLEX Nils Goroll Systemoptimierung])
AC_INIT([libvmod-oob_probe], [trunk])
AC_CONFIG_MACRO_DIR([m4])
m4_ifndef([VARNISH_VMOD_INCLUDES], AC_MSG_ERROR([Need varnish.m4 -- see README.rst]))
AC_CONFIG_SRCDIR(src/vmod.vcc)
AM_CONFIG_HEADER(config.h)

AC_CANONICAL_SYSTEM
AC_LANG(C)

AM_INIT_AUTOMAKE([foreign])

AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CC_STDC
if test "x$ac_cv_prog_cc_c99" = xno; then
	AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi
AC_PROG_CPP

AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

# Check for rst utilities
AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], "no")
if test "x$RST2MAN" = "xno"; then
	AC_MSG_WARN([rst2man not found - not building man pages])
fi
AM_CONDITIONAL(HAVE_RST2MAN, [test "x$RST2MAN" != "xno"])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADER(sys/types.h)
AC_CHECK_HEADER(sys/socket.h)
AC_CHECK_HEADER(netdb.h)

# backwards compat with older pkg-config
# - pull in AC_DEFUN from pkg.m4
m4_ifndef([PKG_CHECK_VAR], [
# PKG_CHECK_VAR(VARIABLE, MODULE, CONFIG-VARIABLE,
# [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -------------------------------------------
# Retrieves the value of the pkg-config variable for the given module.
AC_DEFUN([PKG_CHECK_VAR],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])dnl

_PKG_CONFIG([$1], [variable="][$3]["], [$2])
AS_VAR_COPY([$1], [pkg_cv_][$1])

AS_VAR_IF([$1], [""], [$5], [$4])dnl
])# PKG_CHECK_VAR
])

PKG_CHECK_MODULES([libvarnishapi], [varnishapi])
PKG_CHECK_VAR([LIBVARNISHAPI_PREFIX], [varnishapi], [prefix])
PKG_CHECK_VAR([LIBVARNISHAPI_DATAROOTDIR], [varnishapi], [datarootdir])
PKG_CHECK_VAR([LIBVARNISHAPI_BINDIR], [varnishapi], [bindir])
PKG_CHECK_VAR([LIBVARNISHAPI_SBINDIR], [varnishapi], [sbindir])
AC_SUBST([LIBVARNISHAPI_DATAROOTDIR])

# Varnish include files tree
VARNISH_VMOD_INCLUDES
VARNISH_VMOD_DIR
VARNISH_VMODTOOL
# inherit the prefix from Varnish.
# acessing ac_ variable because AC_PREFIX_DEFAULT acts too early
ac_default_prefix=$LIBVARNISHAPI_PREFIX

AC_PATH_PROG([VARNISHTEST], [varnishtest], [],
    [$LIBVARNISHAPI_BINDIR:$LIBVARNISHAPI_SBINDIR:$PATH])
AC_PATH_PROG([VARNISHD], [varnishd], [],
    [$LIBVARNISHAPI_SBINDIR:$LIBVARNISHAPI_BINDIR:$PATH])

##
## --enable-developer-warnings, --enable-stack-protector and
## --enable-debugging-symbols from Varnish 4.1 configure.ac
##

#######################################################################
# Now that we're done using the compiler to look for functions and
# libraries, set CFLAGS to what we want them to be for our own code

# This is a test to see how much havoc Jenkins exposes.
#
# The reason for -Wno-error=unused-result is a glibc/gcc interaction
# idiocy where write is marked as warn_unused_result, causing build
# failures.
CFLAGS="${CFLAGS} -Wall -Werror"
OCFLAGS="${OCFLAGS} -Wall -Werror"
AX_CHECK_COMPILE_FLAG([-Werror=unused-result],
    [CFLAGS="${CFLAGS} -Wno-error=unused-result"
     OCFLAGS="${OCFLAGS} -Wno-error=unused-result"],
    [AX_CHECK_COMPILE_FLAG([-Wunused-result],
     [CFLAGS="${CFLAGS} -Wno-unused-result"
      OCFLAGS="${OCFLAGS} -Wno-unused-result"])])

# This corresponds to FreeBSD's WARNS level 6
DEVELOPER_CFLAGS=" \
	-Werror \
	-Wall \
	-Wno-format-y2k \
	-W \
	-Wstrict-prototypes \
	-Wmissing-prototypes \
	-Wpointer-arith \
	-Wreturn-type \
	-Wcast-qual \
	-Wwrite-strings \
	-Wswitch \
	-Wshadow \
	-Wunused-parameter \
	-Wcast-align \
	-Wchar-subscripts \
	-Wnested-externs \
	-Wextra \
	-Wno-sign-compare \
"

# These are not compliable yet
DEVELOPER_GCC_CFLAGS="-Wold-style-definition -Wredundant-decls "
#DEVELOPER_CFLAGS="${DEVELOPER_CFLAGS} ${DEVELOPER_GCC_CFLAGS}"

# These are compilable
DEVELOPER_CLANG_CFLAGS="-Wmissing-variable-declarations -Wno-string-plus-int"
# -Wno-empty-body
#DEVELOPER_CFLAGS="${DEVELOPER_CFLAGS} ${DEVELOPER_CLANG_CFLAGS}"

# --enable-stack-protector
AC_ARG_ENABLE(stack-protector,
       AS_HELP_STRING([--enable-stack-protector],[enable stack protector (default is YES)]),
       [],
       [enable_stack_protector=yes])

if test "x$enable_stack_protector" != "xno"; then
	AX_CHECK_COMPILE_FLAG([-fstack-protector],
		AX_CHECK_LINK_FLAG([-fstack-protector],
			[DEVELOPER_CFLAGS="${DEVELOPER_CFLAGS} -fstack-protector"], [], []),
		[], [])
fi

# --enable-developer-warnings
AC_ARG_ENABLE(developer-warnings,
	AS_HELP_STRING([--enable-developer-warnings],[enable strict warnings (default is NO)]),
	[],
	[enable_developer_warnings=no])

if test "x$enable_developer_warnings" != "xno"; then
	# compiler flags not available on gcc3
	AX_CHECK_COMPILE_FLAG([-Wno-pointer-sign],
		[DEVELOPER_CFLAGS="${DEVELOPER_CFLAGS} -Wno-pointer-sign"], [], [])
	# Not available in gcc 4.1.2
	AX_CHECK_COMPILE_FLAG([-Wno-address],
		[DEVELOPER_CFLAGS="${DEVELOPER_CFLAGS} -Wno-address"])

	# no known way to specifically disabling missing-field-initializers warnings
	# keeping the rest of Wextra
	AX_CHECK_COMPILE_FLAG([-Wno-missing-field-initializers],
		[DEVELOPER_CFLAGS="${DEVELOPER_CFLAGS} -Wno-missing-field-initializers"],
		[DEVELOPER_CFLAGS="${DEVELOPER_CFLAGS} -Wno-extra"],
		[])

	CFLAGS="${CFLAGS} ${DEVELOPER_CFLAGS}"
	OCFLAGS="${OCFLAGS} ${DEVELOPER_CFLAGS}"
fi

# --enable-debugging-symbols
AC_ARG_ENABLE(debugging-symbols,
	AS_HELP_STRING([--enable-debugging-symbols],[enable debugging symbols (default is NO)]),
	CFLAGS="${CFLAGS} -O0 -g -fno-inline")

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([digest-cache-tools], [0.1.0], [roberto.sassu@huawei.com])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

# Enable debug.
AC_ARG_ENABLE([debug], [  --enable-debug    Turn on debugging],
	      [debug=${enableval}], [debug=no])

if test -z "$CFLAGS"; then
  if test "$debug" == yes; then
    CFLAGS="-O0 -g"
  else
    CFLAGS="-O2"
  fi
fi

if test "$debug" == yes; then
  CFLAGS="$CFLAGS -DDEBUG"
fi

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_SEARCH_LIBS([SHA256_Init], [crypto])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([openssl/evp.h], [], [crypto=no])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_SIZEOF(long)

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([ftruncate memset munmap strstr])

# Check availability of initrd tools

CFLAGS="$CFLAGS -Wall -Werror -Wextra"

AC_SUBST(CFLAGS)

AC_CONFIG_FILES([Makefile
		 docs/Makefile
		 include/Makefile
		 lib/Makefile
		 src/Makefile])
AC_OUTPUT
cat <<EOF

CFLAGS:				${CFLAGS}

EOF
AC_PREREQ(2.61)
AC_INIT([avmon], [0.4.2], [avmon@ramsesmorales.com])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([avmon/avmon.c])
AM_INIT_AUTOMAKE([1.10 foreign])
AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_STDC
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB(m, floor)
AC_CHECK_LIB(pthread, pthread_create)

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.6])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES([OPENSSL], [openssl])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h errno.h math.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([gethostname gettimeofday memset mkfifo pow select socket strerror strstr])

AC_OUTPUT([
Makefile
avmon/Makefile
mini/Makefile
])

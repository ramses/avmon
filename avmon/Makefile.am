MAINTAINERCLEANFILES    = Makefile.in

INCLUDES                = -I$(top_builddir) -I$(top_srcdir) $(GLIB_CFLAGS) $(OPENSSL_CFLAGS)

AM_CFLAGS               = -Wall -g

pkginclude_HEADERS      = common.h avmon.h conf.h net.h messages.h listener.h util.h

lib_LTLIBRARIES         = libavmon.la
libavmon_la_SOURCES     = avmon.c net.c conf.c messages.c listener.c util.c
libavmon_la_LDFLAGS     = -version-info 0:0:0
libavmon_la_LIBADD       = $(GLIB_LIBS) $(OPENSSL_LIBS)

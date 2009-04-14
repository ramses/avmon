MAINTAINERCLEANFILES = Makefile.in

INCLUDES             = -I$(top_builddir) -I$(top_builddir)/avmon \
		       -I$(top_srcdir) -I$(top_srcdir)/avmon \
		       $(GLIB_CFLAGS)

AM_CFLAGS            = -Wall -g

bin_PROGRAMS         = mini-monitor mini-query

mini_monitor_SOURCES = mini-monitor.c 
mini_monitor_LDADD   = $(top_builddir)/avmon/libavmon.la

mini_query_SOURCES   = mini-query.c
mini_query_LDADD     = $(top_builddir)/avmon/libavmon.la $(GLIB_LIBS)

EXTRA_DIST = start stop quit sample1.conf sample2.conf

LDFLAGS = -static

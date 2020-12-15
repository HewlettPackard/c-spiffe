## Process this file with automake to produce Makefile.in

TESTS = check_util
check_PROGRAMS = check_util
check_util_SOURCES = check_util.c $(top_builddir)/include/util.h
check_util_CFLAGS = @CHECK_CFLAGS@
check_util_LDADD = $(top_builddir)/src/libutil.la @CHECK_LIBS@

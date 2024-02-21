if CMOCKA
TESTS_ENVIRONMENT = \
	LD_LIBRARY_PATH=$(top_srcdir)/lib/.libs; export LD_LIBRARY_PATH;

check_PROGRAMS=gen
TESTS = $(check_PROGRAMS)

gen_LDFLAGS=-no-undefined -avoid-version
gen_LDADD=$(top_srcdir)/lib/libdigestcache.la -lcmocka
gen_CFLAGS=${DEPS_CFLAGS} -DUNIT_TESTING -I$(top_srcdir)/include
gen_SOURCES=gen.c
endif

lib_LTLIBRARIES=libdigestcache.la

libdigestcache_la_LDFLAGS=-no-undefined -avoid-version
libdigestcache_la_LIBADD=
libdigestcache_la_SOURCES=common.c \
			  generators/tlv.c \
			  parsers/tlv.c \
			  parsers/tlv_parser.c
libdigestcache_la_CFLAGS=-I$(top_srcdir)/include

#if RPM
libdigestcache_la_SOURCES+=generators/rpm.c parsers/rpm.c
libdigestcache_la_LIBADD+=-lrpm
#endif

rpm_plugins_LTLIBRARIES=

#if RPM
rpm_pluginsdir=$(libdir)/rpm-plugins

rpm_plugins_LTLIBRARIES+=digest_cache.la

digest_cache_la_LDFLAGS=-no-undefined -avoid-version -module
digest_cache_la_SOURCES=digest_cache.c
digest_cache_la_LIBADD=$(top_srcdir)/lib/libdigestcache.la
digest_cache_la_CFLAGS=-I$(top_srcdir)/include

macros_d_confdir=$(prefix)/lib/rpm/macros.d
macros_d_conf_DATA = macros.digest_cache
EXTRA_DIST = macros.digest_cache
#endif

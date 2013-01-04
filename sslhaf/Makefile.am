
h_sources = sslhaf.h
c_sources = sslhaf.c

library_includedir = $(includedir)/$(GENERIC_LIBRARY_NAME)
library_include_HEADERS = $(h_sources)

INCLUDES = -I$(top_srcdir)
AM_CFLAGS = -D_GNU_SOURCE -g -O2 -Wall -Wextra -std=gnu99 -pedantic \
    -Wextra -Wno-missing-field-initializers -Wshadow -Wpointer-arith \
    -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter

lib_LTLIBRARIES= libsslhaf.la
libsslhaf_la_SOURCES= $(h_sources) $(c_sources)
libsslhaf_la_CFLAGS= @APR_CFLAGS@
libsslhaf_la_CPPFLAGS= @APR_CPPFLAGS@ @HTTPD_CPPFLAGS@
libsslhaf_la_LDFLAGS= -version-info $(GENERIC_LIBRARY_VERSION) -release $(GENERIC_RELEASE) @APR_LDFLAGS@
libsslhaf_la_LIBADD= @APR_LDADD@

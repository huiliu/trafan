MAINTAINERCLEANFILES =   \
	configure              \
	aclocal.m4             \
	stamp-h.in             \
	config.h.in            \
	Makefile.in            \
	aux_files/config.guess \
	aux_files/config.sub   \
	aux_files/ltconfig     \
	aux_files/ltmain.sh    \
	aux_files/install-sh   \
	aux_files/mkinstalldirs

EXTRA_DIST =              \
	aux_files/install-sh    \
	aux_files/mkinstalldirs \
	aux_files/config.sub    \
	aux_files/config.guess  \
	aux_files/ltconfig      \
	aux_files/ltmain.sh 

bin_PROGRAMS   = trafan 
trafan_SOURCES = trafan.c
trafan_CFLAGS  = $(libevent_CFLAGS) $(libglib2_CFLAGS)
trafan_LDADD   = $(libevent_LIBS) $(libglib2_LIBS)

# $Id: Makefile,v 1.8 2006/02/22 15:26:18 raven Exp $
#
# Makefile for autofs
#

-include ../Makefile.conf
include ../Makefile.rules

SRCS = automount.c indirect.c direct.c spawn.c module.c mount.c lookup.c
OBJS = automount.o indirect.o direct.o spawn.o module.o mount.o lookup.o

version := $(shell cat ../.version)

CFLAGS += -rdynamic $(DAEMON_CFLAGS) -DAUTOFS_LIB_DIR=\"$(autofslibdir)\" -DVERSION_STRING=\"$(version)\" -D_GNU_SOURCE -I../include
LDFLAGS += -rdynamic
LIBS = -ldl

all: automount

automount: $(OBJS) $(AUTOFS_LIB)
	$(CC) $(LDFLAGS) $(DAEMON_LDFLAGS) -o automount $(OBJS) $(AUTOFS_LIB) $(LIBS)
	$(STRIP) automount

clean:
	rm -f *.o *.s *~ automount

install: all
	install -d -m 755 $(INSTALLROOT)$(sbindir)
	install -c automount -m 755 $(INSTALLROOT)$(sbindir)



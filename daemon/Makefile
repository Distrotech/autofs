# $Id: Makefile,v 1.1 2003/09/09 11:21:49 raven Exp $
#
# Makefile for autofs
#

-include ../Makefile.conf
include ../Makefile.rules

SRCS = automount.c spawn.c module.c mount.c
OBJS = automount.o spawn.o module.o mount.o

version := $(shell cat ../.version)

CFLAGS += -rdynamic -DAUTOFS_LIB_DIR=\"$(autofslibdir)\" -DVERSION_STRING=\"$(version)\" -I../include
LDFLAGS += -rdynamic
LIBS = -ldl

all: automount

automount: $(OBJS)
	$(CC) $(LDFLAGS) -o automount $(OBJS) $(LIBS)
	$(STRIP) automount

clean:
	rm -f *.o *.s automount

install: all
	install -c automount -m 755 $(INSTALLROOT)$(sbindir)



# $Id: Makefile,v 1.1 2003/09/29 08:22:35 raven Exp $
#
# Makefile for autofs utility library
#

-include ../Makefile.conf
include ../Makefile.rules

RPCGEN = /usr/bin/rpcgen
RANLIB = /usr/bin/ranlib

SRCS = cache.c listmount.c
RPCS = mount.h mount_clnt.c mount_xdr.c
OBJS = cache.o mount_clnt.o mount_xdr.o listmount.o

LIB = autofs.a

CFLAGS += -I../include -fpic -D_GNU_SOURCE -DHAVE_TCP_WRAPPER -DNFS3_SUPPORTED

.PHONY: all install clean

all: autofs.a

autofs.a: $(OBJS)
	rm -f $(LIB)
	$(AR) $(ARFLAGS) $(LIB) $(OBJS)
	-$(RANLIB) $(LIB)

mount.h: mount.x
	$(RPCGEN) -h -o mount.h mount.x

mount_clnt.c: mount.h
	$(RPCGEN) -l -o mount_clnt.c mount.x

mount_clnt.o: mount_clnt.c
	$(CC) $(CFLAGS) -o mount_clnt.o -c mount_clnt.c
	$(STRIP) mount_clnt.o

mount_xdr.c: mount.h
	$(RPCGEN) -c -o mount_xdr.c mount.x

mount_xdr.o: mount_xdr.c
	$(CC) $(CFLAGS) -Wno-unused-variable -o mount_xdr.o -c mount_xdr.c
	$(STRIP) mount_xdr.o

listmount.o: listmount.c
	$(CC) $(CFLAGS) -o listmount.o -c listmount.c
	$(STRIP) listmount.o

install: all

clean:
	rm -f $(LIB) $(RPCS) $(OBJS) *~


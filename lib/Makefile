# $Id: Makefile,v 1.18 2006/03/26 05:41:50 raven Exp $
#
# Makefile for autofs utility library
#

-include ../Makefile.conf
include ../Makefile.rules

#RPCGEN = /usr/bin/rpcgen
#RANLIB = /usr/bin/ranlib
#YACC = /usr/bin/bison

SRCS = cache.c cat_path.c rpc_subs.c mounts.c log.c nsswitch.c \
	master_tok.l master_parse.y nss_tok.c nss_parse.tab.c \
	args.c alarm.c macros.c master.c
RPCS = mount.h mount_clnt.c mount_xdr.c
OBJS = cache.o mount_clnt.o mount_xdr.o cat_path.o rpc_subs.o \
	mounts.o log.o nsswitch.o master_tok.o master_parse.tab.o \
	nss_tok.o nss_parse.tab.o args.o alarm.o macros.o master.o

LIB = autofs.a

CFLAGS += -I../include -fPIC -D_GNU_SOURCE -DHAVE_TCP_WRAPPER -DNFS3_SUPPORTED

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

master_tok.c: master_tok.l
	$(LEX) -o$@ -Pmaster_ $?

master_parse.tab.c master_parse.tab.h: master_parse.y
	$(YACC) -v -d -p master_ -b master_parse $?

master_tok.o: master_tok.c master_parse.tab.h

master_parse.tab.o: master_parse.tab.c master_parse.tab.h

nss_tok.c: nss_tok.l
	$(LEX) -o$@ -Pnss_ $?

nss_parse.tab.c nss_parse.tab.h: nss_parse.y
	$(YACC) -v -d -p nss_ -b nss_parse $?

nss_tok.o: nss_tok.c nss_parse.tab.h

nss_parse.tab.o: nss_parse.tab.c nss_parse.tab.h

install: all

clean:
	rm -f $(LIB) $(RPCS) $(OBJS) *~


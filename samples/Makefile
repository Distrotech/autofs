#
# $Id: Makefile,v 1.9 2006/03/21 04:28:53 raven Exp $
#
-include ../Makefile.conf
include ../Makefile.rules

ifeq ($(LDAP), 1)
  SRCS = autofs-ldap-auto-master.c
  OBJS = autofs-ldap-auto-master.o
  BINS = autofs-ldap-auto-master
endif

CFLAGS += -I../include
LIBS = -lldap -llber

all: $(BINS) rc.autofs

autofs-ldap-auto-master: $(OBJS)
	$(CC) $(LDFLAGS) -o autofs-ldap-auto-master $(OBJS) $(LIBS)
	$(STRIP) autofs-ldap-auto-master

rc.autofs: rc.autofs.in
	sed -e "s|@@sbindir@@|$(sbindir)|g" \
	    -e "s|@@autofslibdir@@|$(autofslibdir)|g" \
	    -e "s|@@autofsconfdir@@|$(autofsconfdir)|g" \
	    -e "s|@@initdir@@|$(initdir)|g" < rc.autofs.in > rc.autofs

install: all
	install -d -m 755 $(INSTALLROOT)$(autofsconfdir)
	install -c autofs.conf.default -m 755 $(INSTALLROOT)$(autofsconfdir)/autofs
	install -d -m 755 $(INSTALLROOT)$(autofsmapdir)
	-mv -f $(INSTALLROOT)$(autofsmapdir)/auto.master $(INSTALLROOT)$(autofsmapdir)/auto.master.old
	install -c auto.master -m 644 $(INSTALLROOT)$(autofsmapdir)
	-mv -f $(INSTALLROOT)$(autofsmapdir)/auto.misc $(INSTALLROOT)$(autofsmapdir)/auto.misc.old
	install -c auto.misc   -m 644 $(INSTALLROOT)$(autofsmapdir)
	-mv -f $(INSTALLROOT)$(autofsmapdir)/auto.net $(INSTALLROOT)$(autofsmapdir)/auto.net.old
	install -c auto.net    -m 755 $(INSTALLROOT)$(autofsmapdir)
	-mv -f $(INSTALLROOT)$(autofsmapdir)/auto.smb $(INSTALLROOT)$(autofsmapdir)/auto.smb.old
	install -c auto.smb    -m 755 $(INSTALLROOT)$(autofsmapdir)
	install -d -m 755 $(INSTALLROOT)$(initdir)
	install -c rc.autofs   -m 755 $(INSTALLROOT)$(initdir)/autofs
	install -d -m 755 $(INSTALLROOT)$(autofslibdir)
	install -d -m 755 $(INSTALLROOT)/var/run/autofs
ifeq ($(LDAP), 1)
	install -c autofs-ldap-auto-master -m 755 $(INSTALLROOT)$(autofslibdir)
endif

clean:
	rm -f *.o *.s autofs-ldap-auto-master rc.autofs


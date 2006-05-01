#
# $Id: Makefile,v 1.12 2006/04/03 23:00:05 raven Exp $
#
-include ../Makefile.conf
include ../Makefile.rules

all: autofs.init autofs.sysconfig

autofs.init: autofs.init.in
	sed -e "s|@@sbindir@@|$(sbindir)|g" \
	    -e "s|@@autofslibdir@@|$(autofslibdir)|g" \
	    -e "s|@@autofsconfdir@@|$(autofsconfdir)|g" \
	    -e "s|@@initdir@@|$(initdir)|g" < autofs.init.in > autofs.init

autofs.sysconfig: autofs.sysconfig.in
	sed -e "s|@@autofsmapdir@@|$(autofsmapdir)|g" \
		< autofs.sysconfig.in > autofs.sysconfig

clean:
	rm -f autofs.init autofs.sysconfig


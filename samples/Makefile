#
# $Id: Makefile,v 1.12 2006/04/03 23:00:05 raven Exp $
#
-include ../Makefile.conf
include ../Makefile.rules

SAMPLES = auto.master auto.misc auto.net auto.smb

all: rc.autofs autofs.conf.default

rc.autofs: rc.autofs.in
	sed -e "s|@@sbindir@@|$(sbindir)|g" \
	    -e "s|@@autofslibdir@@|$(autofslibdir)|g" \
	    -e "s|@@autofsconfdir@@|$(autofsconfdir)|g" \
	    -e "s|@@initdir@@|$(initdir)|g" < rc.autofs.in > rc.autofs

autofs.conf.default: autofs.conf.default.in
	sed -e "s|@@autofsmapdir@@|$(autofsmapdir)|g" \
		< autofs.conf.default.in > autofs.conf.default

.PHONY: dirs
dirs:
	install -d -m 755 $(INSTALLROOT)$(autofsmapdir)
	install -d -m 755 $(INSTALLROOT)$(autofsconfdir)
	install -d -m 755 $(INSTALLROOT)$(autofslibdir)
	install -d -m 755 $(INSTALLROOT)/var/run/autofs

.PHONY: autofs.init
autofs.init:
	@echo
ifneq ($(initdir),)
	install -d -m 755 $(INSTALLROOT)$(initdir)
	install -c rc.autofs -m 755 $(INSTALLROOT)$(initdir)/autofs
else
	if test -d $(INSTALLROOT)/etc/rc.d ; then \
		install -c rc.autofs -m 755 $(INSTALLROOT)/etc/rc.d ; \
	fi
endif

CONFIG = $(shell test -e $(INSTALLROOT)$(autofsconfdir)/autofs.orig || echo "-b --suffix=.orig")
CEXISTS = $(shell test -e $(INSTALLROOT)$(autofsconfdir)/autofs || echo "no")

.PHONY: autofs.conf
autofs.conf: autofs.conf.default
	@echo
	@echo "Installing autofs default configuation in $(autofsconfdir)"
	@if test -z "$(CONFIG)" ; \
	then \
		install -v -c autofs.conf.default -m 755 \
			$(INSTALLROOT)$(autofsconfdir)/autofs.conf.new ; \
		echo "Found existing backup of configuration file." ; \
		echo "Installed package default configuration file as \"autofs.conf.new\"." ; \
	else \
		install -v -c autofs.conf.default -m 755 $(CONFIG) \
				$(INSTALLROOT)$(autofsconfdir)/autofs ; \
		echo "Installed package configuration configuration as \"autofs\"." ; \
		if test -z "$(CEXISTS)" ; \
		then \
			echo "Backup of existing configuration made to \"autofs.orig\"." ; \
		fi ; \
	fi

MASTER = $(shell test -e $(INSTALLROOT)$(autofsmapdir)/auto.master.orig || echo "-b --suffix=.orig")
MEXISTS = $(shell test -e $(INSTALLROOT)$(autofsmapdir)/auto.master || echo "no")

.PHONY: auto.master
auto.master:
	@echo
	@echo "Installing autofs default master map in $(autofsmapdir)"
	@if test -z "$(MASTER)" ; \
	then \
		install -v -c auto.master -m 644 \
			$(INSTALLROOT)$(autofsmapdir)/auto.master.new ; \
		echo "Found existing backup of master map." ; \
		echo "Installed package default master map as \"auto.master.new\"." ; \
	else \
		install -v -c auto.master -m 755 $(MASTER) \
				$(INSTALLROOT)$(autofsmapdir)/auto.master ; \
		echo "Installed package master map as \"auto.master\"." ; \
		if test -z "$(MEXISTS)" ; \
		then \
			echo "Backup of existing map made to \"auto.master.orig\"." ; \
		fi ; \
	fi

MISC = $(shell test -e $(INSTALLROOT)$(autofsmapdir)/auto.misc.orig || echo "-b --suffix=.orig")
IEXISTS = $(shell test -e $(INSTALLROOT)$(autofsmapdir)/auto.misc || echo "no")

.PHONY: auto.misc
auto.misc:
	@echo
	@echo "Installing autofs sample map \"auto.misc\" in $(autofsmapdir)"
	@if test -z "$(MISC)" ; \
	then \
		install -v -c auto.misc -m 644 \
			$(INSTALLROOT)$(autofsmapdir)/auto.misc.new ; \
		echo "Found existing backup of sample map \"auto.misc\"." ; \
		echo "Installed package sample as \"auto.misc.new\"." ; \
	else \
		install -v -c auto.misc -m 755 $(MISC) \
				$(INSTALLROOT)$(autofsmapdir)/auto.misc ; \
		echo "Installed package sample map as \"auto.misc\"." ; \
		if test -z "$(MEXISTS)" ; \
		then \
			echo "Backup of existing map made to \"auto.misc.orig\"." ; \
		fi ; \
	fi

NET = $(shell test -e $(INSTALLROOT)$(autofsmapdir)/auto.net.orig || echo "-b --suffix=.orig")
NEXISTS = $(shell test -e $(INSTALLROOT)$(autofsmapdir)/auto.net || echo "no")

.PHONY: auto.net
auto.net:
	@echo
	@echo "Installing autofs sample map \"auto.net\" in $(autofsmapdir)"
	@if test -z "$(NET)" ; \
	then \
		install -v -c auto.net -m 644 \
			$(INSTALLROOT)$(autofsmapdir)/auto.net.new ; \
		echo "Found existing backup of sample map \"auto.net\"." ; \
		echo "Installed package sample as \"auto.net.new\"." ; \
	else \
		install -v -c auto.net -m 755 $(NET) \
				$(INSTALLROOT)$(autofsmapdir)/auto.net ; \
		echo "Installed package sample map as \"auto.net\"." ; \
		if test -z "$(NEXISTS)" ; \
		then \
			echo "Backup of existing map made to \"auto.net.orig\"." ; \
		fi ; \
	fi

SMB = $(shell test -e $(INSTALLROOT)$(autofsmapdir)/auto.smb.orig || echo "-b --suffix=.orig")
SEXISTS = $(shell test -e $(INSTALLROOT)$(autofsmapdir)/auto.smb || echo "no")

.PHONY: auto.smb
auto.smb:
	@echo
	@echo "Installing autofs sample map \"auto.smb\" in $(autofsmapdir)"
	@if test -z "$(SMB)" ; \
	then \
		install -v -c auto.smb -m 644 \
			$(INSTALLROOT)$(autofsmapdir)/auto.smb.new ; \
		echo "Found existing backup of sample map \"auto.smb\"." ; \
		echo "Installed package sample as \"auto.smb.new\"." ; \
	else \
		install -v -c auto.net -m 755 $(SMB) \
				$(INSTALLROOT)$(autofsmapdir)/auto.smb ; \
		echo "Installed package sample map as \"auto.smb\"." ; \
		if test -z "$(SEXISTS)" ; \
		then \
			echo "Backup of existing map made to \"auto.smb.orig\"." ; \
		fi ; \
	fi

install: rc.autofs autofs.conf.default dirs autofs.init autofs.conf $(SAMPLES)
	@echo

clean:
	rm -f *.o *.s rc.autofs autofs.conf.default


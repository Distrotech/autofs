# -*-makefile-*-
#
# ident $Id: Makefile,v 1.1 2005/11/27 04:08:54 raven Exp $
#
# Makefile for the Linux 2.6 autofs4 kernel module
#
-include ../version

# Include configuration for this system
SRCDIR := $(shell pwd)
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
VERSION ?= $(shell uname -r)

DESTDIR =

INCLUDEDIR := $(KERNELDIR)/include
INSTALLDIR := /lib/modules/$(VERSION)/kernel
MODDIR := $(INSTALLDIR)/fs/autofs4

KERNELCFG = $(KERNELDIR)/.config
-include $(KERNELCFG)

VERBOSE = 
#VERBOSE = "V=1"

INSTALL := /usr/bin/install
DEPMOD := /sbin/depmod

.PHONY: all install uninstall default clean

all: include-test config-test default

O_HDRS  = autofs_i.h
L_HDRS  = include/linux/auto_fs4.h include/linux/auto_fs.h
O_SRCS  = init.c root.c inode.c symlink.c waitq.c expire.c
O_OBJS  = init.o root.o inode.o symlink.o waitq.o expire.o
O_OTHER = Makefile Makefile.kern
TARGET	= autofs4.o

$(O_OBJS): $(O_HDRS) $(L_HDRS)

EXTRA_CFLAGS := -include $(SUBDIRS)/../include/linux/auto_fs4.h

MODULE = autofs4.ko
obj-m := autofs4.o

autofs4-objs := $(O_OBJS)

default:
	$(MAKE) $(VERBOSE) -C $(KERNELDIR) SUBDIRS=$(SRCDIR) modules

BACKUP  = $(shell test -e $(MODDIR)/$(MODULE).orig || echo "-b --suffix=.orig")

install: all
	-@$(INSTALL) -o root -g root -m 755 -d $(DESTDIR)$(MODDIR)
	$(INSTALL) -o root -g root -m 644 $(BACKUP) $(MODULE) $(DESTDIR)$(MODDIR)
	$(DEPMOD) -ae

uninstall:
	if test -e $(DESTDIR)$(MODDIR)/$(MODULE).orig; then \
		mv -f $(DESTDIR)$(MODDIR)/$(MODULE).orig $(DESTDIR)$(MODDIR)/$(MODULE); \
	fi

.PHONY: include-test
include-test:
	@# INCLUDEDIR must point to a valid tree of header files.
	@#   We just test for one we know should be there and must
	@#   fail if it can't be found.
	@if ! test -e $(INCLUDEDIR)/linux/module.h; then \
		echo "ERROR: include files directory does not seem to be valid"; \
		exit 1; \
	fi

.PHONY: config-test
config-test:
	@# KERNELCFG must point to a valid kernel config file.
	@if ! (test -e $(KERNELCFG) -o -e $(KERNELDIR)/.config); then \
		echo "ERROR: kernel config file cannot be found"; \
		exit 1; \
	fi

clean:
	rm -f $(MODULE) $(TARGET) $(O_OBJS)
	rm -rf *.mod.[oc] .*.ko.cmd .*.o.cmd .tmp_versions
	-@rm -f *.d .*.flags \#* *~
	-@rm -rf tmp
	-@rm -f tags

.PHONY: dist
dist:
	@for file in $(O_HDRS) $(O_SRCS) $(O_OTHER); do \
		cp $$file $(distdir)/$$file; \
	done
	@cp -r ../include $(distdir)/..

.PHONY: tags
tags:
	ctags *.[hc]


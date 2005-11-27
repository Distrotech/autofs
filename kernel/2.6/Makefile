-include version

distdir=autofs4-$(AUTOFS4_VERSION)
distarchive=$(distdir).tar.gz

DISTFILES=CHANGELOG Makefile README autofs4.spec version
DIST_SUBDIRS=autofs4 debian include

DESTDIR = 
KVERS ?= $(shell uname -r)

.PHONY: all

all: 
	make -C autofs4

.PHONY: install
install:
	make -C autofs4 install

.PHONY: uninstall
uninstall:
	make -C autofs4 uninstall

.PHONY: clean distclean
clean:
	make -C autofs4 clean
	rm -f *~
	rm -fr ${distdir} ${distdir}.tar.gz ${distarchive} *.deb patch-stamp

distclean: clean
	make -C autofs4 distclean
	rm -f .\#*

.PHONY: dist
dist:
	@rm -rf ${distdir}
	mkdir -p ${distdir}
	@for file in $(DISTFILES); do \
	  cp  $$file $(distdir)/$$file; \
	done
	for subdir in $(DIST_SUBDIRS); do \
	  if test "$$subdir" = .; then :; else \
	    test -d $(distdir)/$$subdir \
	    || mkdir $(distdir)/$$subdir \
	    || exit 1; \
	  fi; \
	done
	make -C autofs4 distdir=../${distdir}/autofs4 dist
	make -C debian distdir=../${distdir}/debian dist
	# Update version in dist rpm spec file - don't crash if it fails
	-sed -i "s/\%define\s\+autofs4_version\s\+[^\}]\+\}/%define autofs4_version $(AUTOFS4_VERSION)\}/" $(distdir)/autofs4.spec
	tar cfz ${distarchive} ${distdir}

rpm: dist autofs4.spec
	rpmbuild -ta $(distarchive) --nodeps --define="autofs4_version $(AUTOFS4_VERSION)"

deb:
	@if [ -d debian ]; then \
		echo -e "autofs4 (${AUTOFS4_VERSION}) unstable; urgency=low\n\n  * see CHANGELOG for details\n\n -- autofs list <autofs@linux.kernel.org>  `date '+%a, %d %b %Y %H:%M:%S %z'`" > debian/changelog; \
		fakeroot make -f debian/rules binary; \
	else \
		 echo "Huh?"; \
	fi

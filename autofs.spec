#
# $Id: autofs.spec,v 1.19 2005/01/01 03:59:09 raven Exp $
#
Summary: A tool from automatically mounting and umounting filesystems.
Name: autofs
%define version 4.1.4
%define release beta1
Version: %{version}
Release: %{release}
License: GPL
Group: System Environment/Daemons
Source: ftp://ftp.kernel.org/pub/linux/daemons/autofs/v4/autofs-%{version}-%{release}.tar.gz
Buildroot: %{_tmppath}/%{name}-tmp
Prereq: chkconfig
Requires: /bin/bash mktemp sed textutils sh-utils grep /bin/ps
Summary(de): autofs daemon 
Summary(fr): d�mon autofs
Summary(tr): autofs sunucu s�reci
Summary(sv): autofs-daemon

%description
autofs is a daemon which automatically mounts filesystems when you use
them, and unmounts them later when you are not using them.  This can
include network filesystems, CD-ROMs, floppies, and so forth.

%description -l de
autofs ist ein D�mon, der Dateisysteme automatisch montiert, wenn sie 
benutzt werden, und sie sp�ter bei Nichtbenutzung wieder demontiert. 
Dies kann Netz-Dateisysteme, CD-ROMs, Disketten und �hnliches einschlie�en. 

%description -l fr
autofs est un d�mon qui monte automatiquement les syst�mes de fichiers
lorsqu'on les utilise et les d�monte lorsqu'on ne les utilise plus. Cela
inclus les syst�mes de fichiers r�seau, les CD-ROMs, les disquettes, etc.

%description -l tr
autofs, kullan�lan dosya sistemlerini gerek olunca kendili�inden ba�lar
ve kullan�mlar� sona erince yine kendili�inden ��zer. Bu i�lem, a� dosya
sistemleri, CD-ROM'lar ve disketler �zerinde yap�labilir.

%description -l sv
autofs �r en daemon som mountar filsystem n�r de anv�nda, och senare
unmountar dem n�r de har varit oanv�nda en best�md tid.  Detta kan
inkludera n�tfilsystem, CD-ROM, floppydiskar, och s� vidare.

%prep
%setup -q

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr
make initdir=/etc/rc.d/init.d

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p -m755 $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p -m755 $RPM_BUILD_ROOT%{_sbindir}
mkdir -p -m755 $RPM_BUILD_ROOT%{_libdir}/autofs
mkdir -p -m755 $RPM_BUILD_ROOT%{_mandir}/{man5,man8}

make install mandir=%{_mandir} initdir=/etc/rc.d/init.d INSTALLROOT=$RPM_BUILD_ROOT
install -m 755 -d $RPM_BUILD_ROOT/misc
install -m 755 -d $RPM_BUILD_ROOT/net

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post
chkconfig --add autofs

%postun
if [ $1 -ge 1 ] ; then
	/sbin/service autofs condrestart > /dev/null 2>&1 || :
fi

%preun
if [ "$1" = 0 ] ; then
	/sbin/service autofs stop > /dev/null 2>&1 || :
	chkconfig --del autofs
fi

%files
%defattr(-,root,root)
%doc CREDITS CHANGELOG COPY* README* TODO multiserver_mount.patch patches/* samples/ldap* samples/autofs.schema
%config /etc/rc.d/init.d/autofs
%config(noreplace) /etc/auto.master
%config(noreplace,missingok) /etc/auto.misc
%config(noreplace,missingok) /etc/auto.net
%{_sbindir}/automount
%dir %{_libdir}/autofs
%{_libdir}/autofs/*
%{_mandir}/*/*
%dir /misc
%dir /net

%changelog
* Sat Jan 1 2005 Ian Kent <raven@themaw.net>
- Update package to version 4.1.4-beta1.

* Sat Apr 3 2004 Ian Kent <raven@themaw.net>
- Update package to version 4.1.2.

* Tue Jan 19 2004 Ian Kent <raven@themaw.net>
- Update spec file to version 4.1.1.
- Remove BuildRequires on LDAP and Hesoid as make allows
  for them to be missing.

* Thu Dec 11 2003 Ian Kent <raven@themaw.net>
- Updated spec file to standardise paths etc.


#
# $Id: autofs.spec,v 1.6 2003/09/29 08:22:35 raven Exp $
#
Summary: autofs daemon
Name: autofs
%define version 4.1.0
%define revision 1
Version: %{version}
Release: 1
Copyright: GPL
Group: Networking/Daemons
Source: ftp://ftp.kernel.org/pub/linux/daemons/autofs/v4/autofs-%{version}-%{revision}.tar.gz
Buildroot: /var/tmp/autofs-tmp
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
mkdir -p -m755 $RPM_BUILD_ROOT/usr/sbin
mkdir -p -m755 $RPM_BUILD_ROOT/usr/lib/autofs
mkdir -p -m755 $RPM_BUILD_ROOT/usr/man/man5
mkdir -p -m755 $RPM_BUILD_ROOT/usr/man/man8

make install initdir=/etc/rc.d/init.d INSTALLROOT=$RPM_BUILD_ROOT
make install_samples initdir=/etc/rc.d/init.d INSTALLROOT=$RPM_BUILD_ROOT
install -m 755 -d $RPM_BUILD_ROOT/misc
install -m 755 -d $RPM_BUILD_ROOT/net

%clean
rm -rf $RPM_BUILD_ROOT

%post
chkconfig --add autofs

%files
%defattr(-,root,root)
%doc COPYRIGHT README* TODO multiserver_mount.patch patches/* samples/ldap*
%doc 
%config /etc/rc.d/init.d/autofs
%config(missingok) /etc/auto.master
%config(missingok) /etc/auto.misc
%config(missingok) /etc/auto.net
/usr/sbin/automount
%dir /misc
%dir /net
/usr/lib/autofs
/usr/man/*/*

%changelog
* Mon Sep 29 2003 Ian Kent <raven@themaw.net>
- Added work around for O(1) patch oddity.

* Sat Aug 17 2003 Ian Kent <raven@themaw.net>
- Fixed tree mounts.
- Corrected transciption error in autofs4-2.4.18 kernel module

* Sun Aug 10 2003 Ian Kent <raven@themaw.net>
- Checked and merged most of the RedHat v3 patches
- Fixed kernel module handling wu-ftpd login problem (again)

* Thu Aug 7 2003 Ian Kent <raven@themaw.net>
- Removed ineffective lock stuff
- Added -n to bind mount to prevent mtab update error
- Added retry to autofs umount to clean matb after fail
- Redirected messages from above to debug log and added info message
- Fixed autofs4 module reentrancy, pwd and chroot handling

* Wed Jul 30 2003 Ian Kent <raven@themaw.net>
- Fixed autofs4 ghosting patch for 2.4.19 and above (again)
- Fixed autofs directory removal on failure of autofs mount
- Fixed lock file wait function overlapping calls to (u)mount

* Sun Jul 27 2003 Ian Kent <raven@themaw.net>
- Implemented LDAP direct map handling for nisMap and automountMap schema
- Fixed autofs4 ghosting patch for 2.4.19 and above (again)
- Added locking to fix overlapping internal calls to (u)mount 
- Added wait for mtab~ to improve tolerance of overlapping external calls to (u)mount
- Fixed ghosted directory removal after failed mount attempt

* Wed May 28 2003 Ian Kent <raven@themaw.net>
- Cleaned up an restructured my added code
- Corrected ghosting problem with 2.4.19 and above
- Added autofs4 ghosting patch for 2.4.19 and above
- Implemented HUP signal to force update of ghosted maps

* Mon Mar 23 2002 Ian Kent <ian.kent@pobox.com>
- Add patch to implement directory ghosting and direct mounts
- Add patch to for autofs4 module to support ghosting


#
# $Id: autofs.spec,v 1.13 2004/01/11 12:00:51 raven Exp $
#
Summary: A tool from automatically mounting and umounting filesystems.
Name: autofs
%define version 4.1.0
%define release 1
Version: %{version}
Release: %{release}
License: GPL
Group: System Environment/Daemons
Source: ftp://ftp.kernel.org/pub/linux/daemons/autofs/v4/autofs-%{version}.tar.gz
Buildroot: %{_tmppath}/%{name}-tmp
BuildPrereq: hesiod-devel, openldap-devel
Prereq: chkconfig
Requires: /bin/bash mktemp sed textutils sh-utils grep /bin/ps
Summary(de): autofs daemon 
Summary(fr): démon autofs
Summary(tr): autofs sunucu süreci
Summary(sv): autofs-daemon

%description
autofs is a daemon which automatically mounts filesystems when you use
them, and unmounts them later when you are not using them.  This can
include network filesystems, CD-ROMs, floppies, and so forth.

%description -l de
autofs ist ein Dämon, der Dateisysteme automatisch montiert, wenn sie 
benutzt werden, und sie später bei Nichtbenutzung wieder demontiert. 
Dies kann Netz-Dateisysteme, CD-ROMs, Disketten und ähnliches einschließen. 

%description -l fr
autofs est un démon qui monte automatiquement les systèmes de fichiers
lorsqu'on les utilise et les démonte lorsqu'on ne les utilise plus. Cela
inclus les systèmes de fichiers réseau, les CD-ROMs, les disquettes, etc.

%description -l tr
autofs, kullanýlan dosya sistemlerini gerek olunca kendiliðinden baðlar
ve kullanýmlarý sona erince yine kendiliðinden çözer. Bu iþlem, að dosya
sistemleri, CD-ROM'lar ve disketler üzerinde yapýlabilir.

%description -l sv
autofs är en daemon som mountar filsystem när de använda, och senare
unmountar dem när de har varit oanvända en bestämd tid.  Detta kan
inkludera nätfilsystem, CD-ROM, floppydiskar, och så vidare.

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
%doc CREDITS COPY* README* TODO multiserver_mount.patch patches/* samples/ldap* samples/autofs.schema
%config /etc/rc.d/init.d/autofs
%config(noreplace) /etc/auto.master
%config(noreplace,missingok) /etc/auto.misc
%config(noreplace,missingok) /etc/auto.net
%{_sbindir}/automount
%dir %{_libdir}/autofs
%{_libdir}/autofs/autofs-ldap-auto-master
%{_libdir}/autofs/lookup_file.so
%{_libdir}/autofs/lookup_hesiod.so
%{_libdir}/autofs/lookup_ldap.so
%{_libdir}/autofs/lookup_multi.so
%{_libdir}/autofs/lookup_nisplus.so
%{_libdir}/autofs/lookup_program.so
%{_libdir}/autofs/lookup_userhome.so
%{_libdir}/autofs/lookup_yp.so
%{_libdir}/autofs/mount_afs.so
%{_libdir}/autofs/mount_autofs.so
%{_libdir}/autofs/mount_bind.so
%{_libdir}/autofs/mount_changer.so
%{_libdir}/autofs/mount_ext2.so
%{_libdir}/autofs/mount_generic.so
%{_libdir}/autofs/mount_nfs.so
%{_libdir}/autofs/parse_hesiod.so
%{_libdir}/autofs/parse_sun.so
%{_mandir}/*/*
%dir /misc
%dir /net

%changelog
* Thu Dec 11 2003 Ian Kent <raven@themaw.net>
- Updated spec file to standardise paths etc.


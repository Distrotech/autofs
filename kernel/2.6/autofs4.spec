# Our module name
%define _name autofs4
%{!?autofs4_version: %define autofs4_version 5.00}
%{!?autofs4_revision: %define autofs4_revision 1}

# Define kernel version if not already defined
%{!?kernel: %define kernel %(uname -r)}
%{!?ksrc: %define ksrc /lib/modules/%{kernel}/build}
%{!?_inst_dir: %define _inst_dir /lib/modules/%{kernel}/kernel/fs/autofs4}

Summary: autofs4 kernel module
Name: %{_name}-%{kernel}
Version: %{autofs4_version}
Release: %{autofs4_revision}
License: GPL
Group: System Environment/Base
Source: %{_name}-%{version}.tar.gz
Requires: /boot/vmlinuz-%{kernel}, modutils
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-%(%{__id_u} -n)
BuildRequires: %{ksrc}/Makefile

%description
Kernel module for autofs4 kernel module.

%prep
%setup -q -n %{_name}-%{autofs4_version}

%build
make all VERSION=%{kernel} KERNELDIR=%{ksrc}

%install
%define inst_dir $RPM_BUILD_ROOT%{_inst_dir}
rm -rf $RPM_BUILD_ROOT
install -o root -g root -m 755 -d %{inst_dir}
install -o root -g root -m 644 %{_name}/autofs4.ko %{inst_dir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(0755, root, root)
%doc README CHANGELOG
%{_inst_dir}/autofs4.ko

%post
if [ "`uname -r`" = "%{kernel}" ] ; then
  depmod -a >/dev/null 2>&1 || :
fi

%postun
if [ "`uname -r`" = "%{kernel}" ] ; then
  depmod -a >/dev/null 2>&1 || :
fi

%changelog
* Sat May  21 2005  <raven@themaw.net> - 
- Initial build.


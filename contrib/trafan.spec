%define bin_dir /usr/local/bin

Name:           trafan
Version:        1
Release:        0
Summary:        Trafan Network Monitoring System
Group:          System Environment/Base
License:        GPL
URL:            http://github.com/ellzey/trafan
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  git libevent-devel scons glib2-devel
Requires:       libevent glib2

%define tmp_dir /tmp/%{name}

%description
Trafan is a pcap based network flow analysis tool.

%prep

%build
rm -rf %{tmp_dir}
mkdir -p %{tmp_dir}
cd %{tmp_dir}
git clone http://github.com/ellzey/trafan.git
cd trafan
scons

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}%{bin_dir}
cp %{tmp_dir}/trafan/trafan %{buildroot}%{bin_dir}/trafan

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf %{tmp_dir}

%files
%attr(755,root,root) %{bin_dir}/trafan

%changelog
* Fri Jun 11 2010 Sean Leach <sleach@name.com> - 1.0
- First version


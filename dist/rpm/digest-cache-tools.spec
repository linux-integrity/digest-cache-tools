name:           digest-cache-tools
Version:        0.1.0
Release:        1
Summary:        Management tools for digest_cache LSM

Source0:        https://github.com/linux-integrity/%{name}/repository/archive/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
License:        GPL-2.0-only
Url:            https://github.com/linux-integrity/digest-cache-tools

BuildRequires:  autoconf automake libtool rpm-devel asciidoc

%if 0%{?suse_version}
BuildRequires: libopenssl-devel linux-glibc-devel ruby3.3-rubygem-ronn
%else
BuildRequires: openssl-devel kernel-headers rubygem-ronn
%endif

%description
This package includes the tools to configure the digest_cache LSM.

%prep
%autosetup -n %{name}-%{version} -p1

%build
autoreconf -iv
%configure
make %{?_smp_mflags}

%check
make check

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%post
ldconfig

%postun
ldconfig

%files
%defattr(-,root,root,-)
%{_bindir}/manage_digest_lists
%{_libdir}/libdigestcache.so
%exclude %{_libdir}/libdigestcache.a
%if 0%{?suse_version}
%exclude %{_libdir}/libdigestcache.la
%endif
%{_libdir}/rpm-plugins/digest_cache.so
%exclude %{_libdir}/rpm-plugins/digest_cache.a
%if 0%{?suse_version}
%exclude %{_libdir}/rpm-plugins/digest_cache.la
%endif
%{_prefix}/lib/rpm/macros.d/macros.digest_cache

%doc
%dir /usr/share/digest-cache-tools
%{_datarootdir}/digest-cache-tools/manage_digest_lists.txt
%{_datarootdir}/digest-cache-tools/README.md
%{_mandir}/man1/manage_digest_lists.1.gz
%{_mandir}/man1/digest-cache-tools.1.gz

%changelog
* Wed Feb 28 2024 Roberto Sassu <roberto.sassu@huawei.com> - 0.1.0-1
- Initial release

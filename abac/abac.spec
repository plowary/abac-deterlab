Summary:            ABAC, a scalable authorization system based on formal logic
Name:               abac
Version:            0.1.10
Release:            1%{?dist}
License:            GPLv2+
Group:              Network/Tied/ABAC              
Source:             %{name}-%{version}.tar.gz
URL:                http://abac.deterlab.net
BuildRoot:          %{_tmppath}/%{name}-root
BuildRequires:      python-devel, make, automake, autoconf
BuildRequires:      libtool, xmlsec1, swig
BuildRequires:      xmlsec1-devel xmlsec1-openssl-devel
BuildRequires:      xmlsec1-openssl libtool-ltdl-devel perl-ExtUtils-Embed
#Requires:           gradle

%description

%prep
%setup -q

%build
export CFLAGS="-DXMLSEC_NO_SIZE_T"
%configure --prefix=%{_prefix} --with-site-perl=/usr/lib64/perl5/site_perl

make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

%files
%defattr(-,root,root)
%config(noreplace) %{_bindir}/*
%{_libdir}/*
%{python_sitelib}/*
%{_includedir}/*
%{_datadir}/man/man1/*

%doc
%changelog



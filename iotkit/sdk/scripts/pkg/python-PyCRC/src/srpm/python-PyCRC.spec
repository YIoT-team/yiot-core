%global pkg_name PyCRC
%global _description \
Python libraries for CRC calculations (it supports CRC-16, CRC-32, CRC-CCITT, etc)

Summary:          Python libraries for CRC calculations (it supports CRC-16, CRC-32, CRC-CCITT, etc)
Name:             python-%{pkg_name}
Version:          1.21
Release:          1%{?dist}
License:          GPLv3
URL:              https://github.com/cristianav/PyCRC
Source0:          %{pkg_name}-%{version}.tar.gz

BuildRequires:    python3-devel
BuildRequires:    python3-setuptools

BuildArch:        noarch
%description      %{_description}

%package -n       python3-%{pkg_name}
Summary:          %{summary}
%description -n   python3-%{pkg_name}     %{_description}

%prep
%setup -q -n PyCRC-%{version}

%build
%py3_build

%install
%py3_install

%files -n python3-%{pkg_name}
%doc AUTHORS.rst     
%doc CONTRIBUTING.rst
%doc HISTORY.rst     
%doc LICENSE         
%doc MANIFEST.in     
%doc PKG-INFO        
%doc README.rst      
%{python3_sitelib}/PyCRC/
%{python3_sitelib}/PyCRC-%{version}-py3.*.egg-info

%changelog

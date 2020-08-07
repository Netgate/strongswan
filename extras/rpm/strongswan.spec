%{!?_topdir: %define _topdir %(pwd)}
%define	real_name	strongswan
Name: netgate-strongswan
Version: %{_version}
Release: %{_release}
Summary: An OpenSource IPsec-based VPN and TNC solution
Group: System Environment/Daemons
License: GPLv2+
URL: http://www.strongswan.org/
Source: %{real_name}-%{version}-%{release}.tar.gz

Obsoletes: %{real_name}
BuildRequires:  gmp-devel autoconf automake gperf
BuildRequires:  libcurl-devel
BuildRequires:  openldap-devel
BuildRequires:  openssl-devel
BuildRequires:  sqlite-devel
BuildRequires:  gettext-devel
BuildRequires:  trousers-devel
BuildRequires:  libxml2-devel
BuildRequires:  pam-devel
BuildRequires:  json-c-devel
BuildRequires:  libgcrypt-devel
BuildRequires:  systemd-devel
#BuildRequires:  NetworkManager-devel
#BuildRequires:  NetworkManager-glib-devel
Obsoletes:      %{real_name}-NetworkManager < 0:5.0.4-5
BuildRequires:  systemd, systemd-devel
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

# Sometimes developers want to build it without installing vpp but passing
# path using VPP_DIR and pointing it to VPP buildroot and/or LIBVPPMGMT_DIR for
# libvppmgmt. Use %{vpp_dir} and %{libvppmgmt_dir} macro for these cases
%if 0%{!?vpp_dir:1}
BuildRequires: vpp-devel
%else
%define vpp_includedir %{vpp_dir}/build-root/install-vpp-native/vpp/include
%define vpp_libdir %{vpp_dir}/build-root/install-vpp-native/vpp/lib
%define custom_vpp_cppflags -I%{vpp_includedir}
%define custom_vpp_ldflags -L%{vpp_libdir}
%endif
%if 0%{!?libvppmgmt_dir:1}
BuildRequires: libvppmgmt-devel
%else
%define libvppmgmt_includedir %{libvppmgmt_dir}%{_includedir}
%define libvppmgmt_libdir %{libvppmgmt_dir}%{_libdir}
%define custom_libvppmgmt_cppflags -I%{libvppmgmt_includedir}
%define custom_libvppmgmt_ldflags -L%{libvppmgmt_libdir}
%endif
%if 0%{!?libtnsrinfra_dir:1}
BuildRequires: libtnsrinfra-devel
%else
%define libtnsrinfra_includedir %{libtnsrinfra_dir}%{_includedir}
%define libtnsrinfra_libdir %{libtnsrinfra_dir}%{_libdir}
%define custom_libtnsrinfra_cppflags -I%{libtnsrinfra_includedir}
%define custom_libtnsrinfra_ldflags -L%{libtnsrinfra_libdir}
%endif


%description
The strongSwan IPsec implementation supports both the IKEv1 and IKEv2 key
exchange protocols in conjunction with the native NETKEY IPsec stack of the
Linux kernel.

%package kernel-vpp
Summary: Module for strongswan to install IKE SAs and policies into VPP
Group: System Environment/Daemons
Requires: %{name} = %{version}
Requires: libtnsrinfra libvppmgmt
Obsoletes: %{real_name}-kernel-vpp

%description kernel-vpp
This package provides a libcharon plugin that can propagate IKE SA data into
VPP. This can be used as an alternative to the other kernel plugins
{netlink, pfkey, libipsec}.

#%package libipsec
#Summary: Strongswan's libipsec backend
#Group: System Environment/Daemons
#%description libipsec
#The kernel-libipsec plugin provides an IPsec backend that works entirely
#in userland, using TUN devices and its own IPsec implementation libipsec.

#%package charon-nm
#Summary:        NetworkManager plugin for Strongswan
#Group:          System Environment/Daemons
#%description charon-nm
#NetworkManager plugin integrates a subset of Strongswan capabilities
#to NetworkManager.

%package tnc-imcvs
Summary: Trusted network connect (TNC)'s IMC/IMV functionality
Group: Applications/System
Requires: %{name} = %{version}
Obsoletes: %{real_name}-tnc-imcvs
%description tnc-imcvs
This package provides Trusted Network Connect's (TNC) architecture support.
It includes support for TNC client and server (IF-TNCCS), IMC and IMV message
exchange (IF-M), interface between IMC/IMV and TNC client/server (IF-IMC
and IF-IMV). It also includes PTS based IMC/IMV for TPM based remote
attestation, SWID IMC/IMV, and OS IMC/IMV. It's IMC/IMV dynamic libraries
modules can be used by any third party TNC Client/Server implementation
possessing a standard IF-IMC/IMV interface. In addition, it implements
PT-TLS to support TNC over TLS.

%prep
%setup -q -n %{package_dirname}

%build
# --with-ipsecdir moves internal commands to /usr/libexec/strongswan
# --bindir moves 'pki' command to /usr/libexec/strongswan
# See: http://wiki.strongswan.org/issues/552
%configure --disable-static \
    CPPFLAGS="%{?custom_vpp_cppflags: %{custom_vpp_cppflags}} %{?custom_libvppmgmt_cppflags: %{custom_libvppmgmt_cppflags}} %{?custom_libtnsrinfra_cppflags: %{custom_libtnsrinfra_cppflags}}" \
    LDFLAGS="%{?custom_vpp_ldflags: %{custom_vpp_ldflags}} %{?custom_libvppmgmt_ldflags: %{custom_libvppmgmt_ldflags}} %{?custom_libtnsrinfra_ldflags: %{custom_libtnsrinfra_ldflags}}" \
    --with-ipsec-script=%{real_name} \
    --sysconfdir=%{_sysconfdir}/%{real_name} \
    --with-ipsecdir=%{_libexecdir}/%{real_name} \
    --bindir=%{_libexecdir}/%{real_name} \
    --with-ipseclibdir=%{_libdir}/%{real_name} \
    --with-fips-mode=0 \
    --with-tss=trousers \
    --disable-nm \
    --enable-systemd \
    --enable-openssl \
    --disable-unity \
    --enable-ctr \
    --enable-ccm \
    --enable-gcm \
    --enable-md4 \
    --enable-gcrypt \
    --enable-xauth-eap \
    --enable-xauth-pam \
    --enable-xauth-noauth \
    --enable-eap-md5 \
    --enable-eap-gtc \
    --enable-eap-tls \
    --enable-eap-ttls \
    --enable-eap-peap \
    --enable-eap-mschapv2 \
    --disable-farp \
    --enable-dhcp \
    --enable-sqlite \
    --disable-tnc-ifmap \
    --disable-tnc-pdp \
    --enable-imc-test \
    --enable-imv-test \
    --enable-imc-scanner \
    --enable-imv-scanner  \
    --enable-imc-attestation \
    --enable-imv-attestation \
    --enable-imv-os \
    --enable-imc-os \
    --enable-imc-swid \
    --enable-imv-swid \
    --enable-eap-tnc \
    --enable-tnccs-20 \
    --enable-tnccs-11 \
    --enable-tnccs-dynamic \
    --enable-tnc-imc \
    --enable-tnc-imv \
    --enable-eap-radius \
    --enable-curl \
    --enable-eap-identity \
    --enable-cmd \
    --enable-acert \
    --enable-aikgen \
    --enable-vici \
    --enable-swanctl \
    --enable-kernel-vpp

make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}
# prefix man pages
for i in %{buildroot}%{_mandir}/*/*; do
    if echo "$i" | grep -vq '/%{real_name}[^\/]*$'; then
        mv "$i" "`echo "$i" | sed -re 's|/([^/]+)$|/%{real_name}_\1|'`"
    fi
done
# delete unwanted library files
rm %{buildroot}%{_libdir}/%{real_name}/*.so
find %{buildroot} -type f -name '*.la' -delete
# delete unwanted man pages
rm -rf %{buildroot}%{_mandir}
# fix config permissions
chmod 644 %{buildroot}%{_sysconfdir}/%{real_name}/%{real_name}.conf
# protect configuration from ordinary user's eyes
chmod 700 %{buildroot}%{_sysconfdir}/%{real_name}
# Create ipsec.d directory tree.
install -d -m 700 %{buildroot}%{_sysconfdir}/%{real_name}/ipsec.d
for i in aacerts acerts certs cacerts crls ocspcerts private reqs; do
    install -d -m 700 %{buildroot}%{_sysconfdir}/%{real_name}/ipsec.d/${i}
done

%post
/sbin/ldconfig
%systemd_post %{real_name}.service
%systemd_post %{real_name}-starter.service

%preun
%systemd_preun %{real_name}.service
%systemd_preun %{real_name}-starter.service

%postun
/sbin/ldconfig
%systemd_postun_with_restart %{real_name}.service
%systemd_postun_with_restart %{real_name}-starter.service

%files
%doc README COPYING NEWS TODO
%config(noreplace) %{_sysconfdir}/%{real_name}
%{_unitdir}/%{real_name}.service
%{_unitdir}/%{real_name}-starter.service
%{_sbindir}/charon-systemd
%dir %{_libdir}/%{real_name}
%{_libdir}/%{real_name}/libcharon.so.0
%{_libdir}/%{real_name}/libcharon.so.0.0.0
%{_libdir}/%{real_name}/libtls.so.0
%{_libdir}/%{real_name}/libtls.so.0.0.0
%{_libdir}/%{real_name}/libpttls.so.0
%{_libdir}/%{real_name}/libpttls.so.0.0.0
%{_libdir}/%{real_name}/lib%{real_name}.so.0
%{_libdir}/%{real_name}/lib%{real_name}.so.0.0.0
%{_libdir}/%{real_name}/libvici.so.0
%{_libdir}/%{real_name}/libvici.so.0.0.0
%{_libdir}/%{real_name}/libtpmtss.so.0
%{_libdir}/%{real_name}/libtpmtss.so.0.0.0
%dir %{_libdir}/%{real_name}/plugins
%{_libdir}/%{real_name}/plugins/lib%{real_name}-aes.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-ctr.so
#%{_libdir}/%{real_name}/plugins/lib%{real_name}-unity.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-ccm.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-gcm.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-gcrypt.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-attr.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-cmac.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-constraints.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-des.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-dnskey.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-fips-prf.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-gmp.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-hmac.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-kernel-netlink.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-md5.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-nonce.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-openssl.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-pem.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-pgp.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-pkcs1.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-pkcs8.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-pkcs12.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-rc2.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-sshkey.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-pubkey.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-random.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-resolve.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-revocation.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-sha1.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-sha2.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-socket-default.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-stroke.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-updown.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-x509.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-xauth-generic.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-xauth-eap.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-xauth-pam.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-xauth-noauth.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-xcbc.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-md4.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-md5.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-gtc.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-tls.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-ttls.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-peap.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-mschapv2.so
#%{_libdir}/%{real_name}/plugins/lib%{real_name}-farp.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-dhcp.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-curl.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-identity.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-acert.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-vici.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-curve25519.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-counters.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-mgf1.so
%dir %{_libexecdir}/%{real_name}
%{_libexecdir}/%{real_name}/_copyright
%{_libexecdir}/%{real_name}/_updown
%{_libexecdir}/%{real_name}/charon
%{_libexecdir}/%{real_name}/scepclient
%{_libexecdir}/%{real_name}/starter
%{_libexecdir}/%{real_name}/stroke
%{_libexecdir}/%{real_name}/_imv_policy
%{_libexecdir}/%{real_name}/imv_policy_manager
%{_libexecdir}/%{real_name}/pki
%{_libexecdir}/%{real_name}/aikgen
%{_libexecdir}/%{real_name}/xfrmi
%{_sbindir}/charon-cmd
%{_sbindir}/%{real_name}
%{_sbindir}/swanctl
%{_datadir}/%{real_name}/templates/config/
%{_datadir}/%{real_name}/templates/database/
%exclude %{_sysconfdir}/%{real_name}/strongswan.d/charon/kernel-vpp.conf

%files tnc-imcvs
%dir %{_libdir}/%{real_name}
%{_libdir}/%{real_name}/libimcv.so.0
%{_libdir}/%{real_name}/libimcv.so.0.0.0
%{_libdir}/%{real_name}/libtnccs.so.0
%{_libdir}/%{real_name}/libtnccs.so.0.0.0
%{_libdir}/%{real_name}/libradius.so.0
%{_libdir}/%{real_name}/libradius.so.0.0.0
%dir %{_libdir}/%{real_name}/imcvs
%{_libdir}/%{real_name}/imcvs/imc-attestation.so
%{_libdir}/%{real_name}/imcvs/imc-scanner.so
%{_libdir}/%{real_name}/imcvs/imc-test.so
%{_libdir}/%{real_name}/imcvs/imc-os.so
%{_libdir}/%{real_name}/imcvs/imv-scanner.so
%{_libdir}/%{real_name}/imcvs/imv-test.so
%{_libdir}/%{real_name}/imcvs/imv-os.so
%{_libdir}/%{real_name}/imcvs/imv-attestation.so
%dir %{_libdir}/%{real_name}/plugins
%{_libdir}/%{real_name}/plugins/lib%{real_name}-pkcs7.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-sqlite.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-tnc.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-tnc-imc.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-tnc-imv.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-tnc-tnccs.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-tnccs-20.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-tnccs-11.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-tnccs-dynamic.so
%{_libdir}/%{real_name}/plugins/lib%{real_name}-eap-radius.so
#%{_libdir}/%{real_name}/plugins/lib%{real_name}-tnc-ifmap.so
#%{_libdir}/%{real_name}/plugins/lib%{real_name}-tnc-pdp.so
%dir %{_libexecdir}/%{real_name}
%{_libexecdir}/%{real_name}/attest
%{_libexecdir}/%{real_name}/pt-tls-client

%files kernel-vpp
%config(noreplace) %{_sysconfdir}/%{real_name}/strongswan.d/charon/kernel-vpp.conf
%{_libdir}/%{real_name}/plugins/libstrongswan-kernel-vpp.so

#%files libipsec
#%{_libdir}/%{real_name}/libipsec.so.0
#%{_libdir}/%{real_name}/libipsec.so.0.0.0
#%{_libdir}/%{real_name}/plugins/libstrongswan-kernel-libipsec.so

#%files charon-nm
#%doc COPYING
#%{_libexecdir}/%{real_name}/charon-nm

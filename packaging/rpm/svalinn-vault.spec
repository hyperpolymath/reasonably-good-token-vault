# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath

Name:           svalinn-vault
Version:        0.1.0
Release:        1%{?dist}
Summary:        Post-quantum secure identity vault

License:        AGPL-3.0-or-later
URL:            https://github.com/hyperpolymath/reasonable-good-token-vault
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  ats2-devel >= 0.4.0
BuildRequires:  zig >= 0.11
BuildRequires:  openssl-devel >= 3.0
BuildRequires:  blake3-devel
Requires:       openssl >= 3.0
Requires:       blake3
Recommends:     selinux-policy
Recommends:     firewalld

%description
Svalinn Vault provides military-grade protection for digital identities
using post-quantum cryptography including Kyber-1024 and Dilithium5.

Features:
- Post-quantum key encapsulation (Kyber-1024)
- Post-quantum signatures (Dilithium5)
- Classical signatures (Ed448, Ed25519)
- AES-256-GCM authenticated encryption
- BLAKE3 hashing
- Argon2id key derivation (64 MiB memory)
- GUID-based storage with redaction
- chmod 000 lockdown when locked
- MFA with anti-AI CAPTCHA

WARNING: This is dual-use technology. Users are responsible for
compliance with applicable export control regulations.

%prep
%autosetup

%build
cd vault-core-ats
zig build -Doptimize=ReleaseSafe
%make_build

%install
install -Dm755 vault-core-ats/svalinn-vault-core %{buildroot}%{_bindir}/svalinn-cli
install -Dm644 vault-core-ats/zig-out/lib/libsvalinn_crypto.a %{buildroot}%{_libdir}/libsvalinn_crypto.a
install -Dm644 container/config/selinux/svalinn.te %{buildroot}%{_datadir}/selinux/packages/svalinn.te

%check
cd vault-core-ats
zig build test

%files
%license LICENSES/AGPL-3.0-or-later.txt
%doc README.adoc ROADMAP.adoc
%{_bindir}/svalinn-cli
%{_libdir}/libsvalinn_crypto.a
%{_datadir}/selinux/packages/svalinn.te

%changelog
* Thu Dec 25 2025 Hyperpolymath <security@hyperpolymath.example> - 0.1.0-1
- Initial release
- Post-quantum cryptography: Kyber-1024, Dilithium5
- GUID-based storage with redaction
- chmod 000 lockdown

# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath

Name:           rgt-vault
Version:        0.1.0
Release:        0.1.alpha%{?dist}
Summary:        RGT Vault - Reasonably Good Token Vault (post-quantum secure)

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
RGT Vault (Reasonably Good Token Vault) - a parody of Pretty Good Privacy.

Built on Svalinn container technology with corre-terro image, providing
military-grade protection for digital identities using post-quantum
cryptography including Kyber-1024 and Dilithium5.

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
install -Dm755 vault-core-ats/rgt-vault %{buildroot}%{_bindir}/rgt-vault
install -Dm644 vault-core-ats/zig-out/lib/librgt_crypto.a %{buildroot}%{_libdir}/librgt_crypto.a
install -Dm644 container/config/selinux/svalinn.te %{buildroot}%{_datadir}/selinux/packages/rgt-vault.te

%check
cd vault-core-ats
zig build test

%files
%license LICENSES/AGPL-3.0-or-later.txt
%doc README.adoc ROADMAP.adoc
%{_bindir}/rgt-vault
%{_libdir}/librgt_crypto.a
%{_datadir}/selinux/packages/rgt-vault.te

%changelog
* Thu Dec 26 2025 Hyperpolymath <security@hyperpolymath.example> - 0.1.0-0.1.alpha
- Initial alpha release
- Renamed from Svalinn Vault to RGT Vault (Reasonably Good Token Vault)
- Post-quantum cryptography: Kyber-1024, Dilithium5
- GUID-based storage with redaction
- chmod 000 lockdown
- Built on Svalinn container with corre-terro image

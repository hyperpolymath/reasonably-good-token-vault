# Security Policy

## MAXIMUM SECURITY POSTURE

This project maintains the highest possible security standards. All security
issues are treated with maximum priority.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

Only the latest version receives security updates.

## Security Measures

### Repository Protection

- **Signed commits required**: All commits must be GPG/SSH signed
- **Branch protection**: Main branch is protected with mandatory reviews
- **Force push disabled**: No force pushes allowed on any protected branch
- **Linear history**: Required to prevent merge commit confusion
- **Mirroring disabled**: No mirroring to prevent data exfiltration

### Code Security

- **CodeQL**: Automated code scanning on every commit
- **Dependency Review**: All dependencies scanned for vulnerabilities
- **Secret Scanning**: Automated detection of leaked secrets
- **Cargo Audit**: Rust-specific security audit
- **Trivy**: Container image vulnerability scanning
- **Echidna**: Formal verification of security properties

### Cryptographic Standards

- **Post-Quantum**: Kyber-1024 and Dilithium5
- **Classical**: AES-256-GCM, BLAKE3, SHAKE3-256, Ed448
- **Key Derivation**: Argon2id with 64 MiB memory
- **No Deprecated**: MD5, SHA1, DES, 3DES are NOT used

## Reporting a Vulnerability

### DO

1. **Email**: security@hyperpolymath.example (PGP key below)
2. **Include**: Detailed description, reproduction steps, impact assessment
3. **Wait**: Allow 90 days for fix before public disclosure
4. **Coordinate**: Work with us on timing of disclosure

### DO NOT

1. **Do not** open public GitHub issues for security vulnerabilities
2. **Do not** exploit vulnerabilities beyond proof-of-concept
3. **Do not** access or modify other users' data
4. **Do not** perform denial of service attacks

### PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP key would be here]
-----END PGP PUBLIC KEY BLOCK-----
```

## Response Timeline

| Severity | Response Time | Fix Time |
|----------|---------------|----------|
| Critical | 24 hours      | 7 days   |
| High     | 48 hours      | 14 days  |
| Medium   | 7 days        | 30 days  |
| Low      | 14 days       | 90 days  |

## Bug Bounty

Currently no formal bug bounty program. Researchers will be credited in
SECURITY-ACKNOWLEDGEMENTS.md.

## Security Acknowledgements

See [SECURITY-ACKNOWLEDGEMENTS.md](SECURITY-ACKNOWLEDGEMENTS.md) for
researchers who have responsibly disclosed vulnerabilities.

## Minimum Principle

This codebase follows the **minimum principle**: only the absolute minimum
functionality required for secure identity storage is implemented. Any feature
that could be misused for unintended purposes is explicitly not included.

### Explicitly NOT Supported

- Remote code execution
- Arbitrary file access outside vault
- Network services beyond the API
- Shell access or command execution
- Dynamic code loading
- Plugin systems
- External integrations beyond defined API

## Hash Verification

All releases are signed and include SHA-256 checksums:

```bash
# Verify release
sha256sum -c svalinn-vault-0.1.0.sha256
gpg --verify svalinn-vault-0.1.0.sig svalinn-vault-0.1.0.tar.gz
```

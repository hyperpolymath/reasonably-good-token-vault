# TEST-NEEDS.md — reasonably-good-token-vault

## CRG Grade: C — ACHIEVED 2026-04-04

## Current Test State

| Category | Count | Notes |
|----------|-------|-------|
| ATS2 unit tests | 2 | `vault-core-ats/tests/{test_crypto,test_identity}.dats` |
| Zig FFI tests | 1 | `vault-core-ats/zig/tests/crypto_test.zig` |
| Specification tests | Present | `validation/echidna-spec.sol` |
| RPM/Packaging specs | Present | Packaging test configurations |

## What's Covered

- [x] ATS2 crypto and identity verification
- [x] Zig FFI crypto layer tests
- [x] Echidna formal specification
- [x] Packaging validation

## Still Missing (for CRG B+)

- [ ] Property-based testing for vault operations
- [ ] Fuzzing for cryptographic edge cases
- [ ] Performance benchmarks
- [ ] Integration tests with container deployment

## Run Tests

```bash
cd /var/mnt/eclipse/repos/reasonably-good-token-vault && make test
```

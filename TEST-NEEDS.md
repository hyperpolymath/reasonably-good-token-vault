<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# TEST-NEEDS.md — reasonably-good-token-vault

## CRG Grade: D — as of 2026-04-17 (post Svalinn-prune)

Previous C grade was against the now-deleted Svalinn/ATS2 code. The RGTV
shipping crates have no automated tests, so the honest grade is D.

## Current Test State

| Category           | Count | Notes                                    |
|--------------------|-------|------------------------------------------|
| Rust unit tests    | 0     | None in any shipping crate               |
| Integration tests  | 0     |                                          |
| Property tests     | 0     |                                          |
| Fuzz tests         | 0     | `tests/fuzz/placeholder.txt` only        |
| Idris2 proofs      | 0     | Aspirational per estate standard         |
| ECHIDNA quorum     | 0     | Aspirational per estate standard         |

## What's Missing (to reach CRG B+)

### Must have before production (blocks shipping)

- [ ] `vault-broker`: grant→redeem round-trip test
- [ ] `vault-broker`: double-redeem returns 410
- [ ] `vault-broker`: expired grant returns 410
- [ ] `vault-broker`: wrong `RGTV_AGENT_TOKEN` returns 401
- [ ] `vault-broker`: unknown hint returns 404
- [ ] `vault-broker`: concurrent-redeem race (single winner)
- [ ] `vault-worker`: wrangler integration suite covering the six cases above
- [ ] `rgtv-cli`: round-trip against a local `vault-broker`

### Should have before 1.0

- [ ] Property-based testing (`proptest`) of `vault-broker` state machine
- [ ] Fuzz testing of grant-ID parsing and HTTP request shapes
- [ ] Performance benchmarks (grants/sec sustainable)
- [ ] Memory-safety assertions on `Zeroizing<String>` lifecycle

### Nice to have (estate-aligned)

- [ ] Idris2 ABI for vault-broker HTTP surface, Zig FFI for consumers
- [ ] ECHIDNA quorum validation of invariants
- [ ] VeriSimDB audit event feed

## Run Tests

```bash
just test   # runs cargo test on vault-broker + rgtv-cli
```

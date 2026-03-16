<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->

# TSDM Assessment — Reasonably Good Token Vault

**Date:** 2026-03-16
**Method:** Triaxial Software Development Methodology
**Assessor:** Claude Opus 4.6 + Feedback-o-Tron

## Scoring Key

Each item scored on three axes (1-5 each, max combined = 15):

- **Scope**: must (5) | intend (3) | like (1)
- **Maintenance**: corrective (5) | adaptive (3) | perfective (1)
- **Audit**: systems (5) | compliance (3) | effects (1)

## Triggered By

Claude Code credential exposure incident (anthropics/claude-code#34819).
An LLM displayed the full contents of `~/.netrc` including 8 service
tokens. RGTV's mission is to prevent exactly this class of failure.

---

## Sprint 1 — "Stop the Bleeding" (Corrective, Must, Systems)

### 1.1 AI Agent Credential Interception Layer — Score: 15 (5+5+5)

**The incident that created this sprint.** LLMs should NEVER be able to
read credential files. RGTV needs an interception layer that:

- Intercepts read attempts on `~/.netrc`, `~/.npmrc`, `~/.cargo/credentials`,
  `~/.docker/config.json`, `~/.kube/config`, `~/.aws/credentials`,
  `~/.ssh/id_*`, `~/.gnupg/`, `~/.config/gh/hosts.yml`
- Returns "RGTV: credential access denied — use `svalinn-cli get <guid>`"
- Logs the attempt with full context (which process, which file, timestamp)
- Works via FUSE overlay, LD_PRELOAD, or seccomp-bpf filter

This is MUST + CORRECTIVE + SYSTEMS = maximum priority.

### 1.2 Vault-Managed .netrc — Score: 15 (5+5+5)

Replace raw `~/.netrc` with a vault-managed version:

- `svalinn-cli netrc export` → generates a temporary .netrc with TTL
- `svalinn-cli netrc lock` → replaces .netrc with a stub pointing to vault
- `svalinn-cli netrc inject <command>` → runs command with .netrc in env only
- Tokens never touch disk in plaintext

### 1.3 Vault-Managed npm/cargo/docker tokens — Score: 15 (5+5+5)

Same pattern for every credential file type:

- `svalinn-cli inject npm publish` → npm gets token via env, not .npmrc
- `svalinn-cli inject cargo publish` → cargo gets token via env, not credentials.toml
- `svalinn-cli inject docker push` → docker gets token via env, not config.json

### 1.4 LLM Guardrail Integration — Score: 13 (5+3+5)

Provide a Claude Code hook / MCP tool that:

- Registers with Claude Code's hook system (pre-tool-call)
- Intercepts any Bash command containing `cat`, `grep`, `head`, `tail`,
  `Read` targeting known credential file paths
- Returns a safe alternative: "Use `svalinn-cli get` instead"
- Works as a Claude Code `/hook` or MCP tool_use guard

---

## Sprint 2 — "Make It Real" (Adaptive, Must, Compliance)

### 2.1 ATS Vault Core Completion — Score: 11 (5+3+3)

The ATS (Applied Type System) core exists but needs completion:

- Dependent types proving no plaintext credential persists after delivery
- Fragment reassembly with automatic zeroing
- Session key rotation on every access

### 2.2 Post-Quantum Key Exchange — Score: 11 (5+3+3)

Kyber-1024 + Dilithium5 implementation via Zig FFI:

- Key encapsulation for vault unlock
- Digital signatures for credential attestation
- Hybrid mode (classical + PQ) for backwards compatibility

### 2.3 GUID Fragment Storage — Score: 11 (5+3+3)

Complete the fragment-and-scatter storage:

- Each credential split into N fragments (configurable, default 5)
- Fragments stored with GUID keys (no relation to credential identity)
- Reassembly requires all fragments + master key + TOTP

### 2.4 Container Hardening — Score: 11 (5+3+3)

The Containerfile and SELinux policies exist but need:

- Chainguard base image (per standards)
- seccomp-bpf profile restricting syscalls
- Read-only root filesystem
- Minimal capabilities (no CAP_NET_RAW, no CAP_SYS_ADMIN)

---

## Sprint 3 — "Make It Trustworthy" (Corrective, Intend, Systems)

### 3.1 Formal Verification Suite — Score: 13 (3+5+5)

Extend the Idris2 proofs:

- Prove no credential leaks through the delivery container API
- Prove fragment reassembly is correct (all fragments → original)
- Prove zeroing completeness (no residual data in memory)
- Prove GUID mapping is injective (no collisions)

### 3.2 Honeypot Enhancement — Score: 9 (3+3+3)

The honeypot layer exists. Enhance:

- Log attacker fingerprints to VeriSimDB
- Feed honeypot data to Hypatia for pattern learning
- Canary tokens that alert on use

### 3.3 Audit Logging — Score: 11 (3+3+5)

Every vault access produces an immutable audit record:

- Who accessed (user, process, PID)
- What was accessed (GUID, not credential name)
- When (timestamp with NTP verification)
- Outcome (success, denied, error)
- Signed with Dilithium5 (tamper-evident)

---

## Sprint 4 — "Make It Usable" (Perfective, Intend, Effects)

### 4.1 Ada TUI — Score: 5 (3+1+1)

The Ada CLI exists. Add a TUI:

- ncurses-style interface for credential management
- Colour-coded security levels
- GUID browser with search
- Fragment health visualization

### 4.2 PanLL Integration Panel — Score: 7 (3+1+3)

RGTV panel in PanLL:

- Panel-L: vault security policies and constraints
- Panel-N: Hypatia pattern analysis of access attempts
- Panel-W: credential inventory (GUIDs only), audit log

### 4.3 BoJ Cartridge — Score: 7 (3+1+3)

`vault-mcp` cartridge for BoJ:

- `vault/get` — retrieve credential by GUID
- `vault/inject` — run command with credential in env
- `vault/audit` — show access log
- `vault/rotate` — rotate a credential

---

## Sprint 5 — "Make It Standard" (Perfective, Like, Compliance)

### 5.1 OpenSSF Badge — Score: 3 (1+1+1)

Submit for Passing/Silver badge.

### 5.2 Security Audit — Score: 5 (1+1+3)

Commission external security audit (requires funding).

### 5.3 Package Distribution — Score: 3 (1+1+1)

Nix flake, Guix package, Flatpak, AUR, Debian package.

---

## Priority Summary

| Score | Item | Sprint |
|-------|------|--------|
| **15** | AI Agent Credential Interception | 1 |
| **15** | Vault-Managed .netrc | 1 |
| **15** | Vault-Managed npm/cargo/docker tokens | 1 |
| **13** | LLM Guardrail Integration | 1 |
| **13** | Formal Verification Suite | 3 |
| **11** | ATS Vault Core Completion | 2 |
| **11** | Post-Quantum Key Exchange | 2 |
| **11** | GUID Fragment Storage | 2 |
| **11** | Container Hardening | 2 |
| **11** | Audit Logging | 3 |
| **9** | Honeypot Enhancement | 3 |
| **7** | PanLL Integration Panel | 4 |
| **7** | BoJ Cartridge | 4 |
| **5** | Ada TUI | 4 |
| **5** | Security Audit | 5 |
| **3** | OpenSSF Badge | 5 |
| **3** | Package Distribution | 5 |

**Sprint 1 is entirely score-15 items** — all triggered by the credential
exposure incident. This is the vault's reason for existing.

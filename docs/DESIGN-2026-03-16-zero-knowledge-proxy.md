<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
<!-- Design Document: Zero-Knowledge Credential Proxy -->
<!-- Date: 2026-03-16 -->
<!-- Author: Jonathan D.A. Jewell / Claude Opus 4.6 -->
<!-- Status: Proposed -->

# Zero-Knowledge Credential Proxy — LLM-Proof + CI-Proof Architecture

## Overview

Three interconnected systems that ensure credentials never exist in any
environment an attacker (human, LLM, or compromised CI runner) can access:

1. **MCP Proxy** — LLM agents request effects, never see credentials
2. **GitHub Secrets Replacement** — secrets become GUID pointers, resolved at runtime
3. **SPARK Vault Core** — formally proven credential isolation

## Part 1: MCP Zero-Knowledge Proxy (LLM Protection)

### Problem

LLM agents with shell access can read credential files (~/.netrc, ~/.npmrc,
~/.cargo/credentials) and display them in conversation. Even with guardrails,
the attack surface is too large — any `cat`, `grep`, `env`, `/proc` access
can leak credentials.

### Solution

The LLM never enters the same security domain as decrypted credentials.

```
LLM Sandbox (seccomp, no ptrace, no /proc, separate namespaces)
    │ "please run: git push origin main"
    ▼
RGTV Proxy (validates command against allowlist)
    │ requests human auth via OS secure input (opaque to LLM)
    ▼
RGTV Execution Namespace (separate PID, net, mount, user)
    │ assembles credential from fragments
    │ checksums target binary (fexecve)
    │ injects via kernel keyring (not env)
    │ executes command
    │ zeroes memory
    ▼
LLM receives: exit code + stdout (never the credential)
```

### MCP Tool: vault/execute

```json
{
  "name": "vault/execute",
  "description": "Execute a command with vault-managed credentials. You never see the credential — only the result.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "command": { "type": "string", "description": "Command to execute (e.g. 'git push origin main')" },
      "credential_hint": { "type": "string", "description": "Which service needs auth (e.g. 'github.com')" }
    }
  }
}
```

### Claude Code Hook: credential_guard

Pre-tool-call hook that intercepts any Bash command targeting credential files:

```json
{
  "hook": "pre_tool_call",
  "pattern": "cat|grep|head|tail|less|more|Read.*(\\.netrc|npmrc|credentials|config\\.json|hosts\\.yml|\\.env|id_rsa|id_ed25519)",
  "action": "block",
  "message": "RGTV: credential file access blocked. Use vault/execute instead."
}
```

### Security Defenses (Red Team Analysis)

| Tier | Attack | Defense |
|------|--------|---------|
| 1 | `env` / `printenv` | Credential never in LLM's env. Separate namespace. |
| 1 | `/proc/<pid>/environ` | Separate PID namespace. seccomp blocks ptrace. |
| 2 | Swap target binary | `fexecve()` on verified fd. Checksum before exec. |
| 2 | `LD_PRELOAD` injection | Cleared. `--no-new-privs`. |
| 2 | `.gitconfig` credential helper | Isolated `$HOME`. |
| 2 | `tcpdump` / network sniff | Separate network namespace. |
| 3 | Command injection in args | Allowlist parser, not `sh -c`. |
| 3 | DNS exfiltration | Target URL whitelist. |
| 3 | TOCTOU binary swap | `fexecve()` same fd — no gap. |
| 3 | Timing side-channel | Constant-time SPARK ops. Padded response time. |
| 4 | Social engineering human | OS-level secure input. Hardware security key. |

---

## Part 2: GitHub Secrets Replacement (CI Protection)

### Problem

GitHub Secrets are encrypted at rest but decrypted at runtime. They leak via:
- Workflow logs (accidental echo)
- PRs from forks (malicious workflow modification)
- Compromised GitHub Actions (supply chain)
- GitHub itself (breach or insider)

### Solution: GUID Pointers

Replace every GitHub Secret with a GUID pointer to RGTV:

```
# Old (dangerous — real token on GitHub's servers):
ANTHROPIC_API_KEY = "sk-ant-abc123..."

# New (safe — pointer to your vault, useless without your hardware):
ANTHROPIC_API_KEY = "rgtv://vault.hyperpolymath.dev/a7f2c3d4-e5b6-4a8c"
```

### Resolution Flow

```
GitHub Actions workflow starts
    │
    ▼
Step: uses hyperpolymath/rgtv-action@v1
    │ reads RGTV_VAULT_URL + RGTV_RUNNER_CERT (these CAN be public)
    │
    ▼
RGTV receives request:
    - Who: runner certificate (signed by user's CA)
    - What: GUID a7f2c3d4
    - Where: workflow file SHA matches trusted allowlist
    - When: within time window
    │
    ▼
Approval (one of):
    a) Push notification → user approves on phone (interactive)
    b) Pre-approved policy: "workflow SHA abc123 may access GUID a7f2c3d4" (automated)
    c) Time-window: "approved for next 30 minutes" (semi-automated)
    │
    ▼
RGTV assembles credential from fragments
    │ creates time-limited, single-use token derivative
    │ injects into runner step env (one step only, not whole job)
    │ TTL: 60 seconds (configurable)
    │
    ▼
Step executes with real credential (for ~30 seconds)
    │ RGTV monitors for completion
    │ credential auto-revoked after TTL or step completion
    │
    ▼
Workflow log shows: RGTV_VAULT_URL=vault.hyperpolymath.dev (public, safe)
                    ANTHROPIC_API_KEY=*** (never materialized in log)
```

### GitHub Action: hyperpolymath/rgtv-action

```yaml
- name: Authenticate with RGTV
  uses: hyperpolymath/rgtv-action@v1
  with:
    vault-url: ${{ secrets.RGTV_VAULT_URL }}  # This IS safe to "leak"
    credentials: |
      ANTHROPIC_API_KEY=a7f2c3d4-e5b6-4a8c-9d0e-f1a2b3c4d5e6
      NPM_TOKEN=b8c3d4e5-f6a7-5b9d-0e1f-a2b3c4d5e6f7
    policy: workflow-sha  # or: approval-required, time-window
```

### What Happens If Leaked?

| What leaks | Impact |
|------------|--------|
| `RGTV_VAULT_URL` | Zero. It's a hostname. Like leaking "google.com". |
| GUID pointer | Zero. It's an address with no key. Like a Bitcoin address. |
| Runner certificate | Low. Certificate is bound to specific workflow SHAs. Revocable. |
| The real token (during 30s window) | Mitigated. Single-use derivative. Auto-revokes. Audit logged. |

---

## Part 3: SPARK Vault Core (Formal Guarantees)

### Why SPARK

SPARK's information flow analysis formally proves:

1. **No credential flows from vault domain to LLM domain** — the type system
   enforces domain separation at compile time
2. **No credential persists after delivery** — SPARK's ownership model proves
   zeroing completeness
3. **No runtime errors in security-critical paths** — GNATprove verifies
   absence of buffer overflows, integer overflows, null derefs, division by zero
4. **Fragment reassembly is correct** — all N fragments → exact original

### Language Split

```
SPARK/Ada:  Vault core — fragment management, credential assembly,
            memory zeroing, security domain separation, crypto state machine
            (PROVEN: no information flow from vault to external domain)

Rust:       CLI (svalinn-cli), MCP tool, GitHub Action, networking,
            BoJ cartridge (vault-mcp), container integration

Zig:        FFI bridge between SPARK and Rust (C ABI compatibility)

Idris2:     ABI definitions — dependent type proofs for the crypto protocol
            (replaces the ATS2 proof layer, not the runtime)
```

### Migration from ATS2

| ATS2 File | Lines | Target | Rationale |
|-----------|-------|--------|-----------|
| crypto.dats/sats | ~400 | SPARK | Crypto state machine — SPARK proves absence of runtime errors |
| identity.sats | ~100 | SPARK | Identity domain — SPARK proves information flow isolation |
| lockdown.sats | ~100 | SPARK | Lock state machine — SPARK proves no deadlocks |
| storage.sats | ~200 | SPARK | Fragment storage — SPARK proves reassembly correctness |
| cli.dats/sats | ~150 | Rust | CLI is not security-critical — Rust is fine |
| tui.sats | ~100 | Ada (non-SPARK) | TUI already in Ada, just remove ATS dependency |

---

## Implementation Priority

1. **MCP vault/execute tool** — immediate (blocks LLM credential access NOW)
2. **Claude Code credential_guard hook** — immediate (prevents the incident class)
3. **SPARK vault core scaffold** — this week (foundation for everything)
4. **GitHub Action + GUID pointer system** — next (CI protection)
5. **Push notification approval flow** — after (interactive approval)
6. **Runner certificate CA** — after (automated CI approval)

---

*"Like PGP, but for tokens. And reasonably good."*

*The name is deliberately modest. The architecture is not.*

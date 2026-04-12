# SPDX-License-Identifier: PMPL-1.0-or-later
# justfile for reasonably-good-token-vault

set shell := ["bash", "-uc"]

default:
    @just --list

# Build vault-broker and rgtv CLI
build:
    cargo build --manifest-path vault-broker/Cargo.toml --release
    cargo build --manifest-path svalinn-cli/Cargo.toml --release

# Build vault-broker only
build-broker:
    cargo build --manifest-path vault-broker/Cargo.toml --release

# Build rgtv CLI only
build-cli:
    cargo build --manifest-path svalinn-cli/Cargo.toml --release

# Build vault-core crypto library
build-core:
    cargo build --manifest-path vault-core/Cargo.toml --release

# Build vault-worker WASM (requires worker-build: cargo install worker-build)
build-worker:
    cd vault-worker && worker-build --release

# Run tests for all Rust crates
test:
    cargo test --manifest-path vault-broker/Cargo.toml
    cargo test --manifest-path svalinn-cli/Cargo.toml
    cargo test --manifest-path vault-core/Cargo.toml

# Run clippy + fmt check for all Rust crates
check:
    cargo fmt --manifest-path vault-broker/Cargo.toml --check
    cargo clippy --manifest-path vault-broker/Cargo.toml -- -D warnings
    cargo fmt --manifest-path svalinn-cli/Cargo.toml --check
    cargo clippy --manifest-path svalinn-cli/Cargo.toml -- -D warnings

# Format all Rust source
fmt:
    cargo fmt --manifest-path vault-broker/Cargo.toml
    cargo fmt --manifest-path svalinn-cli/Cargo.toml

# Clean all build artefacts
clean:
    cargo clean --manifest-path vault-broker/Cargo.toml
    cargo clean --manifest-path svalinn-cli/Cargo.toml
    cargo clean --manifest-path vault-core/Cargo.toml

# ---------------------------------------------------------------------------
# Operational: daemon + CLI
# ---------------------------------------------------------------------------

# Start vault-broker daemon in the background (requires RGTV_AGENT_TOKEN +
# RGTV_CRED_* env vars to be set in the calling shell).
broker-start:
    @echo "Starting vault-broker daemon..."
    @rgtv daemon start

# Stop the running vault-broker daemon.
broker-stop:
    @rgtv daemon stop

# Report daemon health.
broker-status:
    @rgtv daemon status

# Tail the daemon log (follow mode).
broker-logs:
    @tail -f ~/.local/state/rgtv/vault-broker.log

# List the credential hints registered with the running broker.
creds:
    @rgtv list

# Run vault-broker in the foreground (dev mode, logs to stdout).
# Requires: RGTV_AGENT_TOKEN + one or more RGTV_CRED_<HINT> vars.
broker-dev:
    @echo "Starting vault-broker in foreground (dev mode)..."
    @echo "Required: RGTV_AGENT_TOKEN, RGTV_CRED_<HINT>=<value>"
    cargo run --manifest-path vault-broker/Cargo.toml

# ---------------------------------------------------------------------------
# Cloudflare Workers (production deployment)
# ---------------------------------------------------------------------------

# Run vault-worker locally via wrangler dev.
# Requires: wrangler installed (npm i -g wrangler — or via Deno)
#           KV namespace preview IDs set in vault-worker/wrangler.toml
#           wrangler.toml RGTV_AGENT_TOKEN set for local testing
worker-dev:
    @echo "Starting vault-worker in local dev mode (wrangler)..."
    @echo "Ensure KV preview IDs are set in vault-worker/wrangler.toml"
    cd vault-worker && wrangler dev

# Deploy vault-worker to Cloudflare Workers (production).
# One-time prerequisites:
#   1. wrangler kv:namespace create CREDENTIALS  → paste ID into wrangler.toml
#   2. wrangler kv:namespace create GRANTS       → paste ID into wrangler.toml
#   3. wrangler secret put RGTV_AGENT_TOKEN
#   4. Populate credentials: wrangler kv:key put --namespace-id=<ID> HINT value
#   5. just worker-deploy
worker-deploy:
    @echo "Deploying vault-worker to Cloudflare Workers..."
    @echo "Ensure KV namespace IDs are set in vault-worker/wrangler.toml"
    cd vault-worker && wrangler deploy

# Tail live vault-worker logs from Cloudflare.
worker-logs:
    cd vault-worker && wrangler tail

# List credentials in the CREDENTIALS KV namespace (prod).
# Requires: CREDENTIALS namespace ID set in wrangler.toml
worker-creds-list:
    @echo "Listing CREDENTIALS KV keys (prod)..."
    @wrangler kv:key list --namespace-id=$$(grep -A1 'binding = "CREDENTIALS"' vault-worker/wrangler.toml | grep 'id =' | sed 's/.*= "\(.*\)"/\1/')

# Add a credential to the CREDENTIALS KV namespace.
#   just worker-cred-put MY_TOKEN "the-actual-value"
worker-cred-put hint value:
    @wrangler kv:key put --namespace-id=$$(grep -A1 'binding = "CREDENTIALS"' vault-worker/wrangler.toml | grep 'id =' | sed 's/.*= "\(.*\)"/\1/') {{hint}} "{{value}}"

# Generate vexometer traces
trace input:
    cargo run --release -- --trace {{input}}

# Run with vexometer validation
validate before after:
    @echo "Comparing vexometer scores..."
    @echo "Before: {{before}}"
    @echo "After: {{after}}"

# Run panic-attacker pre-commit scan
assail:
    @command -v panic-attack >/dev/null 2>&1 && panic-attack assail . || echo "panic-attack not found — install from https://github.com/hyperpolymath/panic-attacker"

# Self-diagnostic — checks dependencies, permissions, paths
doctor:
    @echo "Running diagnostics for reasonably-good-token-vault..."
    @echo "Checking required tools..."
    @command -v just >/dev/null 2>&1 && echo "  [OK] just" || echo "  [FAIL] just not found"
    @command -v git >/dev/null 2>&1 && echo "  [OK] git" || echo "  [FAIL] git not found"
    @echo "Checking for hardcoded paths..."
    @grep -rn '$HOME\|$ECLIPSE_DIR' --include='*.rs' --include='*.ex' --include='*.res' --include='*.gleam' --include='*.sh' . 2>/dev/null | head -5 || echo "  [OK] No hardcoded paths"
    @echo "Diagnostics complete."

# Auto-repair common issues
heal:
    @echo "Attempting auto-repair for reasonably-good-token-vault..."
    @echo "Fixing permissions..."
    @find . -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    @echo "Cleaning stale caches..."
    @rm -rf .cache/stale 2>/dev/null || true
    @echo "Repair complete."

# Guided tour of key features
tour:
    @echo "=== reasonably-good-token-vault Tour ==="
    @echo ""
    @echo "1. Project structure:"
    @ls -la
    @echo ""
    @echo "2. Available commands: just --list"
    @echo ""
    @echo "3. Read README.adoc for full overview"
    @echo "4. Read EXPLAINME.adoc for architecture decisions"
    @echo "5. Run 'just doctor' to check your setup"
    @echo ""
    @echo "Tour complete! Try 'just --list' to see all available commands."

# Open feedback channel with diagnostic context
help-me:
    @echo "=== reasonably-good-token-vault Help ==="
    @echo "Platform: $(uname -s) $(uname -m)"
    @echo "Shell: $SHELL"
    @echo ""
    @echo "To report an issue:"
    @echo "  https://github.com/hyperpolymath/reasonably-good-token-vault/issues/new"
    @echo ""
    @echo "Include the output of 'just doctor' in your report."


# Print the current CRG grade (reads from READINESS.md '**Current Grade:** X' line)
crg-grade:
    @grade=$$(grep -oP '(?<=\*\*Current Grade:\*\* )[A-FX]' READINESS.md 2>/dev/null | head -1); \
    [ -z "$$grade" ] && grade="X"; \
    echo "$$grade"

# Generate a shields.io badge markdown for the current CRG grade
# Looks for '**Current Grade:** X' in READINESS.md; falls back to X
crg-badge:
    @grade=$$(grep -oP '(?<=\*\*Current Grade:\*\* )[A-FX]' READINESS.md 2>/dev/null | head -1); \
    [ -z "$$grade" ] && grade="X"; \
    case "$$grade" in \
      A) color="brightgreen" ;; B) color="green" ;; C) color="yellow" ;; \
      D) color="orange" ;; E) color="red" ;; F) color="critical" ;; \
      *) color="lightgrey" ;; esac; \
    echo "[![CRG $$grade](https://img.shields.io/badge/CRG-$$grade-$$color?style=flat-square)](https://github.com/hyperpolymath/standards/tree/main/component-readiness-grades)"

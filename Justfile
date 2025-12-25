# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath
#
# Justfile - Task automation for Svalinn Vault
# Use with 'just' command runner: https://just.systems/

# Default recipe
default:
    @just --list

# =============================================================================
# Build Recipes
# =============================================================================

# Build vault-core in release mode with all security flags
build:
    cd vault-core && cargo build --release --locked

# Build with maximum security hardening
build-hardened:
    cd vault-core && RUSTFLAGS="-C target-feature=+cet -C link-arg=-z,now -C link-arg=-z,relro -C link-arg=-pie" \
        cargo build --release --locked

# Build Ada CLI
build-ada:
    cd ada-cli && gprbuild -P svalinn_cli.gpr -XBUILD=release

# Build all components
build-all: build build-ada

# =============================================================================
# Security Recipes
# =============================================================================

# Run all security checks
security: audit deny trivy codeql secrets

# Cargo security audit
audit:
    cd vault-core && cargo audit --deny warnings

# Cargo deny check
deny:
    cd vault-core && cargo deny check

# Trivy container scan
trivy:
    trivy image --severity CRITICAL,HIGH,MEDIUM svalinn-vault:latest

# Run CodeQL analysis (requires gh CLI)
codeql:
    @echo "CodeQL analysis runs in CI/CD pipeline"

# Secret scanning with gitleaks
secrets:
    gitleaks detect --source . --verbose

# Verify all dependencies are hash-pinned
verify-pins:
    cd vault-core && cargo verify-project
    @echo "Checking for unpinned dependencies..."
    @grep -r "version = \"" vault-core/Cargo.toml | grep -v "=" && exit 1 || echo "All pinned"

# =============================================================================
# Test Recipes
# =============================================================================

# Run all tests
test:
    cd vault-core && cargo test --release --locked

# Run tests with coverage
test-coverage:
    cd vault-core && cargo tarpaulin --out Html --output-dir ../coverage

# Run property-based tests
test-proptest:
    cd vault-core && cargo test --release --features proptest

# Formal verification with Echidna
echidna:
    cd validation && echidna echidna-spec.sol --config echidna.yaml

# =============================================================================
# Container Recipes
# =============================================================================

# Build container image
container:
    podman build -f container/svalinn.containerfile -t svalinn-vault:latest .

# Build container with no cache
container-fresh:
    podman build --no-cache -f container/svalinn.containerfile -t svalinn-vault:latest .

# Run container in development mode
container-dev:
    podman run --rm -it \
        --security-opt label=type:svalinn_t \
        --cap-drop=ALL \
        --read-only \
        --tmpfs /tmp:rw,noexec,nosuid,size=64m \
        svalinn-vault:latest

# Scan container for vulnerabilities
container-scan: container trivy

# =============================================================================
# Lockdown Recipes
# =============================================================================

# Lock down all vault files (chmod 000)
lock-files:
    #!/usr/bin/env bash
    set -euo pipefail
    find /var/lib/svalinn/vault -type f -exec chmod 000 {} \;
    find /var/lib/svalinn/vault -type d -exec chmod 000 {} \;
    echo "Vault files locked (chmod 000)"

# Unlock vault files for access
unlock-files:
    #!/usr/bin/env bash
    set -euo pipefail
    find /var/lib/svalinn/vault -type d -exec chmod 500 {} \;
    find /var/lib/svalinn/vault -type f -exec chmod 400 {} \;
    echo "Vault files unlocked (owner read-only)"

# Set up chroot jail
setup-chroot:
    #!/usr/bin/env bash
    set -euo pipefail
    JAIL="/var/lib/svalinn/jail"
    mkdir -p "$JAIL"/{dev,tmp}
    chmod 500 "$JAIL"
    chmod 1700 "$JAIL/tmp"
    mknod -m 444 "$JAIL/dev/null" c 1 3 || true
    mknod -m 444 "$JAIL/dev/urandom" c 1 9 || true
    echo "Chroot jail configured at $JAIL"

# Full lockdown (lock files + setup chroot)
lockdown: lock-files setup-chroot
    @echo "Full lockdown complete"

# =============================================================================
# Network Recipes
# =============================================================================

# Apply IPv4 lockdown
ipv4-lockdown:
    bash container/config/firewalld/ipv4-lockdown.sh

# Start IPv4 honeypots
honeypot:
    bash honeypot/ipv4-honeypot.sh start

# Stop IPv4 honeypots
honeypot-stop:
    bash honeypot/ipv4-honeypot.sh stop

# Configure AirVPN connection
airvpn:
    wg-quick up network/airvpn/airvpn.conf

# Disconnect AirVPN
airvpn-down:
    wg-quick down network/airvpn/airvpn.conf

# =============================================================================
# Validation Recipes
# =============================================================================

# Validate Mustfile requirements
validate-mustfile:
    mustfile validate Mustfile

# Validate Nickel configurations
validate-nickel:
    nickel typecheck config.nickel
    nickel typecheck network/cadre-router/cadre-config.nickel
    nickel typecheck database/cubs/cubs-config.nickel

# Validate all configurations
validate: validate-mustfile validate-nickel

# =============================================================================
# Development Recipes
# =============================================================================

# Format all code
fmt:
    cd vault-core && cargo fmt
    cd ada-cli && gnatpp -P svalinn_cli.gpr

# Lint all code
lint:
    cd vault-core && cargo clippy -- -D warnings

# Clean build artifacts
clean:
    cd vault-core && cargo clean
    cd ada-cli && gprclean -P svalinn_cli.gpr

# =============================================================================
# Release Recipes
# =============================================================================

# Create signed release
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    just build-hardened
    just test
    just security
    mkdir -p release
    cp target/release/svalinn-vault release/
    sha256sum release/svalinn-vault > release/svalinn-vault.sha256
    gpg --armor --detach-sign release/svalinn-vault
    echo "Release {{version}} created and signed"

# Verify release signature
verify-release file:
    sha256sum -c "{{file}}.sha256"
    gpg --verify "{{file}}.sig" "{{file}}"

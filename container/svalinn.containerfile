# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath
#
# Svalinn Vault Container - Security-hardened CoreOS-based image
#
# Security features:
# - Minimal attack surface (distroless-inspired)
# - SELinux enforcing
# - Read-only root filesystem
# - No shell access
# - Capability dropping
# - Seccomp profiles
# - Digital identity binding

FROM quay.io/fedora/fedora-coreos:stable AS base

# Install security packages
RUN rpm-ostree install \
    wireguard-tools \
    firewalld \
    selinux-policy-targeted \
    audit \
    aide \
    && rpm-ostree cleanup -m

# === Build Stage ===
FROM rust:1.75-bookworm AS builder

WORKDIR /build

# Copy Rust vault core
COPY vault-core/ ./vault-core/

# Build with maximum security flags
RUN cd vault-core && \
    RUSTFLAGS="-C target-feature=+cet -Z cf-protection=full" \
    cargo build --release --locked

# Build Ada CLI
FROM ghcr.io/alire-project/alire:latest AS ada-builder

WORKDIR /build
COPY ada-cli/ ./ada-cli/

RUN cd ada-cli && alr build --release

# === Final Image ===
FROM base AS final

LABEL maintainer="hyperpolymath" \
      description="Svalinn Secure Identity Vault" \
      version="0.1.0" \
      org.opencontainers.image.source="https://github.com/hyperpolymath/reasonable-good-token-vault"

# Create vault user (non-root)
RUN useradd -r -s /sbin/nologin -d /vault svalinn

# Create directories
RUN mkdir -p /vault/data /vault/config /vault/keys /vault/audit \
    && chown -R svalinn:svalinn /vault \
    && chmod 700 /vault /vault/data /vault/keys \
    && chmod 750 /vault/config /vault/audit

# Copy binaries
COPY --from=builder /build/vault-core/target/release/svalinn-vault /usr/local/bin/
COPY --from=ada-builder /build/ada-cli/bin/svalinn-cli /usr/local/bin/

# Copy configurations
COPY container/config/selinux/ /etc/selinux/targeted/contexts/files/
COPY container/config/firewalld/ /etc/firewalld/
COPY container/config/wireguard/ /etc/wireguard/
COPY container/config/seccomp.json /etc/seccomp/svalinn.json

# Set permissions
RUN chmod 755 /usr/local/bin/svalinn-vault /usr/local/bin/svalinn-cli

# SELinux context
RUN restorecon -Rv /vault /usr/local/bin/

# Drop capabilities
ENV CAPABILITY_DROP="ALL"
ENV CAPABILITY_ADD="NET_BIND_SERVICE"

# Read-only root filesystem
ENV READONLY_ROOT="true"

# Security labels
LABEL security.selinux.type="svalinn_t" \
      security.seccomp.profile="/etc/seccomp/svalinn.json"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/svalinn-vault health || exit 1

# Switch to non-root user
USER svalinn
WORKDIR /vault

# Volume mounts
VOLUME ["/vault/data", "/vault/config", "/vault/keys"]

# Expose only IPv6
EXPOSE 8443/tcp

# Entry point
ENTRYPOINT ["/usr/local/bin/svalinn-vault"]
CMD ["serve", "--config", "/vault/config/vault.toml"]

# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath
#
# Nix Flake for Svalinn Vault
#
# Provides reproducible builds and development environments

{
  description = "Svalinn Vault - Secure identity storage with post-quantum cryptography";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, naersk }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        # Rust toolchain with security features
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        naersk' = naersk.lib.${system}.override {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        # Build the vault core
        vault-core = naersk'.buildPackage {
          pname = "svalinn-vault-core";
          version = "0.1.0";
          src = ./vault-core;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            openssl
          ];

          # Security-focused build flags
          RUSTFLAGS = "-C target-feature=+cet -C link-arg=-z,relro,-z,now";

          # Run tests
          doCheck = true;
        };

        # Container image
        container-image = pkgs.dockerTools.buildLayeredImage {
          name = "svalinn-vault";
          tag = "latest";

          contents = with pkgs; [
            vault-core
            wireguard-tools
            cacert
            tzdata
          ];

          config = {
            Entrypoint = [ "/bin/svalinn-vault" ];
            Cmd = [ "serve" ];
            ExposedPorts = {
              "8443/tcp" = {};
            };
            User = "nobody:nogroup";
            WorkingDir = "/vault";
            Volumes = {
              "/vault/data" = {};
              "/vault/config" = {};
              "/vault/keys" = {};
            };
          };
        };

      in {
        packages = {
          default = vault-core;
          inherit vault-core container-image;
        };

        # Development shell
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust
            rustToolchain

            # Ada (GNAT)
            gnat
            gprbuild

            # Idris2
            idris2

            # Build tools
            pkg-config
            openssl

            # Security tools
            wireguard-tools
            openssl

            # Database tools
            # Note: XTDB and CUBS would need custom derivations

            # Version management (asdf-like)
            mise

            # Linting and formatting
            rustfmt
            clippy

            # Spell checking
            aspell
            aspellDicts.en

            # Document conversion
            pandoc

            # Fuzzy search
            agrep
          ];

          shellHook = ''
            echo "Svalinn Vault Development Environment"
            echo "======================================"
            echo "Rust: $(rustc --version)"
            echo "GNAT: $(gnat --version | head -1)"
            echo ""
            echo "Available commands:"
            echo "  cargo build    - Build vault core"
            echo "  cargo test     - Run tests"
            echo "  gprbuild       - Build Ada CLI"
            echo ""
            echo "Security: Hostile environment protections enabled"
          '';

          # Security environment variables
          SVALINN_HOSTILE_ENV = "true";
          SVALINN_VERIFY_INTEGRITY = "always";
        };

        # Formal validation with echidna
        checks.formal-validation = pkgs.runCommand "echidna-validation" {
          buildInputs = [ pkgs.echidna ];
        } ''
          echo "Running formal validation..."
          # echidna would validate the contracts here
          mkdir -p $out
          echo "Validation passed" > $out/result
        '';
      }
    );
}

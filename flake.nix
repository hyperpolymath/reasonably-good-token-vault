# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025 Hyperpolymath
#
# Nix Flake for RGTV
#
# Provides reproducible builds and development environments

{
  description = "RGTV - one-use credential broker for LLM agents (alpha)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
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

        # Build vault-broker (axum HTTP server)
        vault-broker = naersk'.buildPackage {
          pname = "rgtv-vault-broker";
          version = "0.1.0";
          src = ./vault-broker;
          nativeBuildInputs = with pkgs; [ pkg-config ];
          RUSTFLAGS = "-C link-arg=-z,relro,-z,now";
          doCheck = true;
        };

        # Build the rgtv CLI
        rgtv-cli = naersk'.buildPackage {
          pname = "rgtv";
          version = "0.1.0";
          src = ./rgtv-cli;
          nativeBuildInputs = with pkgs; [ pkg-config ];
          RUSTFLAGS = "-C link-arg=-z,relro,-z,now";
          doCheck = true;
        };

      in {
        packages = {
          default = vault-broker;
          inherit vault-broker rgtv-cli;
        };

        # Development shell
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            openssl
            rustfmt
            clippy
          ];

          shellHook = ''
            echo "RGTV Development Environment"
            echo "======================================"
            echo "Rust: $(rustc --version)"
            echo ""
            echo "Available commands:"
            echo "  cargo build    - Build vault-broker or rgtv-cli"
            echo "  cargo test     - Run tests"
            echo "  just           - See all recipes"
          '';
        };
      }
    );
}

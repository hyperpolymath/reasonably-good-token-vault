;;; SPDX-License-Identifier: MPL-2.0
;;; SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
;;;
;;; Guix package definition for RGTV (Reasonably Good Token Vault).
;;;
;;; Build with: guix build -f guix.scm
;;;
;;; Replaces the prior svalinn-vault-core package (pointing at the now-deleted
;;; vault-core/ crate). This is a minimal stub; detailed dependency pinning
;;; against Guix's Rust package set will be added when RGTV reaches beta.

(use-modules (guix packages)
             (guix git-download)
             (guix build-system cargo)
             (guix gexp)
             ((guix licenses) #:prefix license:)
             (gnu packages rust)
             (gnu packages rust-apps))

(define-public rgtv-vault-broker
  (package
    (name "rgtv-vault-broker")
    (version "0.1.0")
    (source
     (local-file "vault-broker"
                 #:recursive? #t))
    (build-system cargo-build-system)
    (arguments `(#:tests? #f))
    (home-page "https://github.com/hyperpolymath/reasonably-good-token-vault")
    (synopsis "Credential broker for LLM agents (axum HTTP server)")
    (description
     "RGTV vault-broker issues one-use opaque grants in place of raw
credentials, so that LLM agents never see the live token values.")
    (license license:mpl2.0)))

(define-public rgtv-cli
  (package
    (name "rgtv")
    (version "0.1.0")
    (source
     (local-file "rgtv-cli"
                 #:recursive? #t))
    (build-system cargo-build-system)
    (arguments `(#:tests? #f))
    (home-page "https://github.com/hyperpolymath/reasonably-good-token-vault")
    (synopsis "Command-line client for the RGTV broker")
    (description
     "rgtv is the CLI companion to vault-broker — creates and redeems grants,
with Zeroizing on received credential values.")
    (license license:mpl2.0)))

rgtv-vault-broker

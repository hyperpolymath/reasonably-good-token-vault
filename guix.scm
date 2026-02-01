;;; SPDX-License-Identifier: MPL-2.0-or-later
;;; SPDX-FileCopyrightText: 2025 Hyperpolymath
;;;
;;; Guix package definition for Svalinn Vault
;;;
;;; Build with: guix build -f guix.scm

(use-modules (guix packages)
             (guix download)
             (guix git-download)
             (guix build-system cargo)
             (guix build-system gnu)
             (guix gexp)
             ((guix licenses) #:prefix license:)
             (gnu packages base)
             (gnu packages rust)
             (gnu packages rust-apps)
             (gnu packages crates-io)
             (gnu packages crypto)
             (gnu packages tls)
             (gnu packages databases)
             (gnu packages version-control)
             (gnu packages compression))

(define-public svalinn-vault-core
  (package
    (name "svalinn-vault-core")
    (version "0.1.0")
    (source
     (local-file "vault-core"
                 #:recursive? #t))
    (build-system cargo-build-system)
    (arguments
     `(#:cargo-inputs
       (("rust-argon2" ,rust-argon2)
        ("rust-blake3" ,rust-blake3)
        ("rust-aes-gcm" ,rust-aes-gcm)
        ("rust-sha3" ,rust-sha3)
        ("rust-rand" ,rust-rand)
        ("rust-rand-chacha" ,rust-rand-chacha)
        ("rust-serde" ,rust-serde)
        ("rust-serde-json" ,rust-serde-json)
        ("rust-chrono" ,rust-chrono)
        ("rust-uuid" ,rust-uuid)
        ("rust-zeroize" ,rust-zeroize)
        ("rust-thiserror" ,rust-thiserror)
        ("rust-base64" ,rust-base64)
        ("rust-hex" ,rust-hex)
        ("rust-num-bigint" ,rust-num-bigint)
        ("rust-num-traits" ,rust-num-traits))
       #:phases
       (modify-phases %standard-phases
         (add-after 'unpack 'set-security-flags
           (lambda _
             (setenv "RUSTFLAGS"
                     "-C target-feature=+cet -C link-arg=-z,relro,-z,now")
             #t)))))
    (home-page "https://github.com/hyperpolymath/reasonable-good-token-vault")
    (synopsis "Secure identity vault with post-quantum cryptography")
    (description
     "Svalinn Vault Core provides secure storage for SSH keys, PGP keys,
personal access tokens, and API credentials using post-quantum cryptography
including Kyber-1024 and Dilithium signatures.")
    (license license:agpl3+)))

(define-public svalinn-cli
  (package
    (name "svalinn-cli")
    (version "0.1.0")
    (source
     (local-file "ada-cli"
                 #:recursive? #t))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (replace 'configure
           (lambda _
             ;; No configure script
             #t))
         (replace 'build
           (lambda _
             (invoke "gprbuild" "-P" "svalinn_cli.gpr"
                     "-XBUILD_MODE=release")))
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let ((bin (string-append (assoc-ref outputs "out") "/bin")))
               (mkdir-p bin)
               (install-file "bin/svalinn_main" bin)
               (rename-file (string-append bin "/svalinn_main")
                           (string-append bin "/svalinn-cli"))
               #t))))))
    (native-inputs
     (list gnat gprbuild))
    (inputs
     (list svalinn-vault-core))
    (home-page "https://github.com/hyperpolymath/reasonable-good-token-vault")
    (synopsis "CLI and TUI for Svalinn identity vault")
    (description
     "Command-line and text user interface for managing the Svalinn
secure identity vault, written in Ada for safety.")
    (license license:agpl3+)))

(define-public svalinn-container
  (package
    (name "svalinn-container")
    (version "0.1.0")
    (source
     (local-file "container"
                 #:recursive? #t))
    (build-system gnu-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (delete 'configure)
         (delete 'build)
         (replace 'install
           (lambda* (#:key outputs #:allow-other-keys)
             (let* ((out (assoc-ref outputs "out"))
                    (share (string-append out "/share/svalinn")))
               (mkdir-p share)
               (copy-recursively "." share)
               #t))))))
    (home-page "https://github.com/hyperpolymath/reasonable-good-token-vault")
    (synopsis "Container configuration for Svalinn vault")
    (description
     "Container files, SELinux policies, and security configurations
for deploying Svalinn vault in a hardened container environment.")
    (license license:agpl3+)))

;; Development environment
(define-public svalinn-dev-environment
  (package
    (name "svalinn-dev-environment")
    (version "0.1.0")
    (source #f)
    (build-system gnu-build-system)
    (arguments '(#:builder (mkdir %output)))
    (propagated-inputs
     (list rust
           rust-analyzer
           gnat
           gprbuild
           wireguard-tools
           openssl
           git))
    (home-page "https://github.com/hyperpolymath/reasonable-good-token-vault")
    (synopsis "Development environment for Svalinn")
    (description "Complete development environment for Svalinn vault.")
    (license license:agpl3+)))

;; Return the main package for guix build -f
svalinn-vault-core

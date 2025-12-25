;; SPDX-License-Identifier: AGPL-3.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell
;;
;; Svalinn Vault - ddraig-ssg site configuration
;; Maximum SEO and security hardening

(define-module (svalinn-site)
  #:use-module (ddraig core)
  #:use-module (ddraig html)
  #:use-module (ddraig seo)
  #:use-module (ddraig security))

;; Site metadata
(define site-config
  '((name . "Svalinn Vault")
    (tagline . "Post-Quantum Secure Identity Storage")
    (url . "https://svalinn.hyperpolymath.dev")
    (author . "Jonathan D.A. Jewell")
    (language . "en")
    (charset . "utf-8")))

;; SEO configuration
(define seo-config
  '((title . "Svalinn Vault - Post-Quantum Secure Identity Storage | Hyperpolymath")
    (description . "Military-grade protection for SSH keys, PGP keys, API tokens with Kyber-1024 and Dilithium5 post-quantum cryptography. Open source AGPL-3.0.")
    (keywords . ("post-quantum cryptography"
                 "identity vault"
                 "secure storage"
                 "SSH keys"
                 "PGP keys"
                 "API tokens"
                 "Kyber-1024"
                 "Dilithium5"
                 "AES-256-GCM"
                 "BLAKE3"
                 "Argon2id"
                 "quantum-resistant"
                 "NIST PQC"
                 "open source"
                 "AGPL"
                 "ATS"
                 "dependent types"))
    (og-type . "website")
    (og-image . "/images/svalinn-og.png")
    (twitter-card . "summary_large_image")
    (twitter-site . "@hyperpolymath")
    (canonical . "https://svalinn.hyperpolymath.dev/")))

;; Security headers (CSP, HSTS, etc.)
(define security-headers
  '((content-security-policy . "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'none'")
    (strict-transport-security . "max-age=63072000; includeSubDomains; preload")
    (x-content-type-options . "nosniff")
    (x-frame-options . "DENY")
    (x-xss-protection . "0")
    (referrer-policy . "no-referrer")
    (permissions-policy . "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
    (cross-origin-embedder-policy . "require-corp")
    (cross-origin-opener-policy . "same-origin")
    (cross-origin-resource-policy . "same-origin")))

;; Structured data for Google
(define schema-org
  '((type . "SoftwareApplication")
    (name . "Svalinn Vault")
    (applicationCategory . "SecurityApplication")
    (operatingSystem . "Linux, macOS, Windows, Android")
    (offers . ((type . "Offer")
               (price . "0")
               (priceCurrency . "USD")))
    (author . ((type . "Person")
               (name . "Jonathan D.A. Jewell")
               (affiliation . ((type . "EducationalOrganization")
                              (name . "The Open University")))))
    (license . "https://www.gnu.org/licenses/agpl-3.0.html")
    (codeRepository . "https://github.com/hyperpolymath/reasonable-good-token-vault")
    (programmingLanguage . ("ATS" "Zig" "Idris2" "Scheme"))))

;; Pages
(define pages
  '(("/" . index)
    ("/docs/" . documentation)
    ("/security/" . security-policy)
    ("/download/" . downloads)
    ("/whitepaper/" . whitepaper)))

;; Index page content
(define index-content
  `(article
    (header
     (h1 "Svalinn Vault")
     (p (@ (class "tagline"))
        "Post-Quantum Secure Identity Storage for Hostile Environments"))

    (section (@ (id "warning") (class "warning-box"))
     (h2 "⚠️ Dual-Use Technology Notice")
     (p "This software implements advanced cryptographic technologies that may have dual-use implications. Users are solely responsible for compliance with applicable export control regulations."))

    (section (@ (id "features"))
     (h2 "Security Features")
     (ul
      (li (strong "Post-Quantum Cryptography") ": Kyber-1024 (ML-KEM) and Dilithium5 (ML-DSA)")
      (li (strong "Memory Hardness") ": Argon2id with 64 MiB memory")
      (li (strong "Authenticated Encryption") ": AES-256-GCM with BLAKE3")
      (li (strong "GUID-Based Storage") ": Names redacted until delivery")
      (li (strong "Container Isolation") ": Dual-container with API socket only")
      (li (strong "Lockdown") ": chmod 000 when locked, chroot jail")
      (li (strong "Polymorphic Obfuscation") ": Quantum-seeded transformation")))

    (section (@ (id "install"))
     (h2 "Installation")
     (pre (code "# Nix
nix profile install github:hyperpolymath/reasonable-good-token-vault

# Guix
guix install -f guix.scm

# Arch Linux
yay -S svalinn-vault

# Fedora/RHEL
dnf install svalinn-vault

# Debian/Ubuntu
apt install svalinn-vault")))

    (section (@ (id "research"))
     (h2 "Research")
     (p "Read the "
        (a (@ (href "/whitepaper/")) "whitepaper")
        " for technical details on the cryptographic design and security analysis."))))

;; Build configuration
(define build-config
  '((output-dir . "public")
    (minify-html . #t)
    (minify-css . #t)
    (compress . #t)
    (generate-sitemap . #t)
    (generate-robots . #t)))

;; robots.txt
(define robots-txt
  "User-agent: *
Allow: /

Sitemap: https://svalinn.hyperpolymath.dev/sitemap.xml

# Security
User-agent: GPTBot
Disallow: /

User-agent: ChatGPT-User
Disallow: /

User-agent: CCBot
Disallow: /

User-agent: anthropic-ai
Disallow: /

User-agent: Claude-Web
Disallow: /

User-agent: Google-Extended
Disallow: /")

;; Export configuration
(export site-config
        seo-config
        security-headers
        schema-org
        pages
        index-content
        build-config
        robots-txt)

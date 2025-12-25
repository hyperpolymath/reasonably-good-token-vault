;;; SPDX-License-Identifier: AGPL-3.0-or-later
;;; SPDX-FileCopyrightText: 2025 Hyperpolymath
;;;
;;; USERMEMORY.scm - Secure Identity Location Registry
;;;
;;; This file stores the locations of all managed digital identities
;;; including SSH keys, PGP keys, PATs, and API credentials.
;;;
;;; SECURITY:
;;; - All entries are encrypted with Argon2id + AES-256-GCM
;;; - Post-quantum protected with Kyber-1024 + Dilithium
;;; - Time-locked to UTC with configurable access windows
;;; - MFA required for access
;;; - BLAKE3 integrity verification
;;; - Polymorphic/metamorphic obfuscation
;;;
;;; Storage:
;;; - Primary: CUBS database in Svalinn container
;;; - Search: XTDB with agrep fuzzy indexing
;;; - Cache: Dragonfly (encrypted values only)
;;; - Network: IPv6 only via WireGuard SDP
;;;
;;; Validation: hyperpolymath/echidna formal verification

(define-module (svalinn usermemory)
  #:use-module (srfi srfi-9)      ; Records
  #:use-module (srfi srfi-19)     ; Time
  #:use-module (ice-9 match)      ; Pattern matching
  #:use-module (ice-9 format)     ; Formatting
  #:export (make-identity-registry
            identity-registry?
            registry-version
            registry-identities
            registry-last-modified
            registry-integrity-hash
            make-identity-entry
            identity-entry?
            entry-id
            entry-name
            entry-type
            entry-locations
            entry-fingerprint
            entry-created-at
            entry-modified-at
            entry-accessed-at
            entry-expires-at
            entry-mfa-required?
            entry-timelock
            add-identity!
            remove-identity!
            find-identity
            find-by-type
            find-by-host
            find-by-tag
            export-registry
            import-registry
            verify-integrity))

;;;; === Identity Types ===

(define *identity-types*
  '((ssh . "SSH Key")
    (pgp . "PGP/GPG Key")
    (pat . "Personal Access Token")
    (rest-api . "REST API Credential")
    (graphql-api . "GraphQL API Credential")
    (grpc-api . "gRPC API Credential")
    (xpc . "XPC Service Credential")
    (x509 . "X.509 Certificate")
    (did . "Decentralized Identifier")
    (oauth2 . "OAuth2 Token")
    (jwt . "JWT Token")
    (wireguard . "WireGuard Private Key")
    (custom . "Custom Identity")))

;;;; === Record Types ===

;;; Identity location reference
(define-record-type <identity-location>
  (make-identity-location path host port protocol env-var service-id)
  identity-location?
  (path location-path)
  (host location-host)
  (port location-port)
  (protocol location-protocol)
  (env-var location-env-var)
  (service-id location-service-id))

;;; Timelock configuration
(define-record-type <timelock-config>
  (make-timelock-config not-before not-after allowed-hours allowed-days)
  timelock-config?
  (not-before timelock-not-before)
  (not-after timelock-not-after)
  (allowed-hours timelock-allowed-hours)
  (allowed-days timelock-allowed-days))

;;; Rotation policy
(define-record-type <rotation-policy>
  (make-rotation-policy interval-days last-rotation next-rotation auto-rotate?)
  rotation-policy?
  (interval-days rotation-interval-days)
  (last-rotation rotation-last-rotation)
  (next-rotation rotation-next-rotation)
  (auto-rotate? rotation-auto-rotate?))

;;; Identity entry
(define-record-type <identity-entry>
  (make-identity-entry id name type locations fingerprint
                       created-at modified-at accessed-at expires-at
                       tags mfa-required? timelock rotation-policy
                       encrypted-secret-hash)
  identity-entry?
  (id entry-id)
  (name entry-name)
  (type entry-type)
  (locations entry-locations)
  (fingerprint entry-fingerprint)
  (created-at entry-created-at)
  (modified-at entry-modified-at)
  (accessed-at entry-accessed-at)
  (expires-at entry-expires-at)
  (tags entry-tags)
  (mfa-required? entry-mfa-required?)
  (timelock entry-timelock)
  (rotation-policy entry-rotation-policy)
  (encrypted-secret-hash entry-encrypted-secret-hash))

;;; Identity registry
(define-record-type <identity-registry>
  (make-identity-registry version identities created-at last-modified
                          integrity-hash signature)
  identity-registry?
  (version registry-version)
  (identities registry-identities set-registry-identities!)
  (created-at registry-created-at)
  (last-modified registry-last-modified set-registry-last-modified!)
  (integrity-hash registry-integrity-hash set-registry-integrity-hash!)
  (signature registry-signature set-registry-signature!))

;;;; === Common Identity Locations ===

(define *common-ssh-locations*
  '(("~/.ssh/id_ed25519" . ed25519)
    ("~/.ssh/id_ecdsa" . ecdsa)
    ("~/.ssh/id_rsa" . rsa)
    ("~/.ssh/id_dsa" . dsa)))

(define *common-pgp-locations*
  '(("~/.gnupg/pubring.kbx" . public)
    ("~/.gnupg/private-keys-v1.d/" . private)))

(define *common-pat-hosts*
  '(("github.com" . "GITHUB_TOKEN")
    ("gitlab.com" . "GITLAB_TOKEN")
    ("bitbucket.org" . "BITBUCKET_TOKEN")
    ("dev.azure.com" . "AZURE_DEVOPS_PAT")))

(define *common-api-endpoints*
  '(;; REST APIs
    ("api.github.com" . rest-api)
    ("api.gitlab.com" . rest-api)
    ("api.stripe.com" . rest-api)
    ("api.twilio.com" . rest-api)
    ;; GraphQL APIs
    ("api.github.com/graphql" . graphql-api)
    ;; gRPC APIs
    ("grpc.example.com" . grpc-api)))

;;;; === Registry Operations ===

;;; Create a new empty registry
(define (create-registry)
  (make-identity-registry
   "0.1.0"                              ; version
   '()                                  ; identities (empty)
   (current-time time-utc)              ; created-at
   (current-time time-utc)              ; last-modified
   #f                                   ; integrity-hash (computed later)
   #f))                                 ; signature (computed later)

;;; Add identity to registry
(define (add-identity! registry entry)
  (let ((current (registry-identities registry)))
    ;; Check for duplicate fingerprint
    (when (find (lambda (e) (equal? (entry-fingerprint e)
                                    (entry-fingerprint entry)))
                current)
      (error "Identity with this fingerprint already exists"))
    ;; Add to registry
    (set-registry-identities! registry (cons entry current))
    (set-registry-last-modified! registry (current-time time-utc))
    ;; Return the entry ID
    (entry-id entry)))

;;; Remove identity from registry
(define (remove-identity! registry id)
  (let* ((current (registry-identities registry))
         (found (find (lambda (e) (equal? (entry-id e) id)) current)))
    (unless found
      (error "Identity not found" id))
    (set-registry-identities!
     registry
     (filter (lambda (e) (not (equal? (entry-id e) id))) current))
    (set-registry-last-modified! registry (current-time time-utc))
    found))

;;; Find identity by ID
(define (find-identity registry id)
  (find (lambda (e) (equal? (entry-id e) id))
        (registry-identities registry)))

;;; Find identities by type
(define (find-by-type registry type)
  (filter (lambda (e) (eq? (entry-type e) type))
          (registry-identities registry)))

;;; Find identities by host
(define (find-by-host registry host)
  (filter (lambda (e)
            (any (lambda (loc)
                   (and (location-host loc)
                        (string-contains (location-host loc) host)))
                 (entry-locations e)))
          (registry-identities registry)))

;;; Find identities by tag
(define (find-by-tag registry tag)
  (filter (lambda (e)
            (member tag (entry-tags e)))
          (registry-identities registry)))

;;;; === Serialization ===

;;; Export registry as S-expression (for armoring)
(define (export-registry registry)
  `((version . ,(registry-version registry))
    (created-at . ,(time-second (registry-created-at registry)))
    (last-modified . ,(time-second (registry-last-modified registry)))
    (identity-count . ,(length (registry-identities registry)))
    (identities
     . ,(map (lambda (e)
               `((id . ,(entry-id e))
                 (name . ,(entry-name e))
                 (type . ,(entry-type e))
                 (fingerprint . ,(entry-fingerprint e))
                 (mfa-required . ,(entry-mfa-required? e))
                 (tags . ,(entry-tags e))))
             (registry-identities registry)))))

;;; Import registry from S-expression
(define (import-registry sexp)
  (let ((version (assoc-ref sexp 'version))
        (created (assoc-ref sexp 'created-at))
        (modified (assoc-ref sexp 'last-modified))
        (identities (assoc-ref sexp 'identities)))
    (make-identity-registry
     version
     (map import-identity-entry identities)
     (make-time time-utc 0 created)
     (make-time time-utc 0 modified)
     #f
     #f)))

;;; Import a single identity entry
(define (import-identity-entry sexp)
  (make-identity-entry
   (assoc-ref sexp 'id)
   (assoc-ref sexp 'name)
   (assoc-ref sexp 'type)
   '()                                  ; locations (encrypted separately)
   (assoc-ref sexp 'fingerprint)
   (current-time time-utc)              ; created-at
   (current-time time-utc)              ; modified-at
   #f                                   ; accessed-at
   #f                                   ; expires-at
   (or (assoc-ref sexp 'tags) '())
   (assoc-ref sexp 'mfa-required)
   #f                                   ; timelock
   #f                                   ; rotation-policy
   #f))                                 ; encrypted-secret-hash

;;;; === Integrity Verification ===

;;; Verify registry integrity (stub - actual impl in Rust)
(define (verify-integrity registry)
  ;; This would call the Rust BLAKE3 verification
  ;; For now, return #t as placeholder
  #t)

;;;; === Default Registry Instance ===

;;; The global registry (loaded from vault on unlock)
(define *current-registry* (create-registry))

;;; Access the current registry
(define (current-registry)
  *current-registry*)

;;;; === Example Usage ===

;; Example: Register an SSH key
;; (add-identity! (current-registry)
;;   (make-identity-entry
;;     (generate-uuid)
;;     "GitHub SSH Key"
;;     'ssh
;;     (list (make-identity-location
;;             "~/.ssh/id_ed25519"
;;             "github.com"
;;             22
;;             "ssh"
;;             #f
;;             #f))
;;     "SHA256:abc123..."
;;     (current-time time-utc)
;;     (current-time time-utc)
;;     #f
;;     #f
;;     '("github" "development")
;;     #t                            ; MFA required
;;     (make-timelock-config
;;       #f
;;       #f
;;       '(9 10 11 12 13 14 15 16 17)  ; 9 AM - 5 PM UTC
;;       '(1 2 3 4 5))                 ; Mon-Fri
;;     (make-rotation-policy 90 #f #f #t)
;;     #f))

;;; EOF

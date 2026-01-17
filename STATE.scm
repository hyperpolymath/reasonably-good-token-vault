;; SPDX-License-Identifier: PMPL-1.0
;; STATE.scm - Project state for reasonably-good-token-vault

(state
  (metadata
    (version "0.1.0")
    (schema-version "1.0")
    (created "2024-06-01")
    (updated "2025-01-17")
    (project "reasonably-good-token-vault")
    (repo "hyperpolymath/reasonably-good-token-vault"))

  (project-context
    (name "Reasonably Good Token Vault")
    (tagline "Post-quantum secure identity vault for SSH keys, API tokens, PGP keys")
    (tech-stack ("rust" "kyber" "dilithium")))

  (current-position
    (phase "specification")
    (overall-completion 20)
    (working-features
      ("Post-quantum crypto design"
       "Credential storage spec"))))

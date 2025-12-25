// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Svalinn Vault - ReScript interface for secure identity storage
//
// Type-safe bindings to the Rust vault core

// === Identity Types ===

type identityType =
  | Ssh
  | Pgp
  | Pat
  | RestApi
  | GraphqlApi
  | GrpcApi
  | Xpc
  | X509Certificate
  | Did
  | Oauth2Token
  | JwtToken
  | WireGuard
  | Custom

type apiAuthMethod =
  | BearerToken
  | ApiKey
  | BasicAuth
  | OAuth2
  | Mtls
  | Hmac
  | CustomAuth

type identityLocation = {
  path: option<string>,
  host: option<string>,
  port: option<int>,
  protocol: option<string>,
  envVar: option<string>,
  serviceId: option<string>,
}

type timelockConfig = {
  notBefore: option<float>,
  notAfter: option<float>,
  allowedHours: option<array<int>>,
  allowedDays: option<array<int>>,
}

type rotationPolicy = {
  intervalDays: int,
  lastRotation: option<float>,
  nextRotation: option<float>,
  autoRotate: bool,
}

type identity = {
  id: string,
  name: string,
  identityType: identityType,
  locations: array<identityLocation>,
  createdAt: float,
  modifiedAt: float,
  accessedAt: option<float>,
  expiresAt: option<float>,
  tags: array<string>,
  fingerprint: string,
  mfaRequired: bool,
  timelock: option<timelockConfig>,
  rotationPolicy: option<rotationPolicy>,
}

// === Vault Types ===

type vaultState =
  | Locked
  | MfaPending
  | Unlocked
  | Sealed

type vaultConfig = {
  name: string,
  version: string,
  autoLockTimeout: int,
  requireMfa: bool,
  allowRecovery: bool,
  maxUnlockAttempts: int,
  sealOnMaxFailures: bool,
}

type mfaMethod =
  | Totp
  | Hotp
  | RecoveryCode
  | HardwareKey
  | Biometric
  | PushNotification
  | EmailOtp
  | SmsOtp

// === Error Types ===

type vaultError =
  | AuthenticationFailed
  | KeyDerivationFailed
  | EncryptionFailed
  | DecryptionFailed
  | SignatureVerificationFailed
  | TimeLockActive(float)
  | MfaRequired
  | MfaVerificationFailed
  | IdentityNotFound
  | IdentityAlreadyExists
  | VaultLocked
  | VaultCorrupted
  | OperationNotPermitted

type result<'a> = Belt.Result.t<'a, vaultError>

// === Vault Operations ===

module Vault = {
  // External bindings to Rust vault core (via WASM or FFI)
  @module("svalinn-vault-core")
  external createVault: (~name: string, ~password: string) => result<unit> = "create_vault"

  @module("svalinn-vault-core")
  external unlockVault: (~password: string) => result<unit> = "unlock_vault"

  @module("svalinn-vault-core")
  external lockVault: unit => unit = "lock_vault"

  @module("svalinn-vault-core")
  external getState: unit => vaultState = "get_vault_state"

  @module("svalinn-vault-core")
  external verifyMfa: (~method: mfaMethod, ~code: string) => result<unit> = "verify_mfa"

  @module("svalinn-vault-core")
  external enableTotp: (~accountName: string, ~issuer: string) => result<string> = "enable_totp"

  @module("svalinn-vault-core")
  external generateRecoveryCodes: (~count: int) => result<array<string>> = "generate_recovery_codes"
}

// === Identity Operations ===

module Identity = {
  @module("svalinn-vault-core")
  external addIdentity: identity => result<string> = "add_identity"

  @module("svalinn-vault-core")
  external getIdentity: (~id: string) => result<identity> = "get_identity"

  @module("svalinn-vault-core")
  external removeIdentity: (~id: string) => result<identity> = "remove_identity"

  @module("svalinn-vault-core")
  external listIdentities: (~identityType: option<identityType>) => result<array<identity>> = "list_identities"

  @module("svalinn-vault-core")
  external findByHost: (~host: string) => result<array<identity>> = "find_by_host"

  @module("svalinn-vault-core")
  external findByTag: (~tag: string) => result<array<identity>> = "find_by_tag"

  // Helper functions
  let createSshIdentity = (~name: string, ~path: string, ~host: option<string>=?) => {
    {
      id: "",
      name,
      identityType: Ssh,
      locations: [{
        path: Some(path),
        host,
        port: Some(22),
        protocol: Some("ssh"),
        envVar: None,
        serviceId: None,
      }],
      createdAt: Js.Date.now(),
      modifiedAt: Js.Date.now(),
      accessedAt: None,
      expiresAt: None,
      tags: ["ssh"],
      fingerprint: "",
      mfaRequired: false,
      timelock: None,
      rotationPolicy: None,
    }
  }

  let createPatIdentity = (~name: string, ~host: string, ~envVar: option<string>=?) => {
    {
      id: "",
      name,
      identityType: Pat,
      locations: [{
        path: None,
        host: Some(host),
        port: None,
        protocol: Some("https"),
        envVar,
        serviceId: None,
      }],
      createdAt: Js.Date.now(),
      modifiedAt: Js.Date.now(),
      accessedAt: None,
      expiresAt: None,
      tags: ["pat", "token"],
      fingerprint: "",
      mfaRequired: true,
      timelock: None,
      rotationPolicy: Some({
        intervalDays: 90,
        lastRotation: None,
        nextRotation: None,
        autoRotate: false,
      }),
    }
  }

  let createApiIdentity = (
    ~name: string,
    ~host: string,
    ~identityType: identityType,
    ~authMethod: apiAuthMethod,
  ) => {
    let protocol = switch identityType {
    | GraphqlApi => "graphql"
    | GrpcApi => "grpc"
    | Xpc => "xpc"
    | _ => "https"
    }

    {
      id: "",
      name,
      identityType,
      locations: [{
        path: None,
        host: Some(host),
        port: None,
        protocol: Some(protocol),
        envVar: None,
        serviceId: None,
      }],
      createdAt: Js.Date.now(),
      modifiedAt: Js.Date.now(),
      accessedAt: None,
      expiresAt: None,
      tags: ["api", protocol],
      fingerprint: "",
      mfaRequired: true,
      timelock: None,
      rotationPolicy: None,
    }
  }
}

// === Timelock Operations ===

module Timelock = {
  let createAbsoluteTimelock = (~unlockTime: float) => {
    {
      notBefore: Some(unlockTime),
      notAfter: None,
      allowedHours: None,
      allowedDays: None,
    }
  }

  let createWindowTimelock = (~start: float, ~end_: float) => {
    {
      notBefore: Some(start),
      notAfter: Some(end_),
      allowedHours: None,
      allowedDays: None,
    }
  }

  let createScheduleTimelock = (~hours: array<int>, ~days: array<int>) => {
    {
      notBefore: None,
      notAfter: None,
      allowedHours: Some(hours),
      allowedDays: Some(days),
    }
  }

  // Business hours: Mon-Fri 9-17 UTC
  let businessHoursTimelock = createScheduleTimelock(
    ~hours=[9, 10, 11, 12, 13, 14, 15, 16, 17],
    ~days=[1, 2, 3, 4, 5], // Mon-Fri
  )
}

// === Armor Operations ===

module Armor = {
  @module("svalinn-vault-core")
  external exportArmored: unit => result<string> = "export_armored"

  @module("svalinn-vault-core")
  external importArmored: (~pem: string) => result<unit> = "import_armored"
}

// === Audit Operations ===

module Audit = {
  type auditAction =
    | VaultUnlock
    | VaultLock
    | VaultSeal
    | IdentityAdd
    | IdentityRemove
    | IdentityAccess
    | IdentityModify
    | MfaVerify
    | MfaFail
    | ConfigChange
    | RecoveryAttempt

  type auditEntry = {
    id: string,
    timestamp: float,
    action: auditAction,
    targetId: option<string>,
    success: bool,
    details: option<string>,
  }

  @module("svalinn-vault-core")
  external getAuditLog: unit => result<array<auditEntry>> = "get_audit_log"

  @module("svalinn-vault-core")
  external getIdentityHistory: (~id: string) => result<array<auditEntry>> = "get_identity_history"

  @module("svalinn-vault-core")
  external verifyAuditIntegrity: unit => result<bool> = "verify_audit_integrity"
}

// === Crypto Operations ===

module Crypto = {
  @module("svalinn-vault-core")
  external generateKyberKeypair: unit => result<(string, string)> = "generate_kyber_keypair"

  @module("svalinn-vault-core")
  external generateDilithiumKeypair: unit => result<(string, string)> = "generate_dilithium_keypair"

  @module("svalinn-vault-core")
  external encapsulateKey: (~publicKey: string) => result<(string, string)> = "encapsulate_key"

  @module("svalinn-vault-core")
  external signWithDilithium: (~message: string) => result<string> = "sign_with_dilithium"

  @module("svalinn-vault-core")
  external verifyDilithiumSignature: (
    ~message: string,
    ~signature: string,
    ~publicKey: string,
  ) => result<bool> = "verify_dilithium_signature"
}

// === QRNG Operations ===

module Qrng = {
  type qrngSource =
    | AnuQuantum
    | LocalHardware
    | Cached

  @module("svalinn-vault-core")
  external getQuantumRandomBytes: (~count: int, ~source: qrngSource) => result<array<int>> = "get_quantum_random"

  @module("svalinn-vault-core")
  external refreshQrngCache: unit => result<unit> = "refresh_qrng_cache"

  @module("svalinn-vault-core")
  external getQrngCacheStatus: unit => result<int> = "get_qrng_cache_status"
}

// === Registry Location Types ===

type identityRegistryEntry = {
  identity: identity,
  vaultPath: string,
  encryptedSecretHash: string,
  lastVerified: float,
}

type identityRegistry = {
  entries: array<identityRegistryEntry>,
  version: string,
  lastModified: float,
  integrityHash: string,
}

// Utility to convert identity type to string
let identityTypeToString = (t: identityType): string => {
  switch t {
  | Ssh => "SSH"
  | Pgp => "PGP"
  | Pat => "PAT"
  | RestApi => "REST-API"
  | GraphqlApi => "GraphQL-API"
  | GrpcApi => "gRPC-API"
  | Xpc => "XPC"
  | X509Certificate => "X.509"
  | Did => "DID"
  | Oauth2Token => "OAuth2"
  | JwtToken => "JWT"
  | WireGuard => "WireGuard"
  | Custom => "Custom"
  }
}

let identityTypeFromString = (s: string): option<identityType> => {
  switch s {
  | "SSH" | "ssh" => Some(Ssh)
  | "PGP" | "pgp" => Some(Pgp)
  | "PAT" | "pat" => Some(Pat)
  | "REST-API" | "rest-api" | "rest" => Some(RestApi)
  | "GraphQL-API" | "graphql-api" | "graphql" => Some(GraphqlApi)
  | "gRPC-API" | "grpc-api" | "grpc" => Some(GrpcApi)
  | "XPC" | "xpc" => Some(Xpc)
  | "X.509" | "x509" | "certificate" => Some(X509Certificate)
  | "DID" | "did" => Some(Did)
  | "OAuth2" | "oauth2" | "oauth" => Some(Oauth2Token)
  | "JWT" | "jwt" => Some(JwtToken)
  | "WireGuard" | "wireguard" | "wg" => Some(WireGuard)
  | "Custom" | "custom" => Some(Custom)
  | _ => None
  }
}

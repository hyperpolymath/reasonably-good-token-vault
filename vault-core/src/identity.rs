// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Identity types for secure credential storage
//
// Supports:
// - SSH keys (Ed25519, ECDSA, RSA)
// - PGP/GPG keys
// - Personal Access Tokens (PATs)
// - API credentials (GraphQL, REST, gRPC, XPC)
// - Digital identities (certificates, DIDs)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::Blake3Hasher;
use crate::error::{VaultError, VaultResult};

/// Identity type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityType {
    /// SSH private/public key pair
    Ssh,
    /// PGP/GPG key
    Pgp,
    /// Personal Access Token
    Pat,
    /// API credential for REST endpoints
    RestApi,
    /// API credential for GraphQL endpoints
    GraphqlApi,
    /// API credential for gRPC endpoints
    GrpcApi,
    /// XPC service credential (macOS/Darwin)
    Xpc,
    /// X.509 certificate
    X509Certificate,
    /// Decentralized Identifier
    Did,
    /// OAuth2 token
    Oauth2Token,
    /// JWT token
    JwtToken,
    /// WireGuard private key
    WireGuard,
    /// Custom identity type
    Custom,
}

impl std::fmt::Display for IdentityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssh => write!(f, "SSH"),
            Self::Pgp => write!(f, "PGP"),
            Self::Pat => write!(f, "PAT"),
            Self::RestApi => write!(f, "REST-API"),
            Self::GraphqlApi => write!(f, "GraphQL-API"),
            Self::GrpcApi => write!(f, "gRPC-API"),
            Self::Xpc => write!(f, "XPC"),
            Self::X509Certificate => write!(f, "X.509"),
            Self::Did => write!(f, "DID"),
            Self::Oauth2Token => write!(f, "OAuth2"),
            Self::JwtToken => write!(f, "JWT"),
            Self::WireGuard => write!(f, "WireGuard"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// SSH key algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshKeyAlgorithm {
    Ed25519,
    Ecdsa256,
    Ecdsa384,
    Ecdsa521,
    Rsa2048,
    Rsa4096,
}

/// API authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiAuthMethod {
    BearerToken,
    ApiKey,
    BasicAuth,
    OAuth2,
    Mtls,
    Hmac,
    Custom,
}

/// Location reference for where the identity is stored/used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityLocation {
    /// Filesystem path (e.g., ~/.ssh/id_ed25519)
    pub path: Option<String>,
    /// Remote host/service (e.g., github.com)
    pub host: Option<String>,
    /// Port number
    pub port: Option<u16>,
    /// Protocol (ssh, https, grpc, etc.)
    pub protocol: Option<String>,
    /// Environment variable name
    pub env_var: Option<String>,
    /// Service identifier
    pub service_id: Option<String>,
}

/// Secure credential data (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct CredentialData {
    /// Primary secret (private key, token, password)
    #[zeroize(skip)]
    pub encrypted_secret: Vec<u8>,
    /// Public component (public key, if applicable)
    pub public_component: Option<Vec<u8>>,
    /// Additional metadata (non-sensitive)
    #[zeroize(skip)]
    pub metadata: Option<String>,
}

/// Digital identity with full metadata
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier
    pub id: Uuid,
    /// Human-readable name
    pub name: String,
    /// Identity type
    pub identity_type: IdentityType,
    /// Location references
    pub locations: Vec<IdentityLocation>,
    /// Encrypted credential data
    pub credential: CredentialData,
    /// Creation timestamp (UTC)
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp (UTC)
    pub modified_at: DateTime<Utc>,
    /// Last accessed timestamp (UTC)
    pub accessed_at: Option<DateTime<Utc>>,
    /// Expiration timestamp (UTC)
    pub expires_at: Option<DateTime<Utc>>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// BLAKE3 fingerprint of the identity
    pub fingerprint: String,
    /// Whether MFA is required for access
    pub mfa_required: bool,
    /// Time-lock configuration
    pub timelock: Option<TimelockConfig>,
    /// Rotation policy
    pub rotation_policy: Option<RotationPolicy>,
}

/// Time-lock configuration for identity access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelockConfig {
    /// Earliest UTC time the identity can be accessed
    pub not_before: Option<DateTime<Utc>>,
    /// Latest UTC time the identity can be accessed
    pub not_after: Option<DateTime<Utc>>,
    /// Allowed hours of day (0-23) in UTC
    pub allowed_hours: Option<Vec<u8>>,
    /// Allowed days of week (0=Sunday, 6=Saturday)
    pub allowed_days: Option<Vec<u8>>,
}

/// Rotation policy for credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Rotation interval in days
    pub interval_days: u32,
    /// Last rotation timestamp
    pub last_rotation: Option<DateTime<Utc>>,
    /// Next scheduled rotation
    pub next_rotation: Option<DateTime<Utc>>,
    /// Auto-rotate enabled
    pub auto_rotate: bool,
}

impl Identity {
    /// Create a new identity
    pub fn new(
        name: String,
        identity_type: IdentityType,
        encrypted_secret: Vec<u8>,
        public_component: Option<Vec<u8>>,
    ) -> Self {
        let id = Uuid::new_v4();
        let now = Utc::now();

        // Generate fingerprint from encrypted secret
        let fingerprint = hex::encode(Blake3Hasher::hash(&encrypted_secret));

        Self {
            id,
            name,
            identity_type,
            locations: Vec::new(),
            credential: CredentialData {
                encrypted_secret,
                public_component,
                metadata: None,
            },
            created_at: now,
            modified_at: now,
            accessed_at: None,
            expires_at: None,
            tags: Vec::new(),
            fingerprint,
            mfa_required: false,
            timelock: None,
            rotation_policy: None,
        }
    }

    /// Add a location reference
    pub fn add_location(&mut self, location: IdentityLocation) {
        self.locations.push(location);
        self.modified_at = Utc::now();
    }

    /// Enable MFA requirement
    pub fn require_mfa(&mut self) {
        self.mfa_required = true;
        self.modified_at = Utc::now();
    }

    /// Set time-lock configuration
    pub fn set_timelock(&mut self, config: TimelockConfig) {
        self.timelock = Some(config);
        self.modified_at = Utc::now();
    }

    /// Set rotation policy
    pub fn set_rotation_policy(&mut self, policy: RotationPolicy) {
        self.rotation_policy = Some(policy);
        self.modified_at = Utc::now();
    }

    /// Check if identity is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Check if identity is within time-lock window
    pub fn is_timelock_active(&self) -> bool {
        if let Some(ref config) = self.timelock {
            let now = Utc::now();

            // Check not_before
            if let Some(not_before) = config.not_before {
                if now < not_before {
                    return true;
                }
            }

            // Check not_after
            if let Some(not_after) = config.not_after {
                if now > not_after {
                    return true;
                }
            }

            // Check allowed hours
            if let Some(ref hours) = config.allowed_hours {
                let current_hour = now.hour() as u8;
                if !hours.contains(&current_hour) {
                    return true;
                }
            }

            // Check allowed days
            if let Some(ref days) = config.allowed_days {
                let current_day = now.weekday().num_days_from_sunday() as u8;
                if !days.contains(&current_day) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if rotation is due
    pub fn is_rotation_due(&self) -> bool {
        if let Some(ref policy) = self.rotation_policy {
            if let Some(next_rotation) = policy.next_rotation {
                return Utc::now() >= next_rotation;
            }
        }
        false
    }

    /// Record access
    pub fn record_access(&mut self) {
        self.accessed_at = Some(Utc::now());
    }
}

/// Identity registry for managing multiple identities
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct IdentityRegistry {
    pub identities: Vec<Identity>,
    pub version: String,
    pub last_modified: DateTime<Utc>,
}

impl IdentityRegistry {
    pub fn new() -> Self {
        Self {
            identities: Vec::new(),
            version: crate::VAULT_VERSION.to_string(),
            last_modified: Utc::now(),
        }
    }

    /// Add an identity to the registry
    pub fn add(&mut self, identity: Identity) -> VaultResult<Uuid> {
        // Check for duplicate fingerprints
        if self.identities.iter().any(|i| i.fingerprint == identity.fingerprint) {
            return Err(VaultError::IdentityAlreadyExists);
        }

        let id = identity.id;
        self.identities.push(identity);
        self.last_modified = Utc::now();
        Ok(id)
    }

    /// Get an identity by ID
    pub fn get(&self, id: &Uuid) -> Option<&Identity> {
        self.identities.iter().find(|i| &i.id == id)
    }

    /// Get a mutable identity by ID
    pub fn get_mut(&mut self, id: &Uuid) -> Option<&mut Identity> {
        self.identities.iter_mut().find(|i| &i.id == id)
    }

    /// Remove an identity by ID
    pub fn remove(&mut self, id: &Uuid) -> VaultResult<Identity> {
        let pos = self.identities.iter().position(|i| &i.id == id)
            .ok_or(VaultError::IdentityNotFound)?;
        self.last_modified = Utc::now();
        Ok(self.identities.remove(pos))
    }

    /// Find identities by type
    pub fn find_by_type(&self, identity_type: IdentityType) -> Vec<&Identity> {
        self.identities
            .iter()
            .filter(|i| i.identity_type == identity_type)
            .collect()
    }

    /// Find identities by tag
    pub fn find_by_tag(&self, tag: &str) -> Vec<&Identity> {
        self.identities
            .iter()
            .filter(|i| i.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Find identities by host
    pub fn find_by_host(&self, host: &str) -> Vec<&Identity> {
        self.identities
            .iter()
            .filter(|i| {
                i.locations.iter().any(|l| {
                    l.host.as_ref().map(|h| h == host).unwrap_or(false)
                })
            })
            .collect()
    }

    /// Get all expired identities
    pub fn get_expired(&self) -> Vec<&Identity> {
        self.identities.iter().filter(|i| i.is_expired()).collect()
    }

    /// Get all identities due for rotation
    pub fn get_rotation_due(&self) -> Vec<&Identity> {
        self.identities.iter().filter(|i| i.is_rotation_due()).collect()
    }

    /// Count identities by type
    pub fn count_by_type(&self) -> std::collections::HashMap<IdentityType, usize> {
        let mut counts = std::collections::HashMap::new();
        for identity in &self.identities {
            *counts.entry(identity.identity_type).or_insert(0) += 1;
        }
        counts
    }
}

// Required for chrono hour() method
use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation() {
        let identity = Identity::new(
            "test-ssh-key".to_string(),
            IdentityType::Ssh,
            vec![1, 2, 3, 4],
            Some(vec![5, 6, 7, 8]),
        );

        assert_eq!(identity.name, "test-ssh-key");
        assert_eq!(identity.identity_type, IdentityType::Ssh);
        assert!(!identity.fingerprint.is_empty());
    }

    #[test]
    fn test_identity_registry() {
        let mut registry = IdentityRegistry::new();

        let identity = Identity::new(
            "test-pat".to_string(),
            IdentityType::Pat,
            vec![1, 2, 3, 4],
            None,
        );

        let id = registry.add(identity).unwrap();
        assert!(registry.get(&id).is_some());

        let found = registry.find_by_type(IdentityType::Pat);
        assert_eq!(found.len(), 1);
    }
}

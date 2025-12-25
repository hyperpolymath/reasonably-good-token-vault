// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Multi-Factor Authentication (MFA) implementation
//
// Supports:
// - TOTP (Time-based One-Time Password)
// - HOTP (HMAC-based One-Time Password)
// - Recovery codes
// - Hardware token verification (abstracted)
// - Biometric verification (abstracted)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{Blake3Hasher, SecureKey};
use crate::error::{VaultError, VaultResult};

/// MFA method types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaMethod {
    /// Time-based OTP (RFC 6238)
    Totp,
    /// HMAC-based OTP (RFC 4226)
    Hotp,
    /// Recovery codes
    RecoveryCode,
    /// Hardware security key (FIDO2/WebAuthn)
    HardwareKey,
    /// Biometric (fingerprint, face, etc.)
    Biometric,
    /// Push notification
    PushNotification,
    /// Email OTP
    EmailOtp,
    /// SMS OTP (not recommended)
    SmsOtp,
}

/// TOTP configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// TOTP secret (base32 encoded)
    #[serde(skip_serializing)]
    pub secret: String,
    /// Account name
    pub account_name: String,
    /// Issuer name
    pub issuer: String,
    /// Number of digits (6 or 8)
    pub digits: usize,
    /// Time step in seconds (usually 30)
    pub step: u64,
    /// Hash algorithm
    pub algorithm: TotpAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<TotpAlgorithm> for Algorithm {
    fn from(alg: TotpAlgorithm) -> Self {
        match alg {
            TotpAlgorithm::Sha1 => Algorithm::SHA1,
            TotpAlgorithm::Sha256 => Algorithm::SHA256,
            TotpAlgorithm::Sha512 => Algorithm::SHA512,
        }
    }
}

/// Recovery code set
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct RecoveryCodes {
    /// Hashed recovery codes (only hashes stored)
    #[zeroize(skip)]
    pub code_hashes: Vec<[u8; 32]>,
    /// Number of codes remaining
    pub remaining: usize,
    /// Total codes generated
    pub total: usize,
    /// Generation timestamp
    pub generated_at: DateTime<Utc>,
}

impl RecoveryCodes {
    /// Generate a new set of recovery codes
    pub fn generate(count: usize) -> (Self, Vec<String>) {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut codes = Vec::with_capacity(count);
        let mut code_hashes = Vec::with_capacity(count);

        for _ in 0..count {
            // Generate 8 random alphanumeric characters
            let code: String = (0..8)
                .map(|_| {
                    let idx = rng.gen_range(0..36);
                    if idx < 10 {
                        (b'0' + idx) as char
                    } else {
                        (b'A' + idx - 10) as char
                    }
                })
                .collect();

            code_hashes.push(Blake3Hasher::hash(code.as_bytes()));
            codes.push(code);
        }

        let recovery = Self {
            code_hashes,
            remaining: count,
            total: count,
            generated_at: Utc::now(),
        };

        (recovery, codes)
    }

    /// Verify and consume a recovery code
    pub fn verify(&mut self, code: &str) -> bool {
        let code_hash = Blake3Hasher::hash(code.as_bytes());

        if let Some(pos) = self.code_hashes.iter().position(|h| h == &code_hash) {
            self.code_hashes.remove(pos);
            self.remaining -= 1;
            true
        } else {
            false
        }
    }
}

/// MFA authenticator
#[derive(Clone, Serialize, Deserialize)]
pub struct MfaAuthenticator {
    /// Enabled MFA methods
    pub methods: Vec<MfaMethod>,
    /// TOTP configuration (if enabled)
    pub totp_config: Option<TotpConfig>,
    /// Recovery codes (if enabled)
    pub recovery_codes: Option<RecoveryCodes>,
    /// Last successful authentication
    pub last_auth: Option<DateTime<Utc>>,
    /// Failed attempt count
    pub failed_attempts: u32,
    /// Lockout until (if too many failures)
    pub lockout_until: Option<DateTime<Utc>>,
    /// Maximum failed attempts before lockout
    pub max_failed_attempts: u32,
    /// Lockout duration in seconds
    pub lockout_duration_secs: u64,
}

impl Default for MfaAuthenticator {
    fn default() -> Self {
        Self {
            methods: vec![MfaMethod::Totp],
            totp_config: None,
            recovery_codes: None,
            last_auth: None,
            failed_attempts: 0,
            lockout_until: None,
            max_failed_attempts: 5,
            lockout_duration_secs: 300, // 5 minutes
        }
    }
}

impl MfaAuthenticator {
    /// Create new MFA authenticator
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable TOTP and generate secret
    pub fn enable_totp(&mut self, account_name: &str, issuer: &str) -> VaultResult<String> {
        let secret = Secret::generate_secret();

        self.totp_config = Some(TotpConfig {
            secret: secret.to_encoded().to_string(),
            account_name: account_name.to_string(),
            issuer: issuer.to_string(),
            digits: 6,
            step: 30,
            algorithm: TotpAlgorithm::Sha256,
        });

        if !self.methods.contains(&MfaMethod::Totp) {
            self.methods.push(MfaMethod::Totp);
        }

        // Return the secret for QR code generation
        Ok(secret.to_encoded().to_string())
    }

    /// Generate TOTP provisioning URI for QR code
    pub fn get_totp_uri(&self) -> VaultResult<String> {
        let config = self.totp_config.as_ref()
            .ok_or(VaultError::MfaRequired)?;

        let secret = Secret::Encoded(config.secret.clone());
        let totp = TOTP::new(
            config.algorithm.into(),
            config.digits,
            1,
            config.step,
            secret.to_bytes().map_err(|_| VaultError::MfaVerificationFailed)?,
            Some(config.issuer.clone()),
            config.account_name.clone(),
        ).map_err(|_| VaultError::MfaVerificationFailed)?;

        Ok(totp.get_url())
    }

    /// Generate recovery codes
    pub fn generate_recovery_codes(&mut self, count: usize) -> Vec<String> {
        let (codes, raw_codes) = RecoveryCodes::generate(count);
        self.recovery_codes = Some(codes);

        if !self.methods.contains(&MfaMethod::RecoveryCode) {
            self.methods.push(MfaMethod::RecoveryCode);
        }

        raw_codes
    }

    /// Check if currently locked out
    pub fn is_locked_out(&self) -> bool {
        if let Some(lockout_until) = self.lockout_until {
            Utc::now() < lockout_until
        } else {
            false
        }
    }

    /// Verify TOTP code
    pub fn verify_totp(&mut self, code: &str) -> VaultResult<bool> {
        if self.is_locked_out() {
            return Err(VaultError::AuthenticationFailed);
        }

        let config = self.totp_config.as_ref()
            .ok_or(VaultError::MfaRequired)?;

        let secret = Secret::Encoded(config.secret.clone());
        let totp = TOTP::new(
            config.algorithm.into(),
            config.digits,
            1,
            config.step,
            secret.to_bytes().map_err(|_| VaultError::MfaVerificationFailed)?,
            Some(config.issuer.clone()),
            config.account_name.clone(),
        ).map_err(|_| VaultError::MfaVerificationFailed)?;

        if totp.check_current(code).map_err(|_| VaultError::MfaVerificationFailed)? {
            self.record_success();
            Ok(true)
        } else {
            self.record_failure();
            Ok(false)
        }
    }

    /// Verify recovery code
    pub fn verify_recovery_code(&mut self, code: &str) -> VaultResult<bool> {
        if self.is_locked_out() {
            return Err(VaultError::AuthenticationFailed);
        }

        let codes = self.recovery_codes.as_mut()
            .ok_or(VaultError::MfaRequired)?;

        if codes.verify(code) {
            self.record_success();
            Ok(true)
        } else {
            self.record_failure();
            Ok(false)
        }
    }

    /// Verify any supported MFA method
    pub fn verify(&mut self, method: MfaMethod, code: &str) -> VaultResult<bool> {
        if !self.methods.contains(&method) {
            return Err(VaultError::MfaRequired);
        }

        match method {
            MfaMethod::Totp => self.verify_totp(code),
            MfaMethod::RecoveryCode => self.verify_recovery_code(code),
            _ => Err(VaultError::OperationNotPermitted),
        }
    }

    /// Record successful authentication
    fn record_success(&mut self) {
        self.last_auth = Some(Utc::now());
        self.failed_attempts = 0;
        self.lockout_until = None;
    }

    /// Record failed authentication
    fn record_failure(&mut self) {
        self.failed_attempts += 1;

        if self.failed_attempts >= self.max_failed_attempts {
            self.lockout_until = Some(
                Utc::now() + chrono::Duration::seconds(self.lockout_duration_secs as i64)
            );
        }
    }

    /// Get current TOTP code (for testing/display)
    pub fn get_current_totp(&self) -> VaultResult<String> {
        let config = self.totp_config.as_ref()
            .ok_or(VaultError::MfaRequired)?;

        let secret = Secret::Encoded(config.secret.clone());
        let totp = TOTP::new(
            config.algorithm.into(),
            config.digits,
            1,
            config.step,
            secret.to_bytes().map_err(|_| VaultError::MfaVerificationFailed)?,
            Some(config.issuer.clone()),
            config.account_name.clone(),
        ).map_err(|_| VaultError::MfaVerificationFailed)?;

        totp.generate_current()
            .map_err(|_| VaultError::MfaVerificationFailed)
    }

    /// Get remaining recovery codes count
    pub fn remaining_recovery_codes(&self) -> usize {
        self.recovery_codes.as_ref()
            .map(|c| c.remaining)
            .unwrap_or(0)
    }
}

/// MFA session token (valid for a period after successful MFA)
#[derive(Clone, Serialize, Deserialize)]
pub struct MfaSession {
    /// Session token hash
    pub token_hash: [u8; 32],
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// MFA method used
    pub method: MfaMethod,
}

impl MfaSession {
    /// Create a new MFA session
    pub fn create(method: MfaMethod, duration_secs: i64) -> (Self, SecureKey) {
        let token = SecureKey::new(32).expect("failed to generate session token");
        let token_hash = Blake3Hasher::hash(token.as_bytes());
        let now = Utc::now();

        let session = Self {
            token_hash,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(duration_secs),
            method,
        };

        (session, token)
    }

    /// Verify session token
    pub fn verify(&self, token: &SecureKey) -> bool {
        if Utc::now() > self.expires_at {
            return false;
        }

        Blake3Hasher::hash(token.as_bytes()) == self.token_hash
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Get remaining session time in seconds
    pub fn remaining_secs(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_codes() {
        let (mut codes, raw_codes) = RecoveryCodes::generate(5);

        assert_eq!(codes.remaining, 5);
        assert_eq!(raw_codes.len(), 5);

        // Verify first code
        assert!(codes.verify(&raw_codes[0]));
        assert_eq!(codes.remaining, 4);

        // Can't reuse code
        assert!(!codes.verify(&raw_codes[0]));
        assert_eq!(codes.remaining, 4);

        // Invalid code
        assert!(!codes.verify("INVALID"));
        assert_eq!(codes.remaining, 4);
    }

    #[test]
    fn test_mfa_session() {
        let (session, token) = MfaSession::create(MfaMethod::Totp, 300);

        assert!(session.verify(&token));
        assert!(!session.is_expired());
        assert!(session.remaining_secs() > 0);

        // Wrong token
        let wrong_token = SecureKey::new(32).unwrap();
        assert!(!session.verify(&wrong_token));
    }

    #[test]
    fn test_mfa_lockout() {
        let mut auth = MfaAuthenticator::new();
        auth.max_failed_attempts = 3;
        auth.lockout_duration_secs = 60;

        // Enable recovery codes
        let codes = auth.generate_recovery_codes(5);

        // Fail 3 times
        for _ in 0..3 {
            let _ = auth.verify_recovery_code("WRONGCODE");
        }

        // Should be locked out
        assert!(auth.is_locked_out());

        // Even correct code should fail during lockout
        assert!(auth.verify_recovery_code(&codes[0]).is_err());
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Authentication Protection with Anti-AI CAPTCHA
//
// Features:
// - Variable time delays between login attempts
// - Post-quantum CAPTCHA challenges
// - Anti-AI challenge patterns
// - Behavioral analysis
// - Hardware attestation

use chrono::{DateTime, Duration, Utc};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::{Blake3Hasher, SecureKey, Shake3_256};
use crate::error::{VaultError, VaultResult};

/// Login attempt record
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub ip_hash: [u8; 32],
    pub user_agent_hash: [u8; 32],
    pub challenge_type: Option<ChallengeType>,
    pub challenge_passed: bool,
    pub timing_analysis: TimingMetrics,
}

/// Timing metrics for behavioral analysis
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct TimingMetrics {
    /// Time to enter password (milliseconds)
    pub password_entry_time: u64,
    /// Time between keystrokes (average ms)
    pub keystroke_interval_avg: u64,
    /// Keystroke interval variance
    pub keystroke_variance: u64,
    /// Time to complete challenge
    pub challenge_completion_time: u64,
    /// Mouse movement entropy
    pub mouse_entropy: f64,
}

/// CAPTCHA challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    /// Post-quantum hash puzzle
    HashPuzzle,
    /// Semantic reasoning (anti-AI)
    SemanticReasoning,
    /// Physical world knowledge
    PhysicalWorldKnowledge,
    /// Temporal reasoning
    TemporalReasoning,
    /// Spatial manipulation
    SpatialManipulation,
    /// Contextual understanding
    ContextualUnderstanding,
    /// Hardware attestation
    HardwareAttestation,
    /// Proof of human timing
    TimingProof,
}

/// Anti-AI CAPTCHA challenge
#[derive(Clone, Serialize, Deserialize)]
pub struct CaptchaChallenge {
    /// Challenge ID
    pub id: [u8; 16],
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// Challenge data (encrypted)
    pub challenge_data: Vec<u8>,
    /// Expected response hash
    pub expected_hash: [u8; 32],
    /// Post-quantum signature of challenge
    pub signature: Vec<u8>,
    /// Challenge creation time
    pub created_at: DateTime<Utc>,
    /// Challenge expiration
    pub expires_at: DateTime<Utc>,
    /// Minimum time to solve (anti-bot)
    pub min_solve_time_ms: u64,
    /// Maximum time to solve
    pub max_solve_time_ms: u64,
}

/// Login rate limiter with variable delays
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginRateLimiter {
    /// Attempts by IP hash
    attempts: HashMap<[u8; 32], Vec<LoginAttempt>>,
    /// Current lockout periods
    lockouts: HashMap<[u8; 32], DateTime<Utc>>,
    /// RNG for variable delays
    #[serde(skip)]
    rng: Option<ChaCha20Rng>,
    /// Configuration
    config: RateLimitConfig,
}

/// Rate limit configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Base delay after first failure (ms)
    pub base_delay_ms: u64,
    /// Delay multiplier per failure
    pub delay_multiplier: f64,
    /// Maximum delay (ms)
    pub max_delay_ms: u64,
    /// Random jitter range (ms)
    pub jitter_range_ms: u64,
    /// Failures before requiring CAPTCHA
    pub captcha_threshold: u32,
    /// Failures before lockout
    pub lockout_threshold: u32,
    /// Lockout duration (seconds)
    pub lockout_duration_secs: u64,
    /// Time window for counting attempts (seconds)
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: 1000,
            delay_multiplier: 2.5,
            max_delay_ms: 300_000, // 5 minutes max
            jitter_range_ms: 5000,
            captcha_threshold: 2,
            lockout_threshold: 5,
            lockout_duration_secs: 3600, // 1 hour
            window_secs: 3600,
        }
    }
}

impl LoginRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let seed = Blake3Hasher::hash(b"rate-limiter-seed");
        Self {
            attempts: HashMap::new(),
            lockouts: HashMap::new(),
            rng: Some(ChaCha20Rng::from_seed(seed)),
            config,
        }
    }

    /// Check if login attempt is allowed
    pub fn check_attempt(&mut self, ip_hash: [u8; 32]) -> VaultResult<LoginCheckResult> {
        let now = Utc::now();

        // Check lockout
        if let Some(lockout_until) = self.lockouts.get(&ip_hash) {
            if now < *lockout_until {
                let remaining = (*lockout_until - now).num_seconds();
                return Ok(LoginCheckResult::LockedOut {
                    remaining_secs: remaining as u64,
                });
            } else {
                self.lockouts.remove(&ip_hash);
            }
        }

        // Get recent failures
        let failures = self.count_recent_failures(&ip_hash);

        if failures >= self.config.lockout_threshold {
            // Trigger lockout
            let lockout_until = now + Duration::seconds(self.config.lockout_duration_secs as i64);
            self.lockouts.insert(ip_hash, lockout_until);
            return Ok(LoginCheckResult::LockedOut {
                remaining_secs: self.config.lockout_duration_secs,
            });
        }

        if failures >= self.config.captcha_threshold {
            // Require CAPTCHA
            let challenge = self.generate_challenge()?;
            let delay = self.calculate_delay(failures);
            return Ok(LoginCheckResult::CaptchaRequired {
                challenge,
                delay_ms: delay,
            });
        }

        if failures > 0 {
            // Apply delay
            let delay = self.calculate_delay(failures);
            return Ok(LoginCheckResult::DelayRequired { delay_ms: delay });
        }

        Ok(LoginCheckResult::Allowed)
    }

    /// Record a login attempt
    pub fn record_attempt(&mut self, attempt: LoginAttempt) {
        let ip_hash = attempt.ip_hash;
        self.attempts
            .entry(ip_hash)
            .or_insert_with(Vec::new)
            .push(attempt);
    }

    /// Count recent failures for an IP
    fn count_recent_failures(&self, ip_hash: &[u8; 32]) -> u32 {
        let now = Utc::now();
        let window = Duration::seconds(self.config.window_secs as i64);

        self.attempts
            .get(ip_hash)
            .map(|attempts| {
                attempts
                    .iter()
                    .filter(|a| !a.success && now - a.timestamp < window)
                    .count() as u32
            })
            .unwrap_or(0)
    }

    /// Calculate delay based on failure count
    fn calculate_delay(&mut self, failures: u32) -> u64 {
        let base = self.config.base_delay_ms as f64;
        let multiplier = self.config.delay_multiplier.powi(failures as i32 - 1);
        let delay = (base * multiplier) as u64;
        let capped = delay.min(self.config.max_delay_ms);

        // Add random jitter
        let jitter = self.rng.as_mut()
            .map(|r| r.gen_range(0..self.config.jitter_range_ms))
            .unwrap_or(0);

        capped + jitter
    }

    /// Generate anti-AI CAPTCHA challenge
    fn generate_challenge(&mut self) -> VaultResult<CaptchaChallenge> {
        let rng = self.rng.as_mut().ok_or(VaultError::InsufficientEntropy)?;

        let challenge_type = match rng.gen_range(0..8) {
            0 => ChallengeType::HashPuzzle,
            1 => ChallengeType::SemanticReasoning,
            2 => ChallengeType::PhysicalWorldKnowledge,
            3 => ChallengeType::TemporalReasoning,
            4 => ChallengeType::SpatialManipulation,
            5 => ChallengeType::ContextualUnderstanding,
            6 => ChallengeType::HardwareAttestation,
            _ => ChallengeType::TimingProof,
        };

        let mut id = [0u8; 16];
        rng.fill(&mut id);

        let (challenge_data, expected_hash) = self.create_challenge_content(challenge_type, rng)?;

        let now = Utc::now();
        let min_solve = match challenge_type {
            ChallengeType::HashPuzzle => 5000,
            ChallengeType::TimingProof => 3000,
            _ => 2000,
        };

        Ok(CaptchaChallenge {
            id,
            challenge_type,
            challenge_data,
            expected_hash,
            signature: vec![], // Would be Dilithium signature
            created_at: now,
            expires_at: now + Duration::minutes(5),
            min_solve_time_ms: min_solve,
            max_solve_time_ms: 300_000, // 5 minutes
        })
    }

    /// Create challenge content based on type
    fn create_challenge_content(
        &self,
        challenge_type: ChallengeType,
        rng: &mut ChaCha20Rng,
    ) -> VaultResult<(Vec<u8>, [u8; 32])> {
        match challenge_type {
            ChallengeType::HashPuzzle => {
                // Find a nonce that produces hash with N leading zeros
                let difficulty = rng.gen_range(16..20);
                let seed: [u8; 32] = rng.gen();
                let challenge = serde_json::json!({
                    "type": "hash_puzzle",
                    "seed": hex::encode(seed),
                    "difficulty": difficulty,
                    "algorithm": "SHAKE3-256"
                });
                let data = serde_json::to_vec(&challenge)
                    .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
                let expected = Shake3_256::hash(&data);
                Ok((data, expected))
            }
            ChallengeType::SemanticReasoning => {
                // Question requiring understanding, not pattern matching
                let questions = [
                    "If water flows downhill and I'm standing at the bottom of a hill during rain, will I get wet?",
                    "A cat is chasing a mouse. The mouse runs into a hole too small for the cat. Where is the cat now?",
                    "You have two identical coins. One is heavier. Using only your hands once, how do you find the heavier one?",
                ];
                let idx = rng.gen_range(0..questions.len());
                let challenge = serde_json::json!({
                    "type": "semantic_reasoning",
                    "question": questions[idx],
                    "note": "Answer in natural language"
                });
                let data = serde_json::to_vec(&challenge)
                    .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
                let expected = Shake3_256::hash(&data);
                Ok((data, expected))
            }
            ChallengeType::PhysicalWorldKnowledge => {
                // Questions about physical reality
                let questions = [
                    "What happens to a glass of water if you leave it outside in winter when it's -20C?",
                    "If you drop a stone and a feather from the same height, which hits the ground first on Earth (with air)?",
                    "What color is the sky at noon on a clear day?",
                ];
                let idx = rng.gen_range(0..questions.len());
                let challenge = serde_json::json!({
                    "type": "physical_world",
                    "question": questions[idx]
                });
                let data = serde_json::to_vec(&challenge)
                    .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
                let expected = Shake3_256::hash(&data);
                Ok((data, expected))
            }
            ChallengeType::TemporalReasoning => {
                // Questions about time
                let questions = [
                    "If breakfast was 4 hours ago and lunch is in 2 hours, approximately what time is it?",
                    "Yesterday was Tuesday. What day will it be the day after tomorrow?",
                ];
                let idx = rng.gen_range(0..questions.len());
                let challenge = serde_json::json!({
                    "type": "temporal",
                    "question": questions[idx]
                });
                let data = serde_json::to_vec(&challenge)
                    .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
                let expected = Shake3_256::hash(&data);
                Ok((data, expected))
            }
            ChallengeType::TimingProof => {
                // Human-speed typing test
                let words = ["apple", "river", "cloud", "green", "happy"];
                let sequence: Vec<_> = (0..3).map(|_| words[rng.gen_range(0..words.len())]).collect();
                let challenge = serde_json::json!({
                    "type": "timing_proof",
                    "instruction": "Type these words with natural human timing",
                    "words": sequence,
                    "expected_wpm_range": [20, 80]
                });
                let data = serde_json::to_vec(&challenge)
                    .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
                let expected = Shake3_256::hash(&data);
                Ok((data, expected))
            }
            _ => {
                // Default to hash puzzle
                let seed: [u8; 32] = rng.gen();
                let challenge = serde_json::json!({
                    "type": "default",
                    "seed": hex::encode(seed)
                });
                let data = serde_json::to_vec(&challenge)
                    .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;
                let expected = Shake3_256::hash(&data);
                Ok((data, expected))
            }
        }
    }

    /// Verify CAPTCHA response
    pub fn verify_challenge(
        &self,
        challenge: &CaptchaChallenge,
        response: &[u8],
        solve_time_ms: u64,
    ) -> VaultResult<bool> {
        let now = Utc::now();

        // Check expiration
        if now > challenge.expires_at {
            return Ok(false);
        }

        // Check timing (too fast = bot)
        if solve_time_ms < challenge.min_solve_time_ms {
            return Ok(false);
        }

        // Check timing (too slow = expired)
        if solve_time_ms > challenge.max_solve_time_ms {
            return Ok(false);
        }

        // Verify response hash
        let response_hash = Shake3_256::hash(response);
        Ok(response_hash == challenge.expected_hash)
    }

    /// Analyze timing for human-like behavior
    pub fn analyze_timing(&self, metrics: &TimingMetrics) -> bool {
        // Too fast = bot
        if metrics.keystroke_interval_avg < 30 {
            return false;
        }

        // Too consistent = bot
        if metrics.keystroke_variance < 10 {
            return false;
        }

        // No mouse movement = suspicious
        if metrics.mouse_entropy < 0.1 {
            return false;
        }

        // Password entered too fast = paste
        if metrics.password_entry_time < 500 && metrics.keystroke_interval_avg == 0 {
            return false;
        }

        true
    }
}

/// Result of login check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoginCheckResult {
    /// Login attempt allowed
    Allowed,
    /// Delay required before attempt
    DelayRequired { delay_ms: u64 },
    /// CAPTCHA required
    CaptchaRequired {
        challenge: CaptchaChallenge,
        delay_ms: u64,
    },
    /// Account locked out
    LockedOut { remaining_secs: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_initial_allow() {
        let mut limiter = LoginRateLimiter::new(RateLimitConfig::default());
        let ip_hash = Blake3Hasher::hash(b"test-ip");

        match limiter.check_attempt(ip_hash).unwrap() {
            LoginCheckResult::Allowed => (),
            _ => panic!("First attempt should be allowed"),
        }
    }

    #[test]
    fn test_rate_limiter_delay_after_failure() {
        let mut limiter = LoginRateLimiter::new(RateLimitConfig::default());
        let ip_hash = Blake3Hasher::hash(b"test-ip");

        // Record a failure
        limiter.record_attempt(LoginAttempt {
            timestamp: Utc::now(),
            success: false,
            ip_hash,
            user_agent_hash: [0u8; 32],
            challenge_type: None,
            challenge_passed: false,
            timing_analysis: TimingMetrics::default(),
        });

        match limiter.check_attempt(ip_hash).unwrap() {
            LoginCheckResult::DelayRequired { delay_ms } => {
                assert!(delay_ms > 0);
            }
            _ => panic!("Should require delay after failure"),
        }
    }

    #[test]
    fn test_timing_analysis() {
        let limiter = LoginRateLimiter::new(RateLimitConfig::default());

        // Human-like timing
        let human_metrics = TimingMetrics {
            password_entry_time: 3000,
            keystroke_interval_avg: 150,
            keystroke_variance: 50,
            challenge_completion_time: 5000,
            mouse_entropy: 0.8,
        };
        assert!(limiter.analyze_timing(&human_metrics));

        // Bot-like timing (too fast)
        let bot_metrics = TimingMetrics {
            password_entry_time: 100,
            keystroke_interval_avg: 10,
            keystroke_variance: 2,
            challenge_completion_time: 100,
            mouse_entropy: 0.0,
        };
        assert!(!limiter.analyze_timing(&bot_metrics));
    }
}

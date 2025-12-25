// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Time-locking mechanisms for identity access control
//
// Features:
// - UTC-based time windows
// - Time-locked encryption (future unlock)
// - Access schedules (hours, days)
// - Cryptographic time-lock puzzles

use chrono::{DateTime, Datelike, Duration, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};

use crate::crypto::{Blake3Hasher, SecureKey, Shake3_256};
use crate::error::{VaultError, VaultResult};

/// UTC-based time zone constant
pub const UTC_OFFSET: i32 = 0;

/// Time-lock state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeLockState {
    /// Time-lock is active, access denied
    Locked,
    /// Time-lock window is open, access permitted
    Unlocked,
    /// Time-lock has expired, permanent lockout
    Expired,
}

/// Time-lock policy types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeLockPolicy {
    /// Simple absolute unlock time
    AbsoluteUnlock {
        unlock_time: DateTime<Utc>,
    },
    /// Window-based access
    TimeWindow {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
    /// Recurring schedule (hours and days)
    Schedule {
        allowed_hours: Vec<u8>,
        allowed_days: Vec<Weekday>,
        timezone_offset: i32,
    },
    /// Cryptographic puzzle-based (time-consuming to solve)
    CryptoPuzzle {
        difficulty: u32,
        puzzle_hash: [u8; 32],
    },
    /// Sequential unlocks (must wait between accesses)
    RateLimited {
        min_interval_seconds: u64,
        last_access: Option<DateTime<Utc>>,
    },
    /// Composite (all policies must be satisfied)
    Composite {
        policies: Vec<TimeLockPolicy>,
    },
}

/// Time-lock controller
#[derive(Clone, Serialize, Deserialize)]
pub struct TimeLock {
    /// Unique identifier
    pub id: String,
    /// Time-lock policy
    pub policy: TimeLockPolicy,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Number of access attempts
    pub access_attempts: u64,
    /// Whether the lock has been bypassed (admin override)
    pub bypassed: bool,
}

impl TimeLock {
    /// Create a new absolute time-lock
    pub fn absolute(id: impl Into<String>, unlock_time: DateTime<Utc>) -> Self {
        Self {
            id: id.into(),
            policy: TimeLockPolicy::AbsoluteUnlock { unlock_time },
            created_at: Utc::now(),
            access_attempts: 0,
            bypassed: false,
        }
    }

    /// Create a time window lock
    pub fn window(id: impl Into<String>, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        Self {
            id: id.into(),
            policy: TimeLockPolicy::TimeWindow { start, end },
            created_at: Utc::now(),
            access_attempts: 0,
            bypassed: false,
        }
    }

    /// Create a schedule-based lock
    pub fn schedule(
        id: impl Into<String>,
        allowed_hours: Vec<u8>,
        allowed_days: Vec<Weekday>,
    ) -> Self {
        Self {
            id: id.into(),
            policy: TimeLockPolicy::Schedule {
                allowed_hours,
                allowed_days,
                timezone_offset: UTC_OFFSET,
            },
            created_at: Utc::now(),
            access_attempts: 0,
            bypassed: false,
        }
    }

    /// Create a rate-limited lock
    pub fn rate_limited(id: impl Into<String>, min_interval_seconds: u64) -> Self {
        Self {
            id: id.into(),
            policy: TimeLockPolicy::RateLimited {
                min_interval_seconds,
                last_access: None,
            },
            created_at: Utc::now(),
            access_attempts: 0,
            bypassed: false,
        }
    }

    /// Create a cryptographic puzzle lock
    pub fn crypto_puzzle(id: impl Into<String>, difficulty: u32, seed: &[u8]) -> Self {
        let puzzle_hash = Blake3Hasher::hash(seed);
        Self {
            id: id.into(),
            policy: TimeLockPolicy::CryptoPuzzle {
                difficulty,
                puzzle_hash,
            },
            created_at: Utc::now(),
            access_attempts: 0,
            bypassed: false,
        }
    }

    /// Check current state of the time-lock
    pub fn state(&self) -> TimeLockState {
        if self.bypassed {
            return TimeLockState::Unlocked;
        }

        match &self.policy {
            TimeLockPolicy::AbsoluteUnlock { unlock_time } => {
                if Utc::now() >= *unlock_time {
                    TimeLockState::Unlocked
                } else {
                    TimeLockState::Locked
                }
            }
            TimeLockPolicy::TimeWindow { start, end } => {
                let now = Utc::now();
                if now < *start {
                    TimeLockState::Locked
                } else if now > *end {
                    TimeLockState::Expired
                } else {
                    TimeLockState::Unlocked
                }
            }
            TimeLockPolicy::Schedule {
                allowed_hours,
                allowed_days,
                ..
            } => {
                let now = Utc::now();
                let current_hour = now.hour() as u8;
                let current_day = now.weekday();

                let hour_ok = allowed_hours.contains(&current_hour);
                let day_ok = allowed_days.contains(&current_day);

                if hour_ok && day_ok {
                    TimeLockState::Unlocked
                } else {
                    TimeLockState::Locked
                }
            }
            TimeLockPolicy::RateLimited {
                min_interval_seconds,
                last_access,
            } => {
                if let Some(last) = last_access {
                    let elapsed = (Utc::now() - *last).num_seconds() as u64;
                    if elapsed >= *min_interval_seconds {
                        TimeLockState::Unlocked
                    } else {
                        TimeLockState::Locked
                    }
                } else {
                    TimeLockState::Unlocked
                }
            }
            TimeLockPolicy::CryptoPuzzle { .. } => {
                // Crypto puzzles require explicit solution
                TimeLockState::Locked
            }
            TimeLockPolicy::Composite { policies } => {
                for policy in policies {
                    let sub_lock = TimeLock {
                        id: self.id.clone(),
                        policy: policy.clone(),
                        created_at: self.created_at,
                        access_attempts: 0,
                        bypassed: false,
                    };
                    match sub_lock.state() {
                        TimeLockState::Locked => return TimeLockState::Locked,
                        TimeLockState::Expired => return TimeLockState::Expired,
                        TimeLockState::Unlocked => continue,
                    }
                }
                TimeLockState::Unlocked
            }
        }
    }

    /// Check if access is permitted
    pub fn check_access(&mut self) -> VaultResult<bool> {
        self.access_attempts += 1;

        match self.state() {
            TimeLockState::Unlocked => {
                // Update last access for rate-limited policies
                if let TimeLockPolicy::RateLimited { last_access, .. } = &mut self.policy {
                    *last_access = Some(Utc::now());
                }
                Ok(true)
            }
            TimeLockState::Locked => {
                let unlock_time = self.next_unlock_time();
                Err(VaultError::TimeLockActive {
                    unlock_time_utc: unlock_time.map(|t| t.timestamp()).unwrap_or(0),
                })
            }
            TimeLockState::Expired => Err(VaultError::OperationNotPermitted),
        }
    }

    /// Get the next unlock time (if determinable)
    pub fn next_unlock_time(&self) -> Option<DateTime<Utc>> {
        match &self.policy {
            TimeLockPolicy::AbsoluteUnlock { unlock_time } => Some(*unlock_time),
            TimeLockPolicy::TimeWindow { start, .. } => {
                let now = Utc::now();
                if now < *start {
                    Some(*start)
                } else {
                    None
                }
            }
            TimeLockPolicy::RateLimited {
                min_interval_seconds,
                last_access,
            } => last_access
                .map(|last| last + Duration::seconds(*min_interval_seconds as i64)),
            _ => None,
        }
    }

    /// Solve a crypto puzzle to unlock
    pub fn solve_puzzle(&mut self, solution: &[u8]) -> VaultResult<bool> {
        if let TimeLockPolicy::CryptoPuzzle {
            difficulty,
            puzzle_hash,
        } = &self.policy
        {
            // Verify the solution by checking leading zeros
            let hash = Shake3_256::hash(solution);

            // Count leading zero bits
            let mut zeros = 0u32;
            for byte in hash.iter() {
                if *byte == 0 {
                    zeros += 8;
                } else {
                    zeros += byte.leading_zeros();
                    break;
                }
            }

            if zeros >= *difficulty && Blake3Hasher::hash(solution) == *puzzle_hash {
                self.bypassed = true;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(VaultError::OperationNotPermitted)
        }
    }

    /// Admin bypass (requires separate authorization)
    pub fn admin_bypass(&mut self, auth_key: &SecureKey) -> VaultResult<()> {
        // Verify auth key is valid (simplified - in production would verify signature)
        if auth_key.len() >= 32 {
            self.bypassed = true;
            Ok(())
        } else {
            Err(VaultError::AuthenticationFailed)
        }
    }

    /// Get time until unlock (in seconds)
    pub fn time_until_unlock(&self) -> Option<i64> {
        self.next_unlock_time()
            .map(|unlock| (unlock - Utc::now()).num_seconds())
    }
}

/// Time-lock encrypted data
/// Data that can only be decrypted after a certain time
#[derive(Clone, Serialize, Deserialize)]
pub struct TimeLockEncrypted {
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Time-lock configuration
    pub timelock: TimeLock,
    /// Hash of the key (for verification after unlock)
    pub key_hash: [u8; 32],
}

impl TimeLockEncrypted {
    /// Create new time-locked encrypted data
    pub fn new(
        ciphertext: Vec<u8>,
        timelock: TimeLock,
        encryption_key: &SecureKey,
    ) -> Self {
        let key_hash = Blake3Hasher::hash(encryption_key.as_bytes());
        Self {
            ciphertext,
            timelock,
            key_hash,
        }
    }

    /// Check if data can be decrypted
    pub fn can_decrypt(&self) -> bool {
        self.timelock.state() == TimeLockState::Unlocked
    }

    /// Verify decryption key
    pub fn verify_key(&self, key: &SecureKey) -> bool {
        Blake3Hasher::hash(key.as_bytes()) == self.key_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_absolute_timelock() {
        // Already passed time
        let past = Utc::now() - Duration::hours(1);
        let lock = TimeLock::absolute("test", past);
        assert_eq!(lock.state(), TimeLockState::Unlocked);

        // Future time
        let future = Utc::now() + Duration::hours(1);
        let lock = TimeLock::absolute("test", future);
        assert_eq!(lock.state(), TimeLockState::Locked);
    }

    #[test]
    fn test_rate_limited() {
        let mut lock = TimeLock::rate_limited("test", 1);

        // First access should work
        assert!(lock.check_access().is_ok());

        // Immediate second access should fail
        assert!(lock.check_access().is_err());
    }

    #[test]
    fn test_time_window() {
        let start = Utc::now() - Duration::hours(1);
        let end = Utc::now() + Duration::hours(1);
        let lock = TimeLock::window("test", start, end);
        assert_eq!(lock.state(), TimeLockState::Unlocked);

        // Expired window
        let start = Utc::now() - Duration::hours(2);
        let end = Utc::now() - Duration::hours(1);
        let lock = TimeLock::window("test", start, end);
        assert_eq!(lock.state(), TimeLockState::Expired);
    }
}

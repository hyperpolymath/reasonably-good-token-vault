// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Prime number verification and generation
//
// Implements:
// - Miller-Rabin primality testing with 64+ rounds
// - Strong prime generation
// - Flat distributed prime generation
// - Sophie Germain primes for DH parameters

use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;

use crate::error::{VaultError, VaultResult};
use crate::MILLER_RABIN_ROUNDS;

/// Prime verification and generation utilities
pub struct PrimeVerifier;

impl PrimeVerifier {
    /// Verify if a number is prime using Miller-Rabin with 64+ rounds
    pub fn is_prime(n: &BigUint) -> bool {
        if n <= &1u32.to_biguint().unwrap() {
            return false;
        }
        if n == &2u32.to_biguint().unwrap() || n == &3u32.to_biguint().unwrap() {
            return true;
        }
        if n.is_even() {
            return false;
        }

        Self::miller_rabin(n, MILLER_RABIN_ROUNDS)
    }

    /// Miller-Rabin primality test
    fn miller_rabin(n: &BigUint, rounds: usize) -> bool {
        let one = BigUint::one();
        let two = 2u32.to_biguint().unwrap();
        let n_minus_one = n - &one;
        let n_minus_two = n - &two;

        // Factor n-1 as 2^r * d
        let mut d = n_minus_one.clone();
        let mut r = 0u32;
        while d.is_even() {
            d >>= 1;
            r += 1;
        }

        // Witness loop
        let mut rng = OsRng;
        for _ in 0..rounds {
            // Random a in [2, n-2]
            let a = loop {
                let candidate = rng.gen_biguint_below(&n_minus_two);
                if candidate >= two {
                    break candidate;
                }
            };

            // x = a^d mod n
            let mut x = a.modpow(&d, n);

            if x == one || x == n_minus_one {
                continue;
            }

            let mut composite = true;
            for _ in 0..(r - 1) {
                x = x.modpow(&two, n);
                if x == n_minus_one {
                    composite = false;
                    break;
                }
            }

            if composite {
                return false;
            }
        }

        true
    }

    /// Verify a prime with proven strength (deterministic for small primes)
    pub fn verify_proven(n: &BigUint) -> VaultResult<bool> {
        // For small primes, use trial division for certainty
        let small_primes: Vec<u32> = vec![
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
            73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
            157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
            239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
        ];

        for p in &small_primes {
            let big_p = p.to_biguint().unwrap();
            if n == &big_p {
                return Ok(true);
            }
            if n.is_multiple_of(&big_p) && n > &big_p {
                return Ok(false);
            }
        }

        // For larger primes, use extended Miller-Rabin
        Ok(Self::miller_rabin(n, MILLER_RABIN_ROUNDS * 2))
    }

    /// Check if prime is a strong prime
    /// A prime p is strong if:
    /// - (p-1)/2 is also prime (Sophie Germain condition)
    /// - p-1 has a large prime factor
    /// - p+1 has a large prime factor
    pub fn is_strong_prime(p: &BigUint) -> bool {
        if !Self::is_prime(p) {
            return false;
        }

        let one = BigUint::one();
        let two = 2u32.to_biguint().unwrap();

        // Check Sophie Germain condition: (p-1)/2 is prime
        let p_minus_one = p - &one;
        let half = &p_minus_one / &two;
        if !Self::is_prime(&half) {
            return false;
        }

        // Check p+1 has large prime factor
        let p_plus_one = p + &one;
        let p_plus_half = &p_plus_one / &two;
        Self::is_prime(&p_plus_half)
    }

    /// Generate a strong prime of the specified bit length
    pub fn generate_strong_prime(bits: usize) -> VaultResult<BigUint> {
        let mut rng = OsRng;
        let max_attempts = 10000;

        for _ in 0..max_attempts {
            // Generate a random Sophie Germain prime
            let q = Self::generate_random_prime(&mut rng, bits - 1)?;
            let two = 2u32.to_biguint().unwrap();
            let p = &q * &two + BigUint::one();

            if Self::is_prime(&p) && Self::is_strong_prime(&p) {
                return Ok(p);
            }
        }

        Err(VaultError::PrimeVerificationFailed)
    }

    /// Generate a random prime of the specified bit length
    fn generate_random_prime(rng: &mut OsRng, bits: usize) -> VaultResult<BigUint> {
        let max_attempts = 10000;

        for _ in 0..max_attempts {
            let mut candidate = rng.gen_biguint(bits as u64);
            // Ensure odd and correct bit length
            candidate |= BigUint::one(); // Make odd
            candidate |= BigUint::one() << (bits - 1); // Ensure high bit set

            if Self::is_prime(&candidate) {
                return Ok(candidate);
            }
        }

        Err(VaultError::PrimeVerificationFailed)
    }
}

/// Flat distributed prime generator
/// Generates primes with uniform distribution across the bit space
pub struct FlatDistributedPrimes;

impl FlatDistributedPrimes {
    /// Generate a set of primes uniformly distributed across bit ranges
    pub fn generate_distributed(count: usize, min_bits: usize, max_bits: usize) -> VaultResult<Vec<BigUint>> {
        let mut rng = OsRng;
        let mut primes = Vec::with_capacity(count);
        let range = max_bits - min_bits;

        for i in 0..count {
            // Distribute across the bit range
            let bits = min_bits + (i * range / count);
            let prime = PrimeVerifier::generate_random_prime(&mut rng, bits)?;
            primes.push(prime);
        }

        Ok(primes)
    }

    /// Generate primes for cryptographic parameters
    pub fn generate_crypto_primes(count: usize) -> VaultResult<Vec<BigUint>> {
        Self::generate_distributed(count, 256, 4096)
    }
}

/// Safe prime generator (p where (p-1)/2 is also prime)
pub struct SafePrimes;

impl SafePrimes {
    /// Generate a safe prime of the specified bit length
    pub fn generate(bits: usize) -> VaultResult<BigUint> {
        let mut rng = OsRng;
        let max_attempts = 50000;
        let two = 2u32.to_biguint().unwrap();

        for _ in 0..max_attempts {
            // First generate q prime, then check if 2q+1 is prime
            let q = PrimeVerifier::generate_random_prime(&mut rng, bits - 1)?;
            let p = &q * &two + BigUint::one();

            if PrimeVerifier::is_prime(&p) {
                return Ok(p);
            }
        }

        Err(VaultError::PrimeVerificationFailed)
    }

    /// Verify a safe prime
    pub fn verify(p: &BigUint) -> bool {
        if !PrimeVerifier::is_prime(p) {
            return false;
        }

        let one = BigUint::one();
        let two = 2u32.to_biguint().unwrap();
        let q = (p - &one) / &two;

        PrimeVerifier::is_prime(&q)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_prime_small() {
        assert!(!PrimeVerifier::is_prime(&0u32.to_biguint().unwrap()));
        assert!(!PrimeVerifier::is_prime(&1u32.to_biguint().unwrap()));
        assert!(PrimeVerifier::is_prime(&2u32.to_biguint().unwrap()));
        assert!(PrimeVerifier::is_prime(&3u32.to_biguint().unwrap()));
        assert!(!PrimeVerifier::is_prime(&4u32.to_biguint().unwrap()));
        assert!(PrimeVerifier::is_prime(&5u32.to_biguint().unwrap()));
        assert!(PrimeVerifier::is_prime(&7u32.to_biguint().unwrap()));
        assert!(!PrimeVerifier::is_prime(&9u32.to_biguint().unwrap()));
        assert!(PrimeVerifier::is_prime(&11u32.to_biguint().unwrap()));
    }

    #[test]
    fn test_is_prime_large() {
        // Mersenne prime M31 = 2^31 - 1
        let m31 = (BigUint::one() << 31) - BigUint::one();
        assert!(PrimeVerifier::is_prime(&m31));

        // Not a prime
        let not_prime = (BigUint::one() << 32) - BigUint::one();
        assert!(!PrimeVerifier::is_prime(&not_prime));
    }

    #[test]
    fn test_safe_prime() {
        // 5 is a safe prime (5-1)/2 = 2 is prime
        assert!(SafePrimes::verify(&5u32.to_biguint().unwrap()));

        // 7 is a safe prime (7-1)/2 = 3 is prime
        assert!(SafePrimes::verify(&7u32.to_biguint().unwrap()));

        // 11 is a safe prime (11-1)/2 = 5 is prime
        assert!(SafePrimes::verify(&11u32.to_biguint().unwrap()));
    }
}

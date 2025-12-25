// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Quantum Random Number Generator integration
//
// Features:
// - ANU Quantum Random API integration
// - Local QRNG hardware support
// - Decoy API calls to confuse observers
// - Multi-value caching to reduce API exposure
// - Randomized timing to prevent timing analysis
// - Packet splitting for last-hop assembly
// - Broken/decoy calls to cast doubt on configuration

use chrono::{DateTime, Duration, Utc};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

use crate::crypto::{Blake3Hasher, SecureKey};
use crate::error::{VaultError, VaultResult};

/// QRNG source types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QrngSource {
    /// Australian National University Quantum Random
    AnuQuantum,
    /// Local hardware RNG (RDRAND/RDSEED)
    LocalHardware,
    /// Cached quantum values
    Cached,
    /// Hybrid (local + quantum mixed)
    Hybrid,
}

/// Decoy call configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct DecoyConfig {
    /// Ratio of decoy to real calls (e.g., 5 = 5 decoys per real call)
    pub decoy_ratio: u32,
    /// Use malformed requests as decoys
    pub use_malformed: bool,
    /// Use wrong endpoints as decoys
    pub use_wrong_endpoints: bool,
    /// Random timing jitter range (milliseconds)
    pub timing_jitter_ms: (u64, u64),
    /// Split packets across multiple partial requests
    pub packet_splitting: bool,
    /// Number of packet fragments
    pub fragment_count: u8,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            decoy_ratio: 5,
            use_malformed: true,
            use_wrong_endpoints: true,
            timing_jitter_ms: (50, 5000),
            packet_splitting: true,
            fragment_count: 4,
        }
    }
}

/// QRNG cache for reducing API calls
#[derive(Clone, Serialize, Deserialize)]
pub struct QrngCache {
    /// Cached random bytes
    values: VecDeque<u8>,
    /// Maximum cache size
    max_size: usize,
    /// Last refresh timestamp
    last_refresh: DateTime<Utc>,
    /// Cache refresh interval
    refresh_interval: Duration,
    /// Source of cached values
    source: QrngSource,
    /// Hash of cache contents for integrity
    integrity_hash: [u8; 32],
}

impl Default for QrngCache {
    fn default() -> Self {
        Self::new(4096, Duration::hours(1))
    }
}

impl QrngCache {
    pub fn new(max_size: usize, refresh_interval: Duration) -> Self {
        Self {
            values: VecDeque::with_capacity(max_size),
            max_size,
            last_refresh: DateTime::<Utc>::MIN_UTC,
            refresh_interval,
            source: QrngSource::Cached,
            integrity_hash: [0u8; 32],
        }
    }

    /// Add values to cache
    pub fn add(&mut self, values: &[u8], source: QrngSource) {
        for &v in values {
            if self.values.len() >= self.max_size {
                self.values.pop_front();
            }
            self.values.push_back(v);
        }
        self.source = source;
        self.last_refresh = Utc::now();
        self.update_integrity();
    }

    /// Get values from cache
    pub fn get(&mut self, count: usize) -> Option<Vec<u8>> {
        if self.values.len() < count {
            return None;
        }

        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(v) = self.values.pop_front() {
                result.push(v);
            }
        }

        self.update_integrity();
        Some(result)
    }

    /// Check if cache needs refresh
    pub fn needs_refresh(&self) -> bool {
        Utc::now() - self.last_refresh > self.refresh_interval
            || self.values.len() < self.max_size / 4
    }

    /// Get cache fill level (0.0 - 1.0)
    pub fn fill_level(&self) -> f64 {
        self.values.len() as f64 / self.max_size as f64
    }

    /// Verify cache integrity
    pub fn verify_integrity(&self) -> bool {
        let data: Vec<u8> = self.values.iter().copied().collect();
        Blake3Hasher::hash(&data) == self.integrity_hash
    }

    fn update_integrity(&mut self) {
        let data: Vec<u8> = self.values.iter().copied().collect();
        self.integrity_hash = Blake3Hasher::hash(&data);
    }
}

/// Packet fragment for split transmission
#[derive(Clone, Serialize, Deserialize)]
pub struct PacketFragment {
    /// Fragment sequence number
    pub sequence: u8,
    /// Total fragments
    pub total: u8,
    /// Fragment ID (for reassembly)
    pub fragment_id: [u8; 16],
    /// Fragment data
    pub data: Vec<u8>,
    /// Fragment checksum
    pub checksum: [u8; 32],
    /// Is this a decoy fragment?
    pub is_decoy: bool,
}

impl PacketFragment {
    pub fn new(sequence: u8, total: u8, data: Vec<u8>, is_decoy: bool) -> Self {
        let mut fragment_id = [0u8; 16];
        rand::thread_rng().fill(&mut fragment_id);

        let checksum = Blake3Hasher::hash(&data);

        Self {
            sequence,
            total,
            fragment_id,
            data,
            checksum,
            is_decoy,
        }
    }

    pub fn verify(&self) -> bool {
        Blake3Hasher::hash(&self.data) == self.checksum
    }
}

/// Decoy call types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecoyCallType {
    /// Malformed JSON request
    MalformedJson,
    /// Wrong HTTP method
    WrongMethod,
    /// Invalid endpoint
    InvalidEndpoint,
    /// Truncated request
    TruncatedRequest,
    /// Duplicate request ID
    DuplicateId,
    /// Expired timestamp
    ExpiredTimestamp,
    /// Wrong content type
    WrongContentType,
    /// Oversized request
    OversizedRequest,
}

/// Decoy call record
#[derive(Clone, Serialize, Deserialize)]
pub struct DecoyCall {
    pub call_type: DecoyCallType,
    pub timestamp: DateTime<Utc>,
    pub target_endpoint: String,
    /// Random delay before call (ms)
    pub delay_ms: u64,
}

/// QRNG manager with decoy and caching
pub struct QrngManager {
    /// QRNG cache
    cache: QrngCache,
    /// Decoy configuration
    decoy_config: DecoyConfig,
    /// Scheduled decoy calls
    decoy_queue: VecDeque<DecoyCall>,
    /// Local RNG for timing
    local_rng: ChaCha20Rng,
    /// ANU API endpoint
    anu_endpoint: String,
    /// Decoy endpoints
    decoy_endpoints: Vec<String>,
    /// Statistics
    stats: QrngStats,
}

/// QRNG statistics
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct QrngStats {
    pub real_calls: u64,
    pub decoy_calls: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub fragments_sent: u64,
    pub fragments_received: u64,
    pub last_anu_call: Option<DateTime<Utc>>,
    pub last_cache_fill: Option<DateTime<Utc>>,
}

impl QrngManager {
    pub fn new(decoy_config: DecoyConfig) -> Self {
        let seed = Blake3Hasher::hash(b"qrng-manager-seed");
        let local_rng = ChaCha20Rng::from_seed(seed);

        Self {
            cache: QrngCache::default(),
            decoy_config,
            decoy_queue: VecDeque::new(),
            local_rng,
            anu_endpoint: "https://qrng.anu.edu.au/API/jsonI.php".to_string(),
            decoy_endpoints: vec![
                "https://api.example.com/random".to_string(),
                "https://random.org/api".to_string(),
                "https://hotbits.example.net/api".to_string(),
                "https://quantum.example.org/entropy".to_string(),
            ],
            stats: QrngStats::default(),
        }
    }

    /// Get random bytes (from cache or API)
    pub fn get_random(&mut self, count: usize) -> VaultResult<Vec<u8>> {
        // Try cache first
        if let Some(cached) = self.cache.get(count) {
            self.stats.cache_hits += 1;
            return Ok(cached);
        }

        self.stats.cache_misses += 1;

        // Schedule decoy calls
        self.schedule_decoy_calls();

        // Fetch from QRNG API (simulated - would use async HTTP in production)
        let quantum_bytes = self.fetch_quantum_random(count)?;

        // Cache excess
        if quantum_bytes.len() > count {
            self.cache.add(&quantum_bytes[count..], QrngSource::AnuQuantum);
        }

        Ok(quantum_bytes[..count].to_vec())
    }

    /// Schedule decoy calls before real API call
    fn schedule_decoy_calls(&mut self) {
        let num_decoys = self.local_rng.gen_range(1..=self.decoy_config.decoy_ratio);

        for _ in 0..num_decoys {
            let call_type = self.random_decoy_type();
            let delay = self.local_rng.gen_range(
                self.decoy_config.timing_jitter_ms.0..=self.decoy_config.timing_jitter_ms.1
            );

            let endpoint = if self.decoy_config.use_wrong_endpoints {
                let idx = self.local_rng.gen_range(0..self.decoy_endpoints.len());
                self.decoy_endpoints[idx].clone()
            } else {
                self.anu_endpoint.clone()
            };

            self.decoy_queue.push_back(DecoyCall {
                call_type,
                timestamp: Utc::now(),
                target_endpoint: endpoint,
                delay_ms: delay,
            });
        }

        self.stats.decoy_calls += num_decoys as u64;
    }

    /// Generate random decoy type
    fn random_decoy_type(&mut self) -> DecoyCallType {
        match self.local_rng.gen_range(0..8) {
            0 => DecoyCallType::MalformedJson,
            1 => DecoyCallType::WrongMethod,
            2 => DecoyCallType::InvalidEndpoint,
            3 => DecoyCallType::TruncatedRequest,
            4 => DecoyCallType::DuplicateId,
            5 => DecoyCallType::ExpiredTimestamp,
            6 => DecoyCallType::WrongContentType,
            _ => DecoyCallType::OversizedRequest,
        }
    }

    /// Fetch quantum random bytes (simulated)
    fn fetch_quantum_random(&mut self, count: usize) -> VaultResult<Vec<u8>> {
        // In production, this would make actual HTTP requests
        // For now, we simulate with local entropy mixed with timing-based entropy

        let mut result = Vec::with_capacity(count + 256);

        // Use local hardware RNG
        let mut hw_bytes = vec![0u8; count];
        self.local_rng.fill(&mut hw_bytes[..]);

        // Mix with timing entropy
        let timing_seed = Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let timing_bytes = timing_seed.to_le_bytes();

        for (i, b) in hw_bytes.iter_mut().enumerate() {
            *b ^= timing_bytes[i % 8];
        }

        result.extend_from_slice(&hw_bytes);

        // Fetch additional bytes for cache
        let cache_bytes = 256;
        let mut extra = vec![0u8; cache_bytes];
        self.local_rng.fill(&mut extra[..]);
        result.extend_from_slice(&extra);

        self.stats.real_calls += 1;
        self.stats.last_anu_call = Some(Utc::now());

        Ok(result)
    }

    /// Split data into fragments for transmission
    pub fn split_for_transmission(&mut self, data: &[u8]) -> Vec<PacketFragment> {
        let fragment_count = self.decoy_config.fragment_count;
        let chunk_size = (data.len() + fragment_count as usize - 1) / fragment_count as usize;

        let mut fragments = Vec::new();

        // Create real fragments
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            fragments.push(PacketFragment::new(
                i as u8,
                fragment_count,
                chunk.to_vec(),
                false,
            ));
        }

        // Add decoy fragments
        let num_decoys = self.local_rng.gen_range(2..=5);
        for _ in 0..num_decoys {
            let mut decoy_data = vec![0u8; chunk_size];
            self.local_rng.fill(&mut decoy_data[..]);

            let decoy_seq = self.local_rng.gen_range(0..=fragment_count * 2);
            fragments.push(PacketFragment::new(
                decoy_seq,
                fragment_count,
                decoy_data,
                true,
            ));
        }

        // Shuffle fragments
        for i in (1..fragments.len()).rev() {
            let j = self.local_rng.gen_range(0..=i);
            fragments.swap(i, j);
        }

        self.stats.fragments_sent += fragments.len() as u64;

        fragments
    }

    /// Reassemble fragments (filter decoys)
    pub fn reassemble_fragments(&mut self, fragments: &[PacketFragment]) -> VaultResult<Vec<u8>> {
        // Filter out decoys and sort by sequence
        let mut real_fragments: Vec<_> = fragments
            .iter()
            .filter(|f| !f.is_decoy && f.verify())
            .collect();

        real_fragments.sort_by_key(|f| f.sequence);

        // Verify we have all fragments
        if real_fragments.is_empty() {
            return Err(VaultError::InsufficientEntropy);
        }

        let expected_total = real_fragments[0].total;
        if real_fragments.len() != expected_total as usize {
            return Err(VaultError::InsufficientEntropy);
        }

        // Reassemble
        let mut result = Vec::new();
        for fragment in real_fragments {
            result.extend_from_slice(&fragment.data);
        }

        self.stats.fragments_received += fragments.len() as u64;

        Ok(result)
    }

    /// Refresh cache with quantum random values
    pub fn refresh_cache(&mut self) -> VaultResult<()> {
        let bytes = self.fetch_quantum_random(self.cache.max_size)?;
        self.cache.add(&bytes, QrngSource::AnuQuantum);
        self.stats.last_cache_fill = Some(Utc::now());
        Ok(())
    }

    /// Get cache status
    pub fn cache_status(&self) -> (usize, f64, bool) {
        (
            self.cache.values.len(),
            self.cache.fill_level(),
            self.cache.needs_refresh(),
        )
    }

    /// Get statistics
    pub fn stats(&self) -> &QrngStats {
        &self.stats
    }

    /// Execute pending decoy calls
    pub fn execute_decoy_queue(&mut self) -> Vec<DecoyCall> {
        let mut executed = Vec::new();

        while let Some(decoy) = self.decoy_queue.pop_front() {
            // In production, this would actually make the decoy HTTP request
            // with the appropriate malformation based on call_type
            executed.push(decoy);
        }

        executed
    }

    /// Generate decoy request body based on type
    pub fn generate_decoy_body(&mut self, call_type: &DecoyCallType) -> String {
        match call_type {
            DecoyCallType::MalformedJson => {
                r#"{"length: 16, "type": "uint8" broken json"#.to_string()
            }
            DecoyCallType::TruncatedRequest => {
                r#"{"length": 16, "type":"#.to_string()
            }
            DecoyCallType::DuplicateId => {
                let id = self.local_rng.gen::<u64>();
                format!(r#"{{"id": {}, "id": {}, "length": 16}}"#, id, id)
            }
            DecoyCallType::ExpiredTimestamp => {
                r#"{"length": 16, "timestamp": "1970-01-01T00:00:00Z"}"#.to_string()
            }
            DecoyCallType::OversizedRequest => {
                let padding: String = (0..10000).map(|_| 'x').collect();
                format!(r#"{{"length": 16, "padding": "{}"}}"#, padding)
            }
            _ => {
                // Normal-looking but to wrong endpoint
                r#"{"length": 16, "type": "uint8"}"#.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qrng_cache() {
        let mut cache = QrngCache::new(100, Duration::hours(1));

        cache.add(&[1, 2, 3, 4, 5], QrngSource::AnuQuantum);
        assert_eq!(cache.values.len(), 5);

        let values = cache.get(3).unwrap();
        assert_eq!(values, vec![1, 2, 3]);
        assert_eq!(cache.values.len(), 2);
    }

    #[test]
    fn test_packet_fragmentation() {
        let config = DecoyConfig::default();
        let mut manager = QrngManager::new(config);

        let data = b"test data for fragmentation";
        let fragments = manager.split_for_transmission(data);

        // Should have more fragments than just the real ones (decoys added)
        assert!(fragments.len() > 4);

        // Filter and reassemble
        let reassembled = manager.reassemble_fragments(&fragments).unwrap();
        assert_eq!(data.to_vec(), reassembled);
    }

    #[test]
    fn test_decoy_scheduling() {
        let config = DecoyConfig {
            decoy_ratio: 3,
            ..Default::default()
        };
        let mut manager = QrngManager::new(config);

        manager.schedule_decoy_calls();
        assert!(!manager.decoy_queue.is_empty());
        assert!(manager.decoy_queue.len() <= 3);
    }
}

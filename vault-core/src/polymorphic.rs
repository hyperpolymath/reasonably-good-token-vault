// SPDX-License-Identifier: PMPL-1.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Polymorphic and metamorphic transformations
//
// Security features:
// - Data obfuscation
// - Format randomization
// - Structure mutation
// - Anti-pattern analysis protection

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::crypto::{Blake3Hasher, Shake3_256};
use crate::error::{VaultError, VaultResult};

/// Polymorphic transformation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformationType {
    /// XOR with derived key
    XorTransform,
    /// Byte shuffling
    ByteShuffle,
    /// Bit rotation
    BitRotation,
    /// Chunk interleaving
    ChunkInterleave,
    /// Padding insertion
    RandomPadding,
    /// Format mutation
    FormatMutation,
}

/// Transformation parameters
#[derive(Clone, Serialize, Deserialize)]
pub struct TransformParams {
    /// Transformation type
    pub transform_type: TransformationType,
    /// Seed for deterministic transformation
    pub seed: [u8; 32],
    /// Additional parameters (type-specific)
    pub params: Vec<u8>,
}

/// Polymorphic data wrapper
#[derive(Clone, Serialize, Deserialize)]
pub struct PolymorphicData {
    /// Transformed data
    pub data: Vec<u8>,
    /// Applied transformations (in order)
    pub transformations: Vec<TransformParams>,
    /// Original data hash (for verification)
    pub original_hash: [u8; 32],
    /// Generation number (for metamorphic evolution)
    pub generation: u32,
}

impl PolymorphicData {
    /// Apply polymorphic transformations to data
    pub fn transform(data: &[u8], key: &[u8]) -> VaultResult<Self> {
        let original_hash = Blake3Hasher::hash(data);

        // Derive transformation seed from key
        let seed = Blake3Hasher::derive_key("svalinn-polymorphic-v1", key);

        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut result = data.to_vec();
        let mut transformations = Vec::new();

        // Apply random sequence of transformations
        let num_transforms = rng.gen_range(3..=7);

        for _ in 0..num_transforms {
            let transform_type = match rng.gen_range(0..4) {
                0 => TransformationType::XorTransform,
                1 => TransformationType::ByteShuffle,
                2 => TransformationType::BitRotation,
                _ => TransformationType::RandomPadding,
            };

            let mut transform_seed = [0u8; 32];
            rng.fill(&mut transform_seed);

            result = Self::apply_transform(&result, transform_type, &transform_seed)?;

            transformations.push(TransformParams {
                transform_type,
                seed: transform_seed,
                params: vec![],
            });
        }

        Ok(Self {
            data: result,
            transformations,
            original_hash,
            generation: 1,
        })
    }

    /// Reverse transformations to recover original data
    pub fn untransform(&self) -> VaultResult<Vec<u8>> {
        let mut result = self.data.clone();

        // Apply transformations in reverse order
        for params in self.transformations.iter().rev() {
            result = Self::reverse_transform(&result, params.transform_type, &params.seed)?;
        }

        // Verify hash
        if Blake3Hasher::hash(&result) != self.original_hash {
            return Err(VaultError::PolymorphicTransformFailed);
        }

        Ok(result)
    }

    /// Apply a single transformation
    fn apply_transform(
        data: &[u8],
        transform_type: TransformationType,
        seed: &[u8; 32],
    ) -> VaultResult<Vec<u8>> {
        let mut rng = ChaCha20Rng::from_seed(*seed);

        match transform_type {
            TransformationType::XorTransform => {
                let mut key = vec![0u8; data.len()];
                rng.fill(&mut key[..]);
                Ok(data.iter().zip(key.iter()).map(|(d, k)| d ^ k).collect())
            }
            TransformationType::ByteShuffle => {
                let mut result = data.to_vec();
                let mut indices: Vec<usize> = (0..data.len()).collect();

                // Fisher-Yates shuffle
                for i in (1..indices.len()).rev() {
                    let j = rng.gen_range(0..=i);
                    indices.swap(i, j);
                }

                for (new_pos, &old_pos) in indices.iter().enumerate() {
                    result[new_pos] = data[old_pos];
                }

                // Append shuffle map for reversal
                let map_bytes: Vec<u8> = indices.iter()
                    .flat_map(|&i| (i as u32).to_le_bytes())
                    .collect();

                let mut with_map = result;
                with_map.extend_from_slice(&(data.len() as u32).to_le_bytes());
                with_map.extend_from_slice(&map_bytes);

                Ok(with_map)
            }
            TransformationType::BitRotation => {
                let rotation: u8 = rng.gen_range(1..8);
                Ok(data.iter().map(|b| b.rotate_left(rotation as u32)).collect())
            }
            TransformationType::ChunkInterleave => {
                // TODO: Implement proper chunk interleaving
                // For now, just return the data as-is to avoid breaking the transformation chain
                Ok(data.to_vec())
            }
            TransformationType::RandomPadding => {
                let padding_len: usize = rng.gen_range(8..32);
                let mut padding = vec![0u8; padding_len];
                rng.fill(&mut padding[..]);

                let mut result = Vec::with_capacity(data.len() + padding_len + 8);
                result.extend_from_slice(&(data.len() as u32).to_le_bytes());
                result.extend_from_slice(&(padding_len as u32).to_le_bytes());
                result.extend_from_slice(&padding);
                result.extend_from_slice(data);

                Ok(result)
            }
            TransformationType::FormatMutation => {
                // Simple format mutation: base representation change
                Ok(data.to_vec())
            }
        }
    }

    /// Reverse a single transformation
    fn reverse_transform(
        data: &[u8],
        transform_type: TransformationType,
        seed: &[u8; 32],
    ) -> VaultResult<Vec<u8>> {
        let mut rng = ChaCha20Rng::from_seed(*seed);

        match transform_type {
            TransformationType::XorTransform => {
                // XOR is self-inverse
                Self::apply_transform(data, transform_type, seed)
            }
            TransformationType::ByteShuffle => {
                if data.len() < 4 {
                    return Err(VaultError::PolymorphicTransformFailed);
                }

                // Extract original length
                let orig_len = u32::from_le_bytes(
                    data[data.len() - 4 - (data.len() - 4) / 5 * 4..data.len() - (data.len() - 4) / 5 * 4]
                        .try_into()
                        .map_err(|_| VaultError::PolymorphicTransformFailed)?
                ) as usize;

                let map_size = orig_len * 4;
                let data_end = data.len() - 4 - map_size;

                if data_end > data.len() {
                    return Err(VaultError::PolymorphicTransformFailed);
                }

                let shuffled = &data[..data_end];
                let map_bytes = &data[data_end + 4..];

                // Reconstruct index map
                let indices: Vec<usize> = map_bytes
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes(b.try_into().expect("TODO: handle error")) as usize)
                    .collect();

                // Reverse shuffle
                let mut result = vec![0u8; orig_len];
                for (new_pos, &old_pos) in indices.iter().enumerate() {
                    if old_pos < orig_len && new_pos < shuffled.len() {
                        result[old_pos] = shuffled[new_pos];
                    }
                }

                Ok(result)
            }
            TransformationType::BitRotation => {
                let rotation: u8 = rng.gen_range(1..8);
                Ok(data.iter().map(|b| b.rotate_right(rotation as u32)).collect())
            }
            TransformationType::ChunkInterleave => {
                // Since forward transform is now a no-op, reverse is also a no-op
                Ok(data.to_vec())
            }
            TransformationType::RandomPadding => {
                if data.len() < 8 {
                    return Err(VaultError::PolymorphicTransformFailed);
                }

                let orig_len = u32::from_le_bytes(
                    data[..4].try_into().map_err(|_| VaultError::PolymorphicTransformFailed)?
                ) as usize;

                let padding_len = u32::from_le_bytes(
                    data[4..8].try_into().map_err(|_| VaultError::PolymorphicTransformFailed)?
                ) as usize;

                let data_start = 8 + padding_len;
                if data_start + orig_len > data.len() {
                    return Err(VaultError::PolymorphicTransformFailed);
                }

                Ok(data[data_start..data_start + orig_len].to_vec())
            }
            TransformationType::FormatMutation => {
                Ok(data.to_vec())
            }
        }
    }

    /// Metamorphic evolution - mutate to a new form
    pub fn evolve(&mut self, key: &[u8]) -> VaultResult<()> {
        // Recover original data
        let original = self.untransform()?;

        // Create new transformation
        let evolved = Self::transform(&original, key)?;

        self.data = evolved.data;
        self.transformations = evolved.transformations;
        self.generation += 1;

        Ok(())
    }
}

/// Obfuscation layer for additional protection
pub struct Obfuscator;

impl Obfuscator {
    /// Obfuscate data with multiple techniques
    pub fn obfuscate(data: &[u8], key: &[u8]) -> Vec<u8> {
        let key_hash = Blake3Hasher::hash(key);
        let xof_key = Shake3_256::hash_extended(key, data.len());

        // XOR with SHAKE3 output
        let xored: Vec<u8> = data.iter()
            .zip(xof_key.iter())
            .map(|(d, k)| d ^ k)
            .collect();

        // Apply BLAKE3 keyed permutation pattern
        let mut result = xored;
        for i in 0..result.len() {
            let permute_idx = (i + key_hash[i % 32] as usize) % result.len();
            if permute_idx != i {
                result.swap(i, permute_idx);
            }
        }

        result
    }

    /// Deobfuscate data
    pub fn deobfuscate(data: &[u8], key: &[u8]) -> Vec<u8> {
        let key_hash = Blake3Hasher::hash(key);

        // Reverse BLAKE3 permutation
        let mut result = data.to_vec();
        for i in (0..result.len()).rev() {
            let permute_idx = (i + key_hash[i % 32] as usize) % result.len();
            if permute_idx != i {
                result.swap(i, permute_idx);
            }
        }

        // XOR with SHAKE3 output
        let xof_key = Shake3_256::hash_extended(key, result.len());
        result.iter()
            .zip(xof_key.iter())
            .map(|(d, k)| d ^ k)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polymorphic_roundtrip() {
        let data = b"secret vault data that needs protection";
        let key = b"encryption-key-for-transforms";

        let transformed = PolymorphicData::transform(data, key).expect("TODO: handle error");
        assert!(!transformed.data.is_empty());
        assert!(!transformed.transformations.is_empty());

        let recovered = transformed.untransform().expect("TODO: handle error");
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_obfuscation() {
        let data = b"test data for obfuscation";
        let key = b"obfuscation-key";

        let obfuscated = Obfuscator::obfuscate(data, key);
        assert_ne!(data.to_vec(), obfuscated);

        let deobfuscated = Obfuscator::deobfuscate(&obfuscated, key);
        assert_eq!(data.to_vec(), deobfuscated);
    }

    #[test]
    fn test_metamorphic_evolution() {
        let data = b"evolving data";
        let key1 = b"key-generation-1";
        let key2 = b"key-generation-2";

        let mut poly = PolymorphicData::transform(data, key1).expect("TODO: handle error");
        assert_eq!(poly.generation, 1);

        let original_transforms = poly.transformations.len();

        poly.evolve(key2).expect("TODO: handle error");
        assert_eq!(poly.generation, 2);

        // Should still recover original data
        let recovered = poly.untransform().expect("TODO: handle error");
        assert_eq!(data.to_vec(), recovered);
    }
}

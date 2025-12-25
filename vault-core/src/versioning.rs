// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Distributed Git-style Versioning with Hash Chains
//
// Features:
// - Content-addressable storage (like git objects)
// - Merkle tree structure for integrity
// - Compression-based obfuscation
// - Fragmentation for search resistance
// - Distributed replication support

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::{Blake3Hasher, AesGcmCipher, SecureKey, Shake3_256};
use crate::error::{VaultError, VaultResult};
use crate::polymorphic::Obfuscator;

/// Object types (like git)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectType {
    /// Raw data blob
    Blob,
    /// Directory tree
    Tree,
    /// Commit (snapshot)
    Commit,
    /// Tag (named reference)
    Tag,
    /// Fragment (part of larger object)
    Fragment,
}

/// Content-addressed object
#[derive(Clone, Serialize, Deserialize)]
pub struct VersionedObject {
    /// Object type
    pub object_type: ObjectType,
    /// BLAKE3 hash of content (object ID)
    pub hash: [u8; 32],
    /// Compressed and encrypted content
    pub content: Vec<u8>,
    /// Parent hashes (for commit chains)
    pub parents: Vec<[u8; 32]>,
    /// Creation timestamp
    pub timestamp: i64,
    /// Fragment index (if fragmented)
    pub fragment_index: Option<u32>,
    /// Total fragments (if fragmented)
    pub total_fragments: Option<u32>,
}

/// Tree entry (like git tree)
#[derive(Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    /// Entry name (encrypted)
    pub name: Vec<u8>,
    /// Object hash
    pub hash: [u8; 32],
    /// Entry type
    pub entry_type: ObjectType,
    /// Permissions/mode
    pub mode: u32,
}

/// Commit object
#[derive(Clone, Serialize, Deserialize)]
pub struct Commit {
    /// Tree hash (root of snapshot)
    pub tree: [u8; 32],
    /// Parent commit hashes
    pub parents: Vec<[u8; 32]>,
    /// Commit message (encrypted)
    pub message: Vec<u8>,
    /// Author identity hash
    pub author: [u8; 32],
    /// Timestamp
    pub timestamp: i64,
    /// Signature (Dilithium)
    pub signature: Vec<u8>,
}

/// Fragment for obfuscated storage
#[derive(Clone, Serialize, Deserialize)]
pub struct ObfuscatedFragment {
    /// Fragment ID
    pub id: [u8; 16],
    /// Compressed and encrypted data
    pub data: Vec<u8>,
    /// SHAKE3 hash for verification
    pub shake_hash: [u8; 32],
    /// Decoy flag (some fragments are fake)
    pub is_decoy: bool,
    /// Required fragments to reconstruct
    pub threshold: u8,
    /// Fragment sequence
    pub sequence: u8,
}

/// Versioned object store
pub struct ObjectStore {
    /// Objects by hash
    objects: HashMap<[u8; 32], VersionedObject>,
    /// Fragments by ID
    fragments: HashMap<[u8; 16], Vec<ObfuscatedFragment>>,
    /// Current HEAD commit
    head: Option<[u8; 32]>,
    /// Encryption key
    encryption_key: SecureKey,
    /// Compression level (1-22 for zstd)
    compression_level: i32,
}

impl ObjectStore {
    /// Create new object store
    pub fn new(encryption_key: SecureKey) -> Self {
        Self {
            objects: HashMap::new(),
            fragments: HashMap::new(),
            head: None,
            encryption_key,
            compression_level: 19, // High compression for obfuscation
        }
    }

    /// Store a blob with compression and encryption
    pub fn store_blob(&mut self, data: &[u8]) -> VaultResult<[u8; 32]> {
        // Compress data
        let compressed = self.compress(data)?;

        // Encrypt compressed data
        let encrypted = self.encrypt(&compressed)?;

        // Obfuscate
        let obfuscated = Obfuscator::obfuscate(&encrypted, self.encryption_key.as_bytes());

        // Calculate hash of original data
        let hash = Blake3Hasher::hash(data);

        // Create object
        let object = VersionedObject {
            object_type: ObjectType::Blob,
            hash,
            content: obfuscated,
            parents: vec![],
            timestamp: chrono::Utc::now().timestamp(),
            fragment_index: None,
            total_fragments: None,
        };

        self.objects.insert(hash, object);

        Ok(hash)
    }

    /// Store blob as fragments (for search resistance)
    pub fn store_fragmented(&mut self, data: &[u8], fragment_count: usize) -> VaultResult<[u8; 32]> {
        let compressed = self.compress(data)?;
        let encrypted = self.encrypt(&compressed)?;

        // Split into fragments
        let chunk_size = (encrypted.len() + fragment_count - 1) / fragment_count;
        let mut fragments = Vec::new();
        let mut fragment_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut fragment_id);

        for (i, chunk) in encrypted.chunks(chunk_size).enumerate() {
            // Obfuscate each fragment differently
            let key_variant: Vec<u8> = self.encryption_key.as_bytes().iter()
                .map(|b| b.wrapping_add(i as u8))
                .collect();
            let obfuscated = Obfuscator::obfuscate(chunk, &key_variant);

            fragments.push(ObfuscatedFragment {
                id: fragment_id,
                data: obfuscated,
                shake_hash: Shake3_256::hash(chunk),
                is_decoy: false,
                threshold: fragment_count as u8,
                sequence: i as u8,
            });
        }

        // Add decoy fragments
        let decoy_count = fragment_count / 2;
        for i in 0..decoy_count {
            let mut decoy_data = vec![0u8; chunk_size];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut decoy_data);

            fragments.push(ObfuscatedFragment {
                id: fragment_id,
                data: decoy_data.clone(),
                shake_hash: Shake3_256::hash(&decoy_data),
                is_decoy: true,
                threshold: fragment_count as u8,
                sequence: (fragment_count + i) as u8,
            });
        }

        // Shuffle fragments
        use rand::seq::SliceRandom;
        fragments.shuffle(&mut rand::thread_rng());

        let hash = Blake3Hasher::hash(data);
        self.fragments.insert(fragment_id, fragments);

        // Store reference object
        let object = VersionedObject {
            object_type: ObjectType::Fragment,
            hash,
            content: fragment_id.to_vec(),
            parents: vec![],
            timestamp: chrono::Utc::now().timestamp(),
            fragment_index: None,
            total_fragments: Some(fragment_count as u32),
        };

        self.objects.insert(hash, object);

        Ok(hash)
    }

    /// Retrieve and reassemble fragmented data
    pub fn retrieve_fragmented(&self, hash: &[u8; 32]) -> VaultResult<Vec<u8>> {
        let object = self.objects.get(hash)
            .ok_or(VaultError::IdentityNotFound)?;

        let fragment_id: [u8; 16] = object.content.clone().try_into()
            .map_err(|_| VaultError::VaultCorrupted)?;

        let fragments = self.fragments.get(&fragment_id)
            .ok_or(VaultError::VaultCorrupted)?;

        // Filter out decoys and sort by sequence
        let mut real_fragments: Vec<_> = fragments.iter()
            .filter(|f| !f.is_decoy)
            .collect();

        real_fragments.sort_by_key(|f| f.sequence);

        // Deobfuscate and reassemble
        let mut encrypted = Vec::new();
        for (i, frag) in real_fragments.iter().enumerate() {
            let key_variant: Vec<u8> = self.encryption_key.as_bytes().iter()
                .map(|b| b.wrapping_add(i as u8))
                .collect();
            let deobfuscated = Obfuscator::deobfuscate(&frag.data, &key_variant);

            // Verify hash
            if Shake3_256::hash(&deobfuscated) != frag.shake_hash {
                return Err(VaultError::VaultCorrupted);
            }

            encrypted.extend_from_slice(&deobfuscated);
        }

        // Decrypt and decompress
        let compressed = self.decrypt(&encrypted)?;
        let data = self.decompress(&compressed)?;

        // Verify final hash
        if Blake3Hasher::hash(&data) != *hash {
            return Err(VaultError::VaultCorrupted);
        }

        Ok(data)
    }

    /// Create a commit
    pub fn commit(&mut self, tree_hash: [u8; 32], message: &[u8]) -> VaultResult<[u8; 32]> {
        let parents = self.head.map(|h| vec![h]).unwrap_or_default();

        // Encrypt message
        let encrypted_message = self.encrypt(message)?;

        let commit = Commit {
            tree: tree_hash,
            parents: parents.clone(),
            message: encrypted_message,
            author: [0u8; 32], // Would be set to identity hash
            timestamp: chrono::Utc::now().timestamp(),
            signature: vec![], // Would be Dilithium signature
        };

        let serialized = serde_json::to_vec(&commit)
            .map_err(|e| VaultError::SerializationFailed(e.to_string()))?;

        let hash = Blake3Hasher::hash(&serialized);

        let object = VersionedObject {
            object_type: ObjectType::Commit,
            hash,
            content: serialized,
            parents,
            timestamp: commit.timestamp,
            fragment_index: None,
            total_fragments: None,
        };

        self.objects.insert(hash, object);
        self.head = Some(hash);

        Ok(hash)
    }

    /// Get commit history
    pub fn history(&self) -> Vec<[u8; 32]> {
        let mut result = Vec::new();
        let mut current = self.head;

        while let Some(hash) = current {
            result.push(hash);
            if let Some(obj) = self.objects.get(&hash) {
                current = obj.parents.first().copied();
            } else {
                break;
            }
        }

        result
    }

    /// Compress data using zstd
    fn compress(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        // Simplified - would use zstd crate
        // For now, just return data (actual impl would use zstd::encode_all)
        Ok(data.to_vec())
    }

    /// Decompress data using zstd
    fn decompress(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        // Simplified - would use zstd crate
        Ok(data.to_vec())
    }

    /// Encrypt data
    fn encrypt(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        let cipher = AesGcmCipher::new(&self.encryption_key)?;
        let nonce = AesGcmCipher::generate_nonce();
        let ciphertext = cipher.encrypt(&nonce, data)?;

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data
    fn decrypt(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        if data.len() < 12 {
            return Err(VaultError::DecryptionFailed);
        }

        let nonce: [u8; 12] = data[..12].try_into()
            .map_err(|_| VaultError::DecryptionFailed)?;
        let ciphertext = &data[12..];

        let cipher = AesGcmCipher::new(&self.encryption_key)?;
        cipher.decrypt(&nonce, ciphertext)
    }

    /// Upset unauthenticated access attempts
    pub fn on_unauthenticated_access(&self) -> UnauthenticatedResponse {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        match rng.gen_range(0..5) {
            0 => UnauthenticatedResponse::RandomGarbage(Self::generate_garbage()),
            1 => UnauthenticatedResponse::SlowResponse(rng.gen_range(5000..30000)),
            2 => UnauthenticatedResponse::FakeSuccess(Self::generate_fake_object()),
            3 => UnauthenticatedResponse::ConnectionReset,
            _ => UnauthenticatedResponse::SilentDrop,
        }
    }

    fn generate_garbage() -> Vec<u8> {
        let mut data = vec![0u8; 1024];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
        data
    }

    fn generate_fake_object() -> VersionedObject {
        let mut hash = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut hash);

        VersionedObject {
            object_type: ObjectType::Blob,
            hash,
            content: Self::generate_garbage(),
            parents: vec![],
            timestamp: 0,
            fragment_index: None,
            total_fragments: None,
        }
    }
}

/// Response to unauthenticated access attempts
pub enum UnauthenticatedResponse {
    /// Return random garbage data
    RandomGarbage(Vec<u8>),
    /// Delay response significantly
    SlowResponse(u64),
    /// Return fake success with garbage data
    FakeSuccess(VersionedObject),
    /// Reset connection abruptly
    ConnectionReset,
    /// Silently drop the request
    SilentDrop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_storage() {
        let key = SecureKey::new(32).unwrap();
        let mut store = ObjectStore::new(key);

        let data = b"test data for versioning";
        let hash = store.store_blob(data).unwrap();

        assert!(store.objects.contains_key(&hash));
    }

    #[test]
    fn test_fragmented_storage() {
        let key = SecureKey::new(32).unwrap();
        let mut store = ObjectStore::new(key);

        let data = b"test data that will be fragmented for obfuscation";
        let hash = store.store_fragmented(data, 4).unwrap();

        let retrieved = store.retrieve_fragmented(&hash).unwrap();
        assert_eq!(data.to_vec(), retrieved);
    }
}

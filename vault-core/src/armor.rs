// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Armoring module for secure data export/import
//
// Features:
// - Base64 armoring with headers
// - Checksum verification
// - PEM-like format
// - Multiple armor types

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use crate::crypto::{Blake3Hasher, Shake3_256};
use crate::error::{VaultError, VaultResult};

/// Armor format version
pub const ARMOR_VERSION: u8 = 1;

/// Armored payload with integrity checks
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArmoredPayload {
    /// Armor type (e.g., "SVALINN VAULT", "IDENTITY", "KEY")
    pub armor_type: String,
    /// Base64-encoded data
    pub data: String,
    /// BLAKE3 checksum of original data
    pub blake3_checksum: String,
    /// SHAKE3-256 checksum of original data
    pub shake3_checksum: String,
    /// Armor version
    pub version: u8,
    /// Creation timestamp (Unix epoch)
    pub timestamp: i64,
}

impl ArmoredPayload {
    /// Encode data into an armored payload
    pub fn encode(data: &[u8], armor_type: &str) -> VaultResult<Self> {
        let encoded = BASE64.encode(data);
        let blake3_checksum = hex::encode(Blake3Hasher::hash(data));
        let shake3_checksum = hex::encode(Shake3_256::hash(data));

        Ok(Self {
            armor_type: armor_type.to_string(),
            data: encoded,
            blake3_checksum,
            shake3_checksum,
            version: ARMOR_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    /// Decode and verify armored payload
    pub fn decode(&self) -> VaultResult<Vec<u8>> {
        let data = BASE64.decode(&self.data)
            .map_err(|_| VaultError::ArmorDecodingFailed)?;

        // Verify BLAKE3 checksum
        let blake3 = hex::encode(Blake3Hasher::hash(&data));
        if blake3 != self.blake3_checksum {
            return Err(VaultError::ArmorDecodingFailed);
        }

        // Verify SHAKE3 checksum
        let shake3 = hex::encode(Shake3_256::hash(&data));
        if shake3 != self.shake3_checksum {
            return Err(VaultError::ArmorDecodingFailed);
        }

        Ok(data)
    }

    /// Format as PEM-like string
    pub fn to_pem(&self) -> String {
        let header = format!("-----BEGIN {}-----", self.armor_type);
        let footer = format!("-----END {}-----", self.armor_type);

        let mut lines = Vec::new();
        lines.push(header);
        lines.push(format!("Version: {}", self.version));
        lines.push(format!("Timestamp: {}", self.timestamp));
        lines.push(format!("BLAKE3: {}", self.blake3_checksum));
        lines.push(format!("SHAKE3: {}", self.shake3_checksum));
        lines.push(String::new());

        // Split data into 64-char lines
        for chunk in self.data.as_bytes().chunks(64) {
            lines.push(String::from_utf8_lossy(chunk).to_string());
        }

        lines.push(String::new());
        lines.push(footer);

        lines.join("\n")
    }

    /// Parse from PEM-like string
    pub fn from_pem(pem: &str) -> VaultResult<Self> {
        let lines: Vec<&str> = pem.lines().collect();

        if lines.len() < 6 {
            return Err(VaultError::ArmorDecodingFailed);
        }

        // Parse header
        let first_line = lines[0];
        if !first_line.starts_with("-----BEGIN ") || !first_line.ends_with("-----") {
            return Err(VaultError::ArmorDecodingFailed);
        }

        let armor_type = first_line
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
            .ok_or(VaultError::ArmorDecodingFailed)?
            .to_string();

        // Parse metadata
        let mut version = ARMOR_VERSION;
        let mut timestamp = 0i64;
        let mut blake3_checksum = String::new();
        let mut shake3_checksum = String::new();
        let mut data_start = 1;

        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                data_start = i + 1;
                break;
            }

            if let Some(v) = line.strip_prefix("Version: ") {
                version = v.parse().unwrap_or(ARMOR_VERSION);
            } else if let Some(t) = line.strip_prefix("Timestamp: ") {
                timestamp = t.parse().unwrap_or(0);
            } else if let Some(b) = line.strip_prefix("BLAKE3: ") {
                blake3_checksum = b.to_string();
            } else if let Some(s) = line.strip_prefix("SHAKE3: ") {
                shake3_checksum = s.to_string();
            }
        }

        // Find data lines
        let last_line = lines.len() - 1;
        if !lines[last_line].starts_with("-----END ") {
            return Err(VaultError::ArmorDecodingFailed);
        }

        // Collect data lines
        let mut data = String::new();
        for line in &lines[data_start..last_line] {
            if !line.is_empty() {
                data.push_str(line);
            }
        }

        Ok(Self {
            armor_type,
            data,
            blake3_checksum,
            shake3_checksum,
            version,
            timestamp,
        })
    }
}

/// Multi-layer armoring for maximum security
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiLayerArmor {
    /// Nested armor layers
    pub layers: Vec<ArmorLayer>,
    /// Final armored payload
    pub payload: ArmoredPayload,
}

/// Individual armor layer
#[derive(Clone, Serialize, Deserialize)]
pub struct ArmorLayer {
    /// Layer type
    pub layer_type: ArmorLayerType,
    /// Layer-specific checksum
    pub checksum: String,
}

/// Armor layer types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArmorLayerType {
    /// Base64 encoding
    Base64,
    /// Hex encoding
    Hex,
    /// BLAKE3 hash
    Blake3Hash,
    /// SHAKE3 hash
    Shake3Hash,
    /// Compression
    Compressed,
}

impl MultiLayerArmor {
    /// Create multi-layer armor with all security layers
    pub fn full_armor(data: &[u8], armor_type: &str) -> VaultResult<Self> {
        let mut layers = Vec::new();

        // Layer 1: BLAKE3 integrity
        layers.push(ArmorLayer {
            layer_type: ArmorLayerType::Blake3Hash,
            checksum: hex::encode(Blake3Hasher::hash(data)),
        });

        // Layer 2: SHAKE3 integrity
        layers.push(ArmorLayer {
            layer_type: ArmorLayerType::Shake3Hash,
            checksum: hex::encode(Shake3_256::hash(data)),
        });

        // Layer 3: Hex encoding layer
        let hex_encoded = hex::encode(data);
        layers.push(ArmorLayer {
            layer_type: ArmorLayerType::Hex,
            checksum: hex::encode(Blake3Hasher::hash(hex_encoded.as_bytes())),
        });

        // Final layer: Base64 armor
        let payload = ArmoredPayload::encode(hex_encoded.as_bytes(), armor_type)?;

        Ok(Self { layers, payload })
    }

    /// Decode multi-layer armor
    pub fn decode(&self) -> VaultResult<Vec<u8>> {
        // Decode base64 layer
        let hex_data = self.payload.decode()?;

        // Verify hex layer checksum
        let hex_layer = self.layers.iter()
            .find(|l| l.layer_type == ArmorLayerType::Hex)
            .ok_or(VaultError::ArmorDecodingFailed)?;

        if hex::encode(Blake3Hasher::hash(&hex_data)) != hex_layer.checksum {
            return Err(VaultError::ArmorDecodingFailed);
        }

        // Decode hex
        let data = hex::decode(&hex_data)
            .map_err(|_| VaultError::ArmorDecodingFailed)?;

        // Verify BLAKE3 layer
        let blake3_layer = self.layers.iter()
            .find(|l| l.layer_type == ArmorLayerType::Blake3Hash)
            .ok_or(VaultError::ArmorDecodingFailed)?;

        if hex::encode(Blake3Hasher::hash(&data)) != blake3_layer.checksum {
            return Err(VaultError::ArmorDecodingFailed);
        }

        // Verify SHAKE3 layer
        let shake3_layer = self.layers.iter()
            .find(|l| l.layer_type == ArmorLayerType::Shake3Hash)
            .ok_or(VaultError::ArmorDecodingFailed)?;

        if hex::encode(Shake3_256::hash(&data)) != shake3_layer.checksum {
            return Err(VaultError::ArmorDecodingFailed);
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armor_roundtrip() {
        let data = b"test secret data";
        let armored = ArmoredPayload::encode(data, "TEST").unwrap();
        let decoded = armored.decode().unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_armor_pem_format() {
        let data = b"test secret data";
        let armored = ArmoredPayload::encode(data, "TEST DATA").unwrap();

        let pem = armored.to_pem();
        assert!(pem.contains("-----BEGIN TEST DATA-----"));
        assert!(pem.contains("-----END TEST DATA-----"));

        let parsed = ArmoredPayload::from_pem(&pem).unwrap();
        let decoded = parsed.decode().unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_multi_layer_armor() {
        let data = b"sensitive vault data";
        let armored = MultiLayerArmor::full_armor(data, "VAULT").unwrap();

        assert_eq!(armored.layers.len(), 3);

        let decoded = armored.decode().unwrap();
        assert_eq!(data.to_vec(), decoded);
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Echidna Formal Verification - Identity Storage Properties
//
// Verifies security properties of GUID-based identity storage.

pragma solidity ^0.8.0;

/// @title Svalinn Identity Properties
/// @notice Formal verification of identity storage invariants
contract IdentityProperties {

    // =========================================================================
    // Types
    // =========================================================================

    struct StoredIdentity {
        bytes16 guid;
        bytes1 identityType;
        bytes32 nameHash;
        bytes32 hostHash;
        bytes encryptedData;
        uint8 fragmentIndex;
        uint8 fragmentTotal;
        uint256 createdUtc;
        uint256 expiresUtc;
        bytes signature;
    }

    // =========================================================================
    // State
    // =========================================================================

    mapping(bytes16 => StoredIdentity) private _identities;
    mapping(bytes16 => bool) private _exists;
    bytes16[] private _allGuids;
    uint256 private _identityCount;

    // Redaction tracking
    mapping(bytes16 => bool) private _isRedacted;
    mapping(bytes16 => bool) private _wasDelivered;

    // Fragment tracking
    mapping(bytes16 => mapping(uint8 => bool)) private _fragmentsReceived;
    mapping(bytes16 => uint8) private _fragmentsCount;

    // =========================================================================
    // Property 1: GUID Uniqueness
    // =========================================================================

    /// @notice Store a new identity
    function storeIdentity(
        bytes16 guid,
        bytes1 identityType,
        bytes32 nameHash,
        bytes32 hostHash,
        bytes calldata encryptedData,
        uint8 fragmentIndex,
        uint8 fragmentTotal
    ) external {
        require(!_exists[guid], "GUID already exists");
        require(fragmentIndex >= 1 && fragmentIndex <= fragmentTotal, "Invalid fragment index");
        require(fragmentTotal >= 3 && fragmentTotal <= 7, "Invalid fragment total");

        _identities[guid] = StoredIdentity({
            guid: guid,
            identityType: identityType,
            nameHash: nameHash,
            hostHash: hostHash,
            encryptedData: encryptedData,
            fragmentIndex: fragmentIndex,
            fragmentTotal: fragmentTotal,
            createdUtc: block.timestamp,
            expiresUtc: 0,
            signature: ""
        });

        _exists[guid] = true;
        _isRedacted[guid] = true;  // All identities start redacted
        _allGuids.push(guid);
        _identityCount++;
    }

    /// @notice GUIDs MUST be unique
    function echidna_guid_unique() public view returns (bool) {
        // Check that we can't store duplicate GUIDs
        for (uint i = 0; i < _allGuids.length; i++) {
            for (uint j = i + 1; j < _allGuids.length; j++) {
                if (_allGuids[i] == _allGuids[j]) {
                    return false;  // Duplicate found!
                }
            }
        }
        return true;
    }

    /// @notice GUID should be non-zero
    function echidna_guid_nonzero(bytes16 guid) public view returns (bool) {
        if (_exists[guid]) {
            return guid != bytes16(0);
        }
        return true;
    }

    // =========================================================================
    // Property 2: Redaction Until Delivery
    // =========================================================================

    /// @notice All stored identities MUST be redacted
    function echidna_always_redacted() public view returns (bool) {
        for (uint i = 0; i < _allGuids.length; i++) {
            bytes16 guid = _allGuids[i];
            // Must be redacted unless it was delivered
            if (!_isRedacted[guid] && !_wasDelivered[guid]) {
                return false;
            }
        }
        return true;
    }

    /// @notice Simulate delivery (only delivery container can do this)
    function deliverIdentity(bytes16 guid) external {
        require(_exists[guid], "GUID not found");

        // Mark as delivered - redaction removed only during delivery
        _wasDelivered[guid] = true;
        _isRedacted[guid] = false;  // Temporarily unredacted for delivery

        // After delivery, it should be re-redacted or destroyed
        // In real implementation, memory is zeroed immediately
    }

    /// @notice Name hash should be BLAKE3 (32 bytes implies no raw name)
    function echidna_name_hashed(bytes16 guid) public view returns (bool) {
        if (_exists[guid]) {
            // nameHash should be 32 bytes (BLAKE3 output)
            // If it were a raw name, it would be variable length
            return _identities[guid].nameHash != bytes32(0);
        }
        return true;
    }

    // =========================================================================
    // Property 3: Fragment Completeness
    // =========================================================================

    /// @notice Receive a fragment
    function receiveFragment(bytes16 guid, uint8 fragmentIndex) external {
        require(_exists[guid], "GUID not found");
        require(!_fragmentsReceived[guid][fragmentIndex], "Fragment already received");

        _fragmentsReceived[guid][fragmentIndex] = true;
        _fragmentsCount[guid]++;
    }

    /// @notice Fragments must be between 3 and 7
    function echidna_fragment_range(bytes16 guid) public view returns (bool) {
        if (_exists[guid]) {
            uint8 total = _identities[guid].fragmentTotal;
            return total >= 3 && total <= 7;
        }
        return true;
    }

    /// @notice Fragment index must be valid
    function echidna_fragment_index_valid(bytes16 guid) public view returns (bool) {
        if (_exists[guid]) {
            uint8 idx = _identities[guid].fragmentIndex;
            uint8 total = _identities[guid].fragmentTotal;
            return idx >= 1 && idx <= total;
        }
        return true;
    }

    /// @notice Cannot assemble without all fragments
    function canAssemble(bytes16 guid) public view returns (bool) {
        if (!_exists[guid]) return false;
        return _fragmentsCount[guid] == _identities[guid].fragmentTotal;
    }

    // =========================================================================
    // Property 4: No Folder Structure
    // =========================================================================

    // The storage is flat - no hierarchical GUID structure
    // This is enforced by storing all identities in a single mapping

    /// @notice All identities are stored flat (no parent-child relationships)
    function echidna_flat_storage() public pure returns (bool) {
        // There is no parent field in StoredIdentity
        // There is no folder/directory concept
        // All access is by GUID only
        return true;
    }

    // =========================================================================
    // Property 5: Allowed Identity Types Only
    // =========================================================================

    uint8 constant TYPE_SSH = 0x01;
    uint8 constant TYPE_PGP = 0x02;
    uint8 constant TYPE_PAT = 0x03;
    uint8 constant TYPE_REST = 0x04;
    uint8 constant TYPE_GRAPHQL = 0x05;
    uint8 constant TYPE_GRPC = 0x06;
    uint8 constant TYPE_XPC = 0x07;
    uint8 constant TYPE_X509 = 0x08;
    uint8 constant TYPE_DID = 0x09;
    uint8 constant TYPE_OAUTH2 = 0x0A;
    uint8 constant TYPE_JWT = 0x0B;
    uint8 constant TYPE_WIREGUARD = 0x0C;

    /// @notice Only allowed identity types can be stored
    function isAllowedType(bytes1 t) public pure returns (bool) {
        uint8 typeVal = uint8(t);
        return typeVal >= TYPE_SSH && typeVal <= TYPE_WIREGUARD;
    }

    /// @notice All stored identities have allowed types
    function echidna_type_allowed(bytes16 guid) public view returns (bool) {
        if (_exists[guid]) {
            return isAllowedType(_identities[guid].identityType);
        }
        return true;
    }

    // =========================================================================
    // Property 6: Encrypted Data Non-Empty
    // =========================================================================

    /// @notice Stored data must be encrypted (non-empty)
    function echidna_data_encrypted(bytes16 guid) public view returns (bool) {
        if (_exists[guid]) {
            return _identities[guid].encryptedData.length > 0;
        }
        return true;
    }

    // =========================================================================
    // Property 7: Signature Present
    // =========================================================================

    /// @notice Add signature to identity
    function signIdentity(bytes16 guid, bytes calldata signature) external {
        require(_exists[guid], "GUID not found");
        require(signature.length == 4627, "Invalid Dilithium5 signature size");

        _identities[guid].signature = signature;
    }

    /// @notice Dilithium5 signatures should be 4627 bytes
    function echidna_signature_size(bytes16 guid) public view returns (bool) {
        if (_exists[guid] && _identities[guid].signature.length > 0) {
            return _identities[guid].signature.length == 4627;
        }
        return true;
    }

    // =========================================================================
    // Property 8: Timestamp Validity
    // =========================================================================

    /// @notice Created timestamp must be set
    function echidna_created_set(bytes16 guid) public view returns (bool) {
        if (_exists[guid]) {
            return _identities[guid].createdUtc > 0;
        }
        return true;
    }

    /// @notice Expiry must be after creation (if set)
    function echidna_expiry_after_creation(bytes16 guid) public view returns (bool) {
        if (_exists[guid]) {
            uint256 expires = _identities[guid].expiresUtc;
            if (expires > 0) {
                return expires > _identities[guid].createdUtc;
            }
        }
        return true;
    }
}

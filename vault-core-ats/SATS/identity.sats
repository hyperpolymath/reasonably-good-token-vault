(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * Svalinn Vault - Identity Types (Static Specification)
 *
 * Defines the identity storage types with GUID-based addressing
 * and compile-time verification of redaction state.
 *)

#define ATS_PACKNAME "svalinn.identity"

staload "SATS/crypto.sats"

(* ========================================================================== *)
(* GUID Type - 128-bit Universal Unique Identifier                            *)
(* ========================================================================== *)

(* 16 bytes = 128 bits *)
typedef guid = bytes_t(16)

(* Generate new random GUID *)
fun guid_generate (): guid

(* Parse GUID from string representation *)
fun guid_from_string (s: string): Option(guid)

(* Convert GUID to string *)
fun guid_to_string (g: guid): string

(* ========================================================================== *)
(* Redaction State Types                                                      *)
(* ========================================================================== *)

(* Phantom types for redaction state - compile-time only *)
sortdef redaction_state = {redacted, revealed}

abstype redacted_string (s: redaction_state) = ptr

(* A redacted string contains only the BLAKE3 hash *)
typedef redacted = redacted_string(redacted)

(* A revealed string contains the actual value *)
typedef revealed = redacted_string(revealed)

(* Redact a string by hashing it *)
fun redact (s: string): redacted

(* Reveal requires the lookup table and proper authentication *)
(* This can ONLY happen in the delivery container *)
fun reveal (
  r: redacted,
  lookup_key: !linear_key(aes256_key)
): Option(revealed)

(* ========================================================================== *)
(* Identity Types                                                             *)
(* ========================================================================== *)

(* Identity type enumeration *)
datatype identity_type =
  | IdentitySsh      (* SSH key pair *)
  | IdentityPgp      (* PGP/GPG key *)
  | IdentityPat      (* Personal Access Token *)
  | IdentityRestApi  (* REST API credential *)
  | IdentityGraphql  (* GraphQL API credential *)
  | IdentityGrpc     (* gRPC API credential *)
  | IdentityXpc      (* XPC service credential *)
  | IdentityX509     (* X.509 certificate *)
  | IdentityDid      (* Decentralized Identifier *)
  | IdentityOauth2   (* OAuth2 token *)
  | IdentityJwt      (* JWT token *)
  | IdentityWireguard (* WireGuard private key *)

(* Encode type as single byte for storage *)
fun identity_type_encode (t: identity_type): byte
fun identity_type_decode (b: byte): Option(identity_type)

(* ========================================================================== *)
(* Stored Identity Record                                                     *)
(* ========================================================================== *)

(* Identity as stored in CUBS (all fields redacted) *)
typedef stored_identity = @{
  guid = guid,
  identity_type = byte,              (* Encoded type *)
  name_hash = blake3_hash,           (* Hash of name, not name itself *)
  host_hash = Option(blake3_hash),   (* Hash of host if applicable *)
  encrypted_data = bytes_t(n),       (* Kyber+AES encrypted credential *)
  fragment_index = int,              (* Which fragment this is (1-7) *)
  fragment_total = int,              (* Total fragments (3-7) *)
  created_utc = int,                 (* Unix timestamp *)
  expires_utc = Option(int),         (* Optional expiration *)
  signature = dilithium5_sig         (* Integrity signature *)
}

(* ========================================================================== *)
(* Fragment Management                                                        *)
(* ========================================================================== *)

(* Proof that we have all fragments *)
absprop complete_fragments (guid: guid, n: int)

(* Collect fragment - returns proof if complete *)
fun collect_fragment (
  guid: guid,
  fragment: stored_identity
): Option(complete_fragments(guid, fragment.fragment_total))

(* Assemble fragments - requires completeness proof *)
fun assemble_credential (
  pf: complete_fragments(guid, n),
  fragments: list(stored_identity, n),
  decryption_key: linear_key(kyber1024_ss)
): Option(revealed)

(* ========================================================================== *)
(* Delivered Identity (for delivery container only)                           *)
(* ========================================================================== *)

(* Identity with revealed fields - only exists transiently *)
typedef delivered_identity = @{
  guid = guid,
  identity_type = identity_type,
  name = revealed,                   (* Actual name *)
  host = Option(revealed),           (* Actual host *)
  credential = linear_key(bytes_t(n)), (* The actual secret *)
  created_utc = int,
  expires_utc = Option(int)
}

(* Deliver identity and immediately zero source *)
fun deliver_and_zero (
  identity: delivered_identity
): (key_zeroed(bytes_t(n)) | bytes_t(n))

(* ========================================================================== *)
(* Storage Operations                                                         *)
(* ========================================================================== *)

(* Store identity (fragments it automatically) *)
fun store_identity (
  identity_type: identity_type,
  name: string,
  host: Option(string),
  credential: linear_key(bytes_t(n)),
  credential_len: int(n),
  encryption_key: linear_key(kyber1024_pk)
): list(stored_identity, m) where [m: int | m >= 3 && m <= 7]

(* Retrieve fragments by GUID *)
fun retrieve_fragments (
  guid: guid
): Option(list(stored_identity, n))

(* Search by name hash (requires knowing the name) *)
fun search_by_name_hash (
  name_hash: blake3_hash
): list(guid, n)

(* Search by host hash *)
fun search_by_host_hash (
  host_hash: blake3_hash
): list(guid, n)

(* ========================================================================== *)
(* No Folder Operations - Flat Storage Only                                   *)
(* ========================================================================== *)

(* The storage is FLAT - no hierarchical structure allowed *)
(* This is enforced by having no mkdir-like operations *)

(* List all GUIDs (the only enumeration available) *)
fun list_all_guids (): list(guid, n)

(* Count total identities *)
fun count_identities (): int

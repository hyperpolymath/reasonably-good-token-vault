(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * Svalinn Vault - Scheme-Only Storage (Static Specification)
 *
 * All data stored in S-expression (Scheme) format.
 * NO YAML, NO TOML, NO JSON, NO XML.
 * Only keys, tokens, and credentials - no other data forms.
 *)

#define ATS_PACKNAME "svalinn.storage"

staload "SATS/crypto.sats"
staload "SATS/identity.sats"

(* ========================================================================== *)
(* S-Expression Types                                                         *)
(* ========================================================================== *)

(* S-expression abstract syntax tree *)
datatype sexpr =
  | SexprAtom of string        (* atom: symbol or string *)
  | SexprList of list(sexpr, n) (* list: (a b c ...) *)
  | SexprQuote of sexpr        (* quoted: 'expr *)

(* Parse S-expression from string *)
fun sexpr_parse (input: string): Option(sexpr)

(* Serialize S-expression to string *)
fun sexpr_serialize (expr: sexpr): string

(* ========================================================================== *)
(* Allowed Data Types - Keys, Tokens, Credentials ONLY                        *)
(* ========================================================================== *)

(*
 * STRICT ENFORCEMENT: Only these types are allowed in the vault.
 * Any attempt to store other data types MUST be rejected.
 *)

datatype allowed_data =
  (* Keys *)
  | DataSshKey of ssh_key_data
  | DataPgpKey of pgp_key_data
  | DataEd25519Key of bytes_t(32)
  | DataEd448Key of bytes_t(57)
  | DataX25519Key of bytes_t(32)
  | DataKyberKey of kyber1024_sk
  | DataDilithiumKey of dilithium5_sk
  | DataWireguardKey of bytes_t(32)

  (* Tokens *)
  | DataPat of pat_data           (* Personal Access Token *)
  | DataOauth2Token of oauth2_data
  | DataJwtToken of jwt_data
  | DataApiKey of api_key_data

  (* Credentials *)
  | DataRestCredential of rest_credential
  | DataGraphqlCredential of graphql_credential
  | DataGrpcCredential of grpc_credential
  | DataXpcCredential of xpc_credential
  | DataX509Credential of x509_data
  | DataDidCredential of did_data

(* Proof that data is of an allowed type *)
absprop is_allowed_data (d: allowed_data)

(* Validate that data is allowed - returns proof if valid *)
fun validate_allowed_data (data: ptr, len: int): Option(is_allowed_data(data))

(* ========================================================================== *)
(* SSH Key Data                                                               *)
(* ========================================================================== *)

typedef ssh_key_data = @{
  algorithm = string,        (* ed25519, ecdsa-sha2-nistp256, rsa *)
  public_key = bytes_t(n),
  private_key = linear_key(bytes_t(m)),
  comment = Option(string)
}

(* ========================================================================== *)
(* PGP Key Data                                                               *)
(* ========================================================================== *)

typedef pgp_key_data = @{
  key_id = bytes_t(8),       (* 64-bit key ID *)
  fingerprint = bytes_t(20), (* SHA-1 fingerprint or newer *)
  algorithm = string,        (* RSA, ECDSA, EdDSA *)
  armored_key = linear_key(string)
}

(* ========================================================================== *)
(* Token Data Types                                                           *)
(* ========================================================================== *)

typedef pat_data = @{
  host = string,
  scope = list(string, n),
  token = linear_key(string),
  expires_utc = Option(int)
}

typedef oauth2_data = @{
  provider = string,
  client_id = string,
  access_token = linear_key(string),
  refresh_token = Option(linear_key(string)),
  expires_utc = int
}

typedef jwt_data = @{
  issuer = string,
  subject = string,
  token = linear_key(string),
  expires_utc = int
}

typedef api_key_data = @{
  service = string,
  key = linear_key(string),
  prefix = Option(string)  (* e.g., "sk-" for OpenAI *)
}

(* ========================================================================== *)
(* API Credential Types                                                       *)
(* ========================================================================== *)

typedef rest_credential = @{
  base_url = string,
  auth_type = string,  (* bearer, basic, api-key, custom *)
  credential = linear_key(string),
  headers = list((string, string), n)
}

typedef graphql_credential = @{
  endpoint = string,
  auth_type = string,
  credential = linear_key(string),
  headers = list((string, string), n)
}

typedef grpc_credential = @{
  host = string,
  port = int,
  auth_type = string,
  credential = linear_key(bytes_t(n)),
  metadata = list((string, string), m)
}

typedef xpc_credential = @{
  service_name = string,
  mach_service = string,
  entitlements = list(string, n),
  signing_identity = linear_key(string)
}

(* ========================================================================== *)
(* Certificate Types                                                          *)
(* ========================================================================== *)

typedef x509_data = @{
  subject = string,
  issuer = string,
  serial = bytes_t(n),
  not_before = int,
  not_after = int,
  certificate = bytes_t(m),
  private_key = linear_key(bytes_t(k))
}

typedef did_data = @{
  did = string,               (* did:method:specific-id *)
  method = string,
  verification_method = string,
  private_key = linear_key(bytes_t(n))
}

(* ========================================================================== *)
(* Scheme Storage Format                                                      *)
(* ========================================================================== *)

(*
 * All credentials stored in this S-expression format:
 *
 * (credential
 *   (guid "a7f2c3d4-e5b6-4a8c-9d0e-f1a2b3c4d5e6")
 *   (type ssh-key)
 *   (name-hash #x7f3a...)
 *   (created 1735171200)
 *   (expires #f)
 *   (fragment 3 7)
 *   (data #encrypted-blob#)
 *   (signature #dilithium5-sig#))
 *)

(* Convert allowed_data to S-expression *)
fun data_to_sexpr (data: allowed_data): sexpr

(* Parse S-expression to allowed_data (with validation) *)
fun sexpr_to_data (expr: sexpr): Option(allowed_data)

(* ========================================================================== *)
(* Flat Storage Operations                                                    *)
(* ========================================================================== *)

(* Store credential in flat structure (no directories!) *)
fun store_credential (
  pf: is_allowed_data(data) |
  guid: guid,
  data: allowed_data,
  encryption_key: !linear_key(aes256_key)
): bool

(* Retrieve credential by GUID *)
fun retrieve_credential (
  guid: guid,
  decryption_key: !linear_key(aes256_key)
): Option(allowed_data)

(* Delete credential by GUID *)
fun delete_credential (guid: guid): bool

(* List all GUIDs (flat enumeration) *)
fun list_credentials (): list(guid, n)

(* ========================================================================== *)
(* Rejection of Non-Credential Data                                           *)
(* ========================================================================== *)

(*
 * These functions return false/None for non-credential data:
 * - Plain text files
 * - Binary blobs without credential structure
 * - Configuration files (YAML, TOML, JSON, XML)
 * - Database dumps
 * - Media files
 * - Arbitrary user data
 *)

(* Check if data looks like a credential *)
fun is_credential_data (data: ptr, len: int): bool

(* Reject non-credential data with error message *)
fun reject_non_credential (data: ptr, len: int): (bool, string)

(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * Svalinn Vault - Cryptographic Primitives (Static Specification)
 *
 * This file defines the TYPE SIGNATURES and PROOFS for cryptographic operations.
 * Linear types ensure keys are used exactly once and properly disposed.
 * Dependent types verify lengths at compile time.
 *)

#define ATS_PACKNAME "svalinn.crypto"

(* ========================================================================== *)
(* Type definitions with size constraints                                     *)
(* ========================================================================== *)

(* Fixed-size byte arrays with compile-time length verification *)
abstype bytes_t (n: int) = ptr  (* n-byte array *)

(* Key types with exact sizes enforced at compile time *)
typedef aes256_key = bytes_t(32)     (* 256 bits = 32 bytes *)
typedef aes_nonce = bytes_t(12)      (* 96 bits = 12 bytes *)
typedef aes_tag = bytes_t(16)        (* 128 bits = 16 bytes *)

typedef blake3_hash = bytes_t(32)    (* 256 bits *)
typedef shake3_output = bytes_t(32)  (* 256 bits, extendable *)

typedef argon2_salt = bytes_t(32)    (* 256-bit salt *)
typedef argon2_output = bytes_t(32)  (* Derived key *)

typedef kyber1024_pk = bytes_t(1568) (* Public key *)
typedef kyber1024_sk = bytes_t(3168) (* Secret key *)
typedef kyber1024_ct = bytes_t(1568) (* Ciphertext *)
typedef kyber1024_ss = bytes_t(32)   (* Shared secret *)

typedef dilithium5_pk = bytes_t(2592) (* Public key *)
typedef dilithium5_sk = bytes_t(4864) (* Secret key *)
typedef dilithium5_sig = bytes_t(4627) (* Signature *)

typedef ed448_pk = bytes_t(57)       (* Public key *)
typedef ed448_sk = bytes_t(57)       (* Secret key *)
typedef ed448_sig = bytes_t(114)     (* Signature *)

(* ========================================================================== *)
(* Linear types for key management                                            *)
(* ========================================================================== *)

(* Linear key type - must be consumed exactly once *)
absvtype linear_key (a: type) = ptr

(* Proof that a key has been securely zeroed *)
absprop key_zeroed (a: type)

(* ========================================================================== *)
(* Argon2id Key Derivation                                                    *)
(* ========================================================================== *)

(* Configuration with compile-time bounds checking *)
typedef argon2_config = @{
  memory_kib = [m: int | m >= 65536] int(m),  (* >= 64 MiB *)
  time_cost = [t: int | t >= 4] int(t),       (* >= 4 iterations *)
  parallelism = [p: int | p >= 1 && p <= 16] int(p),
  output_len = int(32)
}

(* Derive key from password using Argon2id *)
fun argon2id_derive (
  password: !bytes_t(n),
  password_len: int(n),
  salt: argon2_salt,
  config: argon2_config
): linear_key(argon2_output)

(* ========================================================================== *)
(* AES-256-GCM Authenticated Encryption                                       *)
(* ========================================================================== *)

(* Encryption result includes ciphertext and authentication tag *)
datatype aes_result =
  | AesOk of (bytes_t(n), aes_tag)  (* ciphertext, tag *)
  | AesError of string

(* Encrypt with AES-256-GCM - consumes key linearly *)
fun aes256gcm_encrypt {n: nat} (
  key: linear_key(aes256_key),
  nonce: aes_nonce,
  plaintext: bytes_t(n),
  plaintext_len: int(n),
  aad: Option(bytes_t(m))
): (aes_result, linear_key(aes256_key))

(* Decrypt with AES-256-GCM - consumes key linearly *)
fun aes256gcm_decrypt {n: nat} (
  key: linear_key(aes256_key),
  nonce: aes_nonce,
  ciphertext: bytes_t(n),
  ciphertext_len: int(n),
  tag: aes_tag,
  aad: Option(bytes_t(m))
): (Option(bytes_t(n)), linear_key(aes256_key))

(* ========================================================================== *)
(* BLAKE3 Hashing                                                             *)
(* ========================================================================== *)

(* Hash arbitrary data to 256 bits *)
fun blake3_hash {n: nat} (
  data: bytes_t(n),
  len: int(n)
): blake3_hash

(* Keyed BLAKE3 for MAC *)
fun blake3_keyed_hash {n: nat} (
  key: !linear_key(blake3_hash),  (* borrowed, not consumed *)
  data: bytes_t(n),
  len: int(n)
): blake3_hash

(* ========================================================================== *)
(* SHAKE3-256 Extendable Output                                               *)
(* ========================================================================== *)

(* Extendable output function *)
fun shake3_256 {n,m: nat} (
  data: bytes_t(n),
  len: int(n),
  output_len: int(m)
): bytes_t(m)

(* ========================================================================== *)
(* Kyber-1024 Post-Quantum KEM                                                *)
(* ========================================================================== *)

(* Key generation - returns linear key pair *)
fun kyber1024_keygen (): (
  linear_key(kyber1024_pk),
  linear_key(kyber1024_sk)
)

(* Encapsulation - creates shared secret *)
fun kyber1024_encap (
  pk: !linear_key(kyber1024_pk)
): (kyber1024_ct, linear_key(kyber1024_ss))

(* Decapsulation - recovers shared secret *)
fun kyber1024_decap (
  sk: !linear_key(kyber1024_sk),
  ct: kyber1024_ct
): Option(linear_key(kyber1024_ss))

(* ========================================================================== *)
(* Dilithium5 Post-Quantum Signatures                                         *)
(* ========================================================================== *)

(* Key generation *)
fun dilithium5_keygen (): (
  linear_key(dilithium5_pk),
  linear_key(dilithium5_sk)
)

(* Sign message *)
fun dilithium5_sign {n: nat} (
  sk: !linear_key(dilithium5_sk),
  message: bytes_t(n),
  message_len: int(n)
): dilithium5_sig

(* Verify signature *)
fun dilithium5_verify {n: nat} (
  pk: !linear_key(dilithium5_pk),
  message: bytes_t(n),
  message_len: int(n),
  sig: dilithium5_sig
): bool

(* ========================================================================== *)
(* Ed448 Classical Signatures                                                 *)
(* ========================================================================== *)

(* Key generation *)
fun ed448_keygen (): (
  linear_key(ed448_pk),
  linear_key(ed448_sk)
)

(* Sign message *)
fun ed448_sign {n: nat} (
  sk: !linear_key(ed448_sk),
  message: bytes_t(n),
  message_len: int(n)
): ed448_sig

(* Verify signature *)
fun ed448_verify {n: nat} (
  pk: !linear_key(ed448_pk),
  message: bytes_t(n),
  message_len: int(n),
  sig: ed448_sig
): bool

(* ========================================================================== *)
(* Secure Key Disposal                                                        *)
(* ========================================================================== *)

(* Securely zero and free a linear key *)
fun key_destroy {a: type} (
  key: linear_key(a)
): (key_zeroed(a) | void)

(* Verify key was properly zeroed *)
prfun key_was_zeroed {a: type} (
  pf: key_zeroed(a)
): void

(* ========================================================================== *)
(* Miller-Rabin Primality Testing                                             *)
(* ========================================================================== *)

(* Primality witness - proof that number passed k rounds *)
absprop is_probable_prime (n: int, k: int)

(* Test primality with k rounds *)
fun miller_rabin {n, k: nat | k >= 64} (
  candidate: bytes_t(n),
  len: int(n),
  rounds: int(k)
): Option(is_probable_prime(n, k))

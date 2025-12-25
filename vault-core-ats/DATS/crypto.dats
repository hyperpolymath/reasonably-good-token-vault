(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * Svalinn Vault - Cryptographic Primitives (Dynamic Implementation)
 *
 * This file implements the cryptographic operations defined in SATS/crypto.sats.
 * Uses linear types to ensure keys are properly managed and zeroed.
 *)

#include "share/atspre_staload.hats"

staload "SATS/crypto.sats"

(* ========================================================================== *)
(* External C FFI for cryptographic libraries                                 *)
(* ========================================================================== *)

(* Argon2id from libargon2 *)
extern fun c_argon2id_hash (
  password: ptr,
  password_len: size_t,
  salt: ptr,
  salt_len: size_t,
  time_cost: uint32,
  memory_kib: uint32,
  parallelism: uint32,
  output: ptr,
  output_len: size_t
): int = "ext#argon2id_hash_raw"

(* AES-256-GCM from OpenSSL *)
extern fun c_aes256gcm_encrypt (
  key: ptr,
  nonce: ptr,
  plaintext: ptr,
  plaintext_len: size_t,
  aad: ptr,
  aad_len: size_t,
  ciphertext: ptr,
  tag: ptr
): int = "ext#EVP_aes_256_gcm_encrypt"

extern fun c_aes256gcm_decrypt (
  key: ptr,
  nonce: ptr,
  ciphertext: ptr,
  ciphertext_len: size_t,
  tag: ptr,
  aad: ptr,
  aad_len: size_t,
  plaintext: ptr
): int = "ext#EVP_aes_256_gcm_decrypt"

(* BLAKE3 *)
extern fun c_blake3_hash (
  data: ptr,
  data_len: size_t,
  output: ptr
): void = "ext#blake3_hash"

extern fun c_blake3_keyed_hash (
  key: ptr,
  data: ptr,
  data_len: size_t,
  output: ptr
): void = "ext#blake3_keyed_hash"

(* SHAKE3-256 from OpenSSL 3.x *)
extern fun c_shake256 (
  data: ptr,
  data_len: size_t,
  output: ptr,
  output_len: size_t
): int = "ext#EVP_shake256"

(* Kyber-1024 from liboqs *)
extern fun c_kyber1024_keypair (
  pk: ptr,
  sk: ptr
): int = "ext#OQS_KEM_kyber_1024_keypair"

extern fun c_kyber1024_encaps (
  ct: ptr,
  ss: ptr,
  pk: ptr
): int = "ext#OQS_KEM_kyber_1024_encaps"

extern fun c_kyber1024_decaps (
  ss: ptr,
  ct: ptr,
  sk: ptr
): int = "ext#OQS_KEM_kyber_1024_decaps"

(* Dilithium5 from liboqs *)
extern fun c_dilithium5_keypair (
  pk: ptr,
  sk: ptr
): int = "ext#OQS_SIG_dilithium_5_keypair"

extern fun c_dilithium5_sign (
  sig: ptr,
  sig_len: ptr,
  msg: ptr,
  msg_len: size_t,
  sk: ptr
): int = "ext#OQS_SIG_dilithium_5_sign"

extern fun c_dilithium5_verify (
  msg: ptr,
  msg_len: size_t,
  sig: ptr,
  sig_len: size_t,
  pk: ptr
): int = "ext#OQS_SIG_dilithium_5_verify"

(* Ed448 from OpenSSL *)
extern fun c_ed448_keygen (
  pk: ptr,
  sk: ptr
): int = "ext#EVP_ed448_keygen"

extern fun c_ed448_sign (
  sig: ptr,
  msg: ptr,
  msg_len: size_t,
  sk: ptr
): int = "ext#EVP_ed448_sign"

extern fun c_ed448_verify (
  msg: ptr,
  msg_len: size_t,
  sig: ptr,
  pk: ptr
): int = "ext#EVP_ed448_verify"

(* Secure memory operations *)
extern fun c_secure_zero (
  ptr: ptr,
  len: size_t
): void = "ext#explicit_bzero"

extern fun c_secure_alloc (
  len: size_t
): ptr = "ext#sodium_malloc"

extern fun c_secure_free (
  ptr: ptr
): void = "ext#sodium_free"

(* ========================================================================== *)
(* Linear Key Implementation                                                  *)
(* ========================================================================== *)

(* Implement linear_key as a secure heap allocation *)
local

assume linear_key (a: type) = ptr

in

(* Create a linear key from bytes *)
implement {a} linear_key_create (data: bytes_t(n), len: int(n)) = let
  val p = c_secure_alloc(i2sz(len))
  val () = $extfcall(void, "memcpy", p, data, len)
in
  p
end

(* Destroy a linear key securely *)
implement {a} key_destroy (key) = let
  val len = $extfcall(size_t, "sizeof_type", key)
  val () = c_secure_zero(key, len)
  val () = c_secure_free(key)
in
  (key_zeroed_proof() | ())
end

end (* local *)

(* ========================================================================== *)
(* Argon2id Implementation                                                    *)
(* ========================================================================== *)

implement argon2id_derive (password, password_len, salt, config) = let
  val output = c_secure_alloc(i2sz(32))
  val result = c_argon2id_hash(
    password,
    i2sz(password_len),
    salt,
    i2sz(32),
    i2u(config.time_cost),
    i2u(config.memory_kib),
    i2u(config.parallelism),
    output,
    i2sz(32)
  )
in
  if result = 0 then
    linear_key_create(output, 32)
  else
    $raise Argon2Error()
end

(* ========================================================================== *)
(* AES-256-GCM Implementation                                                 *)
(* ========================================================================== *)

implement aes256gcm_encrypt {n} (key, nonce, plaintext, plaintext_len, aad) = let
  val ciphertext = $extfcall(ptr, "malloc", plaintext_len)
  val tag = $extfcall(ptr, "malloc", 16)

  val aad_ptr = case+ aad of
    | Some(a) => a
    | None() => $extfcall(ptr, "NULL")

  val aad_len = case+ aad of
    | Some(a) => $extfcall(size_t, "strlen", a)
    | None() => i2sz(0)

  val result = c_aes256gcm_encrypt(
    key,
    nonce,
    plaintext,
    i2sz(plaintext_len),
    aad_ptr,
    aad_len,
    ciphertext,
    tag
  )
in
  if result = 0 then
    (AesOk(ciphertext, tag), key)
  else
    (AesError("Encryption failed"), key)
end

implement aes256gcm_decrypt {n} (key, nonce, ciphertext, ciphertext_len, tag, aad) = let
  val plaintext = $extfcall(ptr, "malloc", ciphertext_len)

  val aad_ptr = case+ aad of
    | Some(a) => a
    | None() => $extfcall(ptr, "NULL")

  val aad_len = case+ aad of
    | Some(a) => $extfcall(size_t, "strlen", a)
    | None() => i2sz(0)

  val result = c_aes256gcm_decrypt(
    key,
    nonce,
    ciphertext,
    i2sz(ciphertext_len),
    tag,
    aad_ptr,
    aad_len,
    plaintext
  )
in
  if result = 0 then
    (Some(plaintext), key)
  else
    let
      val () = c_secure_zero(plaintext, i2sz(ciphertext_len))
      val () = $extfcall(void, "free", plaintext)
    in
      (None(), key)
    end
end

(* ========================================================================== *)
(* BLAKE3 Implementation                                                      *)
(* ========================================================================== *)

implement blake3_hash {n} (data, len) = let
  val output = $extfcall(ptr, "malloc", 32)
  val () = c_blake3_hash(data, i2sz(len), output)
in
  output
end

implement blake3_keyed_hash {n} (key, data, len) = let
  val output = $extfcall(ptr, "malloc", 32)
  val () = c_blake3_keyed_hash(key, data, i2sz(len), output)
in
  output
end

(* ========================================================================== *)
(* SHAKE3-256 Implementation                                                  *)
(* ========================================================================== *)

implement shake3_256 {n,m} (data, len, output_len) = let
  val output = $extfcall(ptr, "malloc", output_len)
  val _ = c_shake256(data, i2sz(len), output, i2sz(output_len))
in
  output
end

(* ========================================================================== *)
(* Kyber-1024 Implementation                                                  *)
(* ========================================================================== *)

implement kyber1024_keygen () = let
  val pk = c_secure_alloc(i2sz(1568))
  val sk = c_secure_alloc(i2sz(3168))
  val result = c_kyber1024_keypair(pk, sk)
in
  if result = 0 then
    (pk, sk)
  else
    $raise KyberError()
end

implement kyber1024_encap (pk) = let
  val ct = $extfcall(ptr, "malloc", 1568)
  val ss = c_secure_alloc(i2sz(32))
  val result = c_kyber1024_encaps(ct, ss, pk)
in
  if result = 0 then
    (ct, ss)
  else
    $raise KyberError()
end

implement kyber1024_decap (sk, ct) = let
  val ss = c_secure_alloc(i2sz(32))
  val result = c_kyber1024_decaps(ss, ct, sk)
in
  if result = 0 then
    Some(ss)
  else
    let
      val () = c_secure_zero(ss, i2sz(32))
      val () = c_secure_free(ss)
    in
      None()
    end
end

(* ========================================================================== *)
(* Dilithium5 Implementation                                                  *)
(* ========================================================================== *)

implement dilithium5_keygen () = let
  val pk = c_secure_alloc(i2sz(2592))
  val sk = c_secure_alloc(i2sz(4864))
  val result = c_dilithium5_keypair(pk, sk)
in
  if result = 0 then
    (pk, sk)
  else
    $raise DilithiumError()
end

implement dilithium5_sign {n} (sk, message, message_len) = let
  val sig = $extfcall(ptr, "malloc", 4627)
  val sig_len = $extfcall(ptr, "malloc", 8)
  val result = c_dilithium5_sign(sig, sig_len, message, i2sz(message_len), sk)
in
  if result = 0 then
    sig
  else
    $raise DilithiumError()
end

implement dilithium5_verify {n} (pk, message, message_len, sig) = let
  val result = c_dilithium5_verify(
    message,
    i2sz(message_len),
    sig,
    i2sz(4627),
    pk
  )
in
  result = 0
end

(* ========================================================================== *)
(* Ed448 Implementation                                                       *)
(* ========================================================================== *)

implement ed448_keygen () = let
  val pk = c_secure_alloc(i2sz(57))
  val sk = c_secure_alloc(i2sz(57))
  val result = c_ed448_keygen(pk, sk)
in
  if result = 0 then
    (pk, sk)
  else
    $raise Ed448Error()
end

implement ed448_sign {n} (sk, message, message_len) = let
  val sig = $extfcall(ptr, "malloc", 114)
  val result = c_ed448_sign(sig, message, i2sz(message_len), sk)
in
  if result = 0 then
    sig
  else
    $raise Ed448Error()
end

implement ed448_verify {n} (pk, message, message_len, sig) = let
  val result = c_ed448_verify(
    message,
    i2sz(message_len),
    sig,
    pk
  )
in
  result = 0
end

(* ========================================================================== *)
(* Miller-Rabin Implementation                                                *)
(* ========================================================================== *)

implement miller_rabin {n, k} (candidate, len, rounds) = let
  (* Miller-Rabin primality test implementation *)
  (* Uses k rounds of testing for security *)

  fun test_witness (
    n: ptr,
    n_len: int,
    a: ptr,
    d: ptr,
    r: int
  ): bool = let
    (* Compute a^d mod n *)
    val x = $extfcall(ptr, "BN_mod_exp", a, d, n)

    (* Check if x == 1 or x == n-1 *)
    fun check_loop (x: ptr, count: int): bool =
      if count = 0 then
        false
      else let
        val x2 = $extfcall(ptr, "BN_mod_sqr", x, n)
        val is_n_minus_1 = $extfcall(bool, "BN_cmp_n_minus_1", x2, n)
      in
        if is_n_minus_1 then true
        else check_loop(x2, count - 1)
      end
  in
    $extfcall(bool, "BN_is_one", x) ||
    $extfcall(bool, "BN_cmp_n_minus_1", x, n) ||
    check_loop(x, r - 1)
  end

  (* Run k rounds of Miller-Rabin *)
  fun run_rounds (count: int): bool =
    if count = 0 then
      true
    else let
      val a = $extfcall(ptr, "BN_rand_range", candidate)
      val passed = test_witness(candidate, len, a, $null, 64)
    in
      if passed then run_rounds(count - 1)
      else false
    end

  val is_prime = run_rounds(rounds)
in
  if is_prime then
    Some(is_probable_prime_proof())
  else
    None()
end

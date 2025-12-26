(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * RGT Vault - Cryptographic Tests
 *
 * Unit tests for cryptographic primitives.
 *)

#include "share/atspre_staload.hats"

staload "SATS/crypto.sats"

(* ========================================================================== *)
(* Test Utilities                                                              *)
(* ========================================================================== *)

fn test_pass (name: string): void = let
  val _ = $extfcall(int, "printf", "[PASS] %s\n", name)
in
end

fn test_fail (name: string, msg: string): void = let
  val _ = $extfcall(int, "printf", "[FAIL] %s: %s\n", name, msg)
in
end

fn assert_eq (name: string, expected: int, actual: int): bool =
  if expected = actual then let
    val () = test_pass(name)
  in
    true
  end
  else let
    val () = test_fail(name, "values not equal")
  in
    false
  end

(* ========================================================================== *)
(* Cryptographic Constants Tests                                               *)
(* ========================================================================== *)

fn test_aes_key_size (): bool =
  assert_eq("AES key size is 256 bits", 32, AES_KEY_BYTES)

fn test_blake3_output_size (): bool =
  assert_eq("BLAKE3 output is 256 bits", 32, BLAKE3_OUTPUT_BYTES)

fn test_argon2_memory (): bool =
  assert_eq("Argon2id memory is 64 MiB", 65536, ARGON2_MEMORY_KIB)

fn test_kyber_variant (): bool =
  assert_eq("Kyber variant is 1024", 1024, KYBER_VARIANT)

fn test_dilithium_variant (): bool =
  assert_eq("Dilithium variant is 5", 5, DILITHIUM_VARIANT)

fn test_miller_rabin_rounds (): bool =
  assert_eq("Miller-Rabin rounds is 64", 64, MILLER_RABIN_ROUNDS)

(* ========================================================================== *)
(* Main Test Runner                                                            *)
(* ========================================================================== *)

implement main0 () = let
  val _ = $extfcall(int, "printf", "=== RGT Vault Cryptographic Tests ===\n\n")

  val pass_count = ref<int>(0)
  val fail_count = ref<int>(0)

  fun run_test (test: () -> bool): void =
    if test() then
      !pass_count := !pass_count + 1
    else
      !fail_count := !fail_count + 1

  val () = run_test(test_aes_key_size)
  val () = run_test(test_blake3_output_size)
  val () = run_test(test_argon2_memory)
  val () = run_test(test_kyber_variant)
  val () = run_test(test_dilithium_variant)
  val () = run_test(test_miller_rabin_rounds)

  val _ = $extfcall(int, "printf", "\n=== Results: %d passed, %d failed ===\n",
                    !pass_count, !fail_count)

  val _ = if !fail_count > 0 then
    $extfcall(void, "exit", 1)
  else
    ()
in
end

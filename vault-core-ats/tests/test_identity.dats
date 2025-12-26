(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * RGT Vault - Identity Storage Tests
 *
 * Unit tests for identity management.
 *)

#include "share/atspre_staload.hats"

staload "SATS/identity.sats"

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

(* ========================================================================== *)
(* Identity Type Tests                                                         *)
(* ========================================================================== *)

fn test_identity_type_valid (): bool = let
  val ssh_valid = is_valid_identity_type(IdentitySsh)
  val pgp_valid = is_valid_identity_type(IdentityPgp)
  val pat_valid = is_valid_identity_type(IdentityPat)
  val rest_valid = is_valid_identity_type(IdentityRestApi)
  val graphql_valid = is_valid_identity_type(IdentityGraphql)
  val grpc_valid = is_valid_identity_type(IdentityGrpc)
  val xpc_valid = is_valid_identity_type(IdentityXpc)
  val x509_valid = is_valid_identity_type(IdentityX509)
  val did_valid = is_valid_identity_type(IdentityDid)
  val oauth2_valid = is_valid_identity_type(IdentityOauth2)
  val jwt_valid = is_valid_identity_type(IdentityJwt)
  val wg_valid = is_valid_identity_type(IdentityWireguard)
in
  if ssh_valid && pgp_valid && pat_valid && rest_valid &&
     graphql_valid && grpc_valid && xpc_valid && x509_valid &&
     did_valid && oauth2_valid && jwt_valid && wg_valid then let
    val () = test_pass("All identity types are valid")
  in
    true
  end
  else let
    val () = test_fail("Identity type validation", "Some types invalid")
  in
    false
  end
end

fn test_guid_generation (): bool = let
  val g1 = guid_generate()
  val g2 = guid_generate()
  val s1 = guid_to_string(g1)
  val s2 = guid_to_string(g2)
  val len1 = $extfcall(size_t, "strlen", s1)
  val len2 = $extfcall(size_t, "strlen", s2)
in
  (* GUIDs should be 36 characters: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx *)
  if sz2i(len1) = 36 && sz2i(len2) = 36 then let
    val () = test_pass("GUID generation produces valid format")
  in
    true
  end
  else let
    val () = test_fail("GUID generation", "Invalid format")
  in
    false
  end
end

fn test_guid_uniqueness (): bool = let
  val g1 = guid_generate()
  val g2 = guid_generate()
  val s1 = guid_to_string(g1)
  val s2 = guid_to_string(g2)
  val cmp = $extfcall(int, "strcmp", s1, s2)
in
  if cmp != 0 then let
    val () = test_pass("Generated GUIDs are unique")
  in
    true
  end
  else let
    val () = test_fail("GUID uniqueness", "Duplicate GUID generated")
  in
    false
  end
end

(* ========================================================================== *)
(* Main Test Runner                                                            *)
(* ========================================================================== *)

implement main0 () = let
  val _ = $extfcall(int, "printf", "=== RGT Vault Identity Tests ===\n\n")

  val pass_count = ref<int>(0)
  val fail_count = ref<int>(0)

  fun run_test (test: () -> bool): void =
    if test() then
      !pass_count := !pass_count + 1
    else
      !fail_count := !fail_count + 1

  val () = run_test(test_identity_type_valid)
  val () = run_test(test_guid_generation)
  val () = run_test(test_guid_uniqueness)

  val _ = $extfcall(int, "printf", "\n=== Results: %d passed, %d failed ===\n",
                    !pass_count, !fail_count)

  val _ = if !fail_count > 0 then
    $extfcall(void, "exit", 1)
  else
    ()
in
end

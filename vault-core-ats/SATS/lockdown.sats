(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * Svalinn Vault - Lockdown Security (Static Specification)
 *
 * Defines the lockdown state machine with compile-time enforcement
 * of security transitions.
 *)

#define ATS_PACKNAME "svalinn.lockdown"

staload "SATS/crypto.sats"

(* ========================================================================== *)
(* Lockdown State Machine                                                     *)
(* ========================================================================== *)

(* Vault states - phantom types for compile-time tracking *)
sortdef vault_state = {locked, unlocked}

(* Linear vault handle - state tracked at compile time *)
absvtype vault_handle (s: vault_state) = ptr

(* Proof of lockdown state *)
absprop vault_is_locked
absprop vault_is_unlocked

(* ========================================================================== *)
(* State Transitions                                                          *)
(* ========================================================================== *)

(* Unlock vault - requires master key, transitions state *)
fun vault_unlock (
  vault: vault_handle(locked),
  master_key: linear_key(argon2_output),
  mfa_code: int  (* TOTP code *)
): (vault_is_unlocked | vault_handle(unlocked))

(* Lock vault - applies obfuscation, transitions state *)
fun vault_lock (
  vault: vault_handle(unlocked),
  quantum_seed: bytes_t(32)
): (vault_is_locked | vault_handle(locked))

(* ========================================================================== *)
(* Permission Levels                                                          *)
(* ========================================================================== *)

(* Unix permission mode *)
typedef permission_mode = [m: int | m >= 0 && m <= 511] int(m)

(* Permission sets for different states *)
val perm_000: permission_mode  (* No access at all *)
val perm_200: permission_mode  (* Write only - append logs *)
val perm_400: permission_mode  (* Read only *)
val perm_500: permission_mode  (* Read + execute - chroot *)
val perm_600: permission_mode  (* Read + write *)

(* ========================================================================== *)
(* File Lockdown                                                              *)
(* ========================================================================== *)

(* Apply permissions to a path *)
fun apply_permission (
  path: string,
  mode: permission_mode
): bool

(* Locked state permissions *)
fun apply_locked_permissions (
  pf: vault_is_locked |
  vault_dir: string,
  config_dir: string,
  log_dir: string,
  socket_dir: string
): void

(* Unlocked state permissions *)
fun apply_unlocked_permissions (
  pf: vault_is_unlocked |
  vault_dir: string,
  config_dir: string,
  log_dir: string,
  socket_dir: string
): void

(* ========================================================================== *)
(* Chroot Isolation                                                           *)
(* ========================================================================== *)

(* Chroot jail configuration *)
typedef chroot_config = @{
  jail_path = string,
  jail_mode = permission_mode,
  minimal_dev = bool,
  no_shell = bool
}

(* Default chroot configuration *)
val default_chroot_config: chroot_config

(* Set up chroot jail *)
fun setup_chroot (
  config: chroot_config
): bool

(* Enter chroot (irreversible in process) *)
fun enter_chroot (
  config: chroot_config
): bool

(* ========================================================================== *)
(* Polymorphic Obfuscation                                                    *)
(* ========================================================================== *)

(* Obfuscation transform types *)
datatype transform =
  | TransformXor of bytes_t(32)
  | TransformShuffle of list(int, 256)
  | TransformRotate of int
  | TransformInterleave of int

(* Polymorphic engine state - changes each lock *)
abstype polymorphic_state = ptr

(* Create new polymorphic state from quantum seed *)
fun polymorphic_init (
  seed: bytes_t(32)
): polymorphic_state

(* Apply obfuscation *)
fun polymorphic_obfuscate {n: nat} (
  state: !polymorphic_state,
  data: bytes_t(n),
  len: int(n)
): bytes_t(n)

(* Remove obfuscation *)
fun polymorphic_deobfuscate {n: nat} (
  state: !polymorphic_state,
  data: bytes_t(n),
  len: int(n)
): bytes_t(n)

(* Evolve state (metamorphic) *)
fun polymorphic_evolve (
  state: polymorphic_state
): polymorphic_state

(* ========================================================================== *)
(* Lockdown Verification                                                      *)
(* ========================================================================== *)

(* Lockdown report *)
typedef lockdown_report = @{
  vault_locked = bool,
  sockets_locked = bool,
  chroot_ready = bool,
  permissions_correct = bool,
  fully_locked = bool
}

(* Verify current lockdown state *)
fun verify_lockdown (
  vault_dir: string,
  socket_dir: string,
  chroot_config: chroot_config
): lockdown_report

(* Check if fully secure *)
fun is_secure (report: lockdown_report): bool

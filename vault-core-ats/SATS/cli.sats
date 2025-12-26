(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * Svalinn Vault - CLI Interface (Static Specification)
 *
 * ATS-based command line interface with linear resource management.
 *)

#define ATS_PACKNAME "svalinn.cli"

staload "SATS/crypto.sats"
staload "SATS/identity.sats"
staload "SATS/lockdown.sats"

(* ========================================================================== *)
(* Command Types                                                              *)
(* ========================================================================== *)

datatype command =
  | CmdInit                              (* Initialize new vault *)
  | CmdUnlock                            (* Unlock vault *)
  | CmdLock                              (* Lock vault *)
  | CmdAdd of (identity_type, string)    (* Add credential *)
  | CmdGet of guid                       (* Get credential by GUID *)
  | CmdList                              (* List all GUIDs *)
  | CmdDelete of guid                    (* Delete credential *)
  | CmdExport of string                  (* Export to file *)
  | CmdImport of string                  (* Import from file *)
  | CmdRotate                            (* Rotate master password *)
  | CmdVerify                            (* Verify vault integrity *)
  | CmdTui                               (* Launch TUI *)
  | CmdHelp                              (* Show help *)
  | CmdVersion                           (* Show version *)

(* Parse command from arguments *)
fun parse_command (argc: int, argv: ptr): Option(command)

(* ========================================================================== *)
(* CLI State                                                                  *)
(* ========================================================================== *)

(* CLI state machine *)
absvtype cli_state = ptr

(* Initialize CLI *)
fun cli_init (): cli_state

(* Cleanup CLI *)
fun cli_cleanup (state: cli_state): void

(* ========================================================================== *)
(* Command Execution                                                          *)
(* ========================================================================== *)

(* Execute command and return exit code *)
fun execute_command (
  state: !cli_state,
  cmd: command
): int

(* ========================================================================== *)
(* Output Functions                                                           *)
(* ========================================================================== *)

(* Print to stdout *)
fun cli_print (msg: string): void

(* Print error to stderr *)
fun cli_error (msg: string): void

(* Print GUID in standard format *)
fun cli_print_guid (g: guid): void

(* Print identity summary (GUID only, no secrets) *)
fun cli_print_identity_summary (id: stored_identity): void

(* ========================================================================== *)
(* Input Functions                                                            *)
(* ========================================================================== *)

(* Read password securely (no echo) *)
fun cli_read_password (prompt: string): linear_key(bytes_t(n))

(* Read TOTP code *)
fun cli_read_totp (prompt: string): int

(* Confirm action *)
fun cli_confirm (prompt: string): bool

(* ========================================================================== *)
(* Main Entry Point                                                           *)
(* ========================================================================== *)

fun main (argc: int, argv: ptr): int

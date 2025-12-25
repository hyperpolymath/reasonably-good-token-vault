(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * RGT Vault - CLI Interface (Static Specification)
 * (Reasonably Good Token Vault - a parody of Pretty Good Privacy)
 *
 * ATS-based command line interface with linear resource management.
 * Includes MFA, login time limits, security scanning, and chmod 000 on exit.
 * Built on Svalinn container technology with corre-terro image.
 *)

#define ATS_PACKNAME "svalinn.cli"

staload "SATS/crypto.sats"
staload "SATS/identity.sats"
staload "SATS/lockdown.sats"

(* ========================================================================== *)
(* Access Mode                                                                *)
(* ========================================================================== *)

(* --strict: Minimal file access (r, w, or e as appropriate)
 * --relaxed: Open all but most sensitive files to edit at min level *)
datatype access_mode =
  | AccessStrict                         (* Minimal access, maximum security *)
  | AccessRelaxed                        (* Broader access, convenience mode *)

(* ========================================================================== *)
(* Security Check Results                                                     *)
(* ========================================================================== *)

datatype security_check_result =
  | CheckPass of string                  (* Check passed with message *)
  | CheckWarn of string                  (* Check passed with warning *)
  | CheckFail of string                  (* Check failed with error *)

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
  | CmdScan                              (* Security vulnerability scan *)
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
(* MFA and Login Control                                                      *)
(* ========================================================================== *)

(* Login time limit configuration (variable delay between attempts) *)
abstype login_limiter = ptr

(* Create login limiter with base delay *)
fun login_limiter_create (base_delay_ms: int): login_limiter

(* Check if login is allowed (enforces variable delays) *)
fun login_limiter_check (!login_limiter): bool

(* Record failed attempt (increases delay) *)
fun login_limiter_fail (!login_limiter): void

(* Record successful attempt (resets delay) *)
fun login_limiter_success (!login_limiter): void

(* Get current lockout time remaining in seconds *)
fun login_limiter_lockout_remaining (!login_limiter): int

(* Destroy login limiter *)
fun login_limiter_destroy (login_limiter): void

(* Anti-AI CAPTCHA challenge *)
fun cli_captcha_challenge (): bool

(* Post-quantum MFA challenge (Dilithium5 signature verification) *)
fun cli_pq_mfa_challenge (challenge: bytes_t(n)): bool

(* ========================================================================== *)
(* Security Scanning                                                          *)
(* ========================================================================== *)

(* Immediate quick diff scan for vulnerabilities *)
fun security_diff_scan (): list(security_check_result)

(* Makefile validation check *)
fun validate_makefile (path: string): security_check_result

(* ZONEMD integrity check (DNS zone file integrity) *)
fun check_zonemd_integrity (): security_check_result

(* Validate data types - only SSH/PGP/PAT/API credentials allowed *)
(* Returns true if data type is valid (no executable code) *)
fun validate_data_type (data: bytes_t(n), expected_type: identity_type): bool

(* ========================================================================== *)
(* Access Mode Control                                                        *)
(* ========================================================================== *)

(* Get current access mode *)
fun get_access_mode (): access_mode

(* Set access mode (--strict or --relaxed) *)
fun set_access_mode (mode: access_mode): void

(* Check if operation is allowed in current access mode *)
fun is_operation_allowed (op: string, mode: access_mode): bool

(* ========================================================================== *)
(* Exit Handlers (chmod 000 on exit)                                          *)
(* ========================================================================== *)

(* Register cleanup handler - applies chmod 000 to all vault files on exit *)
fun register_exit_handler (): void

(* Apply chmod 000 to all vault files immediately *)
fun apply_lockdown_permissions (): void

(* Cleanup and restore permissions to 000 *)
fun cli_exit_cleanup (state: cli_state): void

(* ========================================================================== *)
(* Main Entry Point                                                           *)
(* ========================================================================== *)

fun main (argc: int, argv: ptr): int

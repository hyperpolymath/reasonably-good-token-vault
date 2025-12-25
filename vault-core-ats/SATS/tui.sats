(* SPDX-License-Identifier: AGPL-3.0-or-later *)
(* SPDX-FileCopyrightText: 2025 Hyperpolymath *)
(*
 * Svalinn Vault - TUI Interface (Static Specification)
 *
 * ATS-based terminal user interface with ncurses.
 *)

#define ATS_PACKNAME "svalinn.tui"

staload "SATS/crypto.sats"
staload "SATS/identity.sats"
staload "SATS/lockdown.sats"

(* ========================================================================== *)
(* TUI State                                                                  *)
(* ========================================================================== *)

(* Linear TUI state - owns the terminal *)
absvtype tui_state = ptr

(* Current view in TUI *)
datatype tui_view =
  | ViewLogin        (* Password entry *)
  | ViewMfa          (* MFA code entry *)
  | ViewList         (* GUID list *)
  | ViewDetail       (* Credential detail *)
  | ViewAdd          (* Add credential *)
  | ViewExport       (* Export wizard *)
  | ViewSettings     (* Settings *)
  | ViewHelp         (* Help screen *)

(* ========================================================================== *)
(* TUI Lifecycle                                                              *)
(* ========================================================================== *)

(* Initialize TUI - takes ownership of terminal *)
fun tui_init (): tui_state

(* Cleanup TUI - releases terminal *)
fun tui_cleanup (state: tui_state): void

(* Run TUI main loop *)
fun tui_run (state: !tui_state): int

(* ========================================================================== *)
(* View Rendering                                                             *)
(* ========================================================================== *)

(* Clear and render current view *)
fun tui_render (state: !tui_state, view: tui_view): void

(* Render status bar *)
fun tui_render_status (state: !tui_state, msg: string): void

(* Render error message *)
fun tui_render_error (state: !tui_state, msg: string): void

(* ========================================================================== *)
(* Input Handling                                                             *)
(* ========================================================================== *)

(* Key input result *)
datatype key_event =
  | KeyChar of char
  | KeyUp
  | KeyDown
  | KeyLeft
  | KeyRight
  | KeyEnter
  | KeyEscape
  | KeyTab
  | KeyBackspace
  | KeyF of int  (* Function keys *)
  | KeyResize    (* Terminal resized *)

(* Read key event *)
fun tui_read_key (state: !tui_state): key_event

(* Read password with masked input *)
fun tui_read_password (
  state: !tui_state,
  prompt: string
): linear_key(bytes_t(n))

(* Read TOTP code *)
fun tui_read_totp (
  state: !tui_state,
  prompt: string
): int

(* ========================================================================== *)
(* List View                                                                  *)
(* ========================================================================== *)

(* Selection state *)
abstype list_selection = ptr

(* Create selection for GUID list *)
fun list_selection_new (guids: list(guid, n)): list_selection

(* Move selection *)
fun list_selection_up (sel: !list_selection): void
fun list_selection_down (sel: !list_selection): void
fun list_selection_page_up (sel: !list_selection): void
fun list_selection_page_down (sel: !list_selection): void

(* Get current selection *)
fun list_selection_current (sel: !list_selection): Option(guid)

(* Render list with selection *)
fun tui_render_list (
  state: !tui_state,
  sel: !list_selection
): void

(* ========================================================================== *)
(* Dialog Windows                                                             *)
(* ========================================================================== *)

(* Show confirmation dialog *)
fun tui_confirm (
  state: !tui_state,
  title: string,
  message: string
): bool

(* Show message dialog *)
fun tui_message (
  state: !tui_state,
  title: string,
  message: string
): void

(* Show input dialog *)
fun tui_input (
  state: !tui_state,
  title: string,
  prompt: string
): Option(string)

(* ========================================================================== *)
(* CAPTCHA Display                                                            *)
(* ========================================================================== *)

(* Display visual CAPTCHA for anti-AI verification *)
fun tui_display_captcha (
  state: !tui_state,
  challenge: bytes_t(n)
): int  (* User's answer *)

(* Display post-quantum visual challenge *)
fun tui_display_pq_challenge (
  state: !tui_state,
  challenge: bytes_t(n)
): bytes_t(m)  (* User's response *)

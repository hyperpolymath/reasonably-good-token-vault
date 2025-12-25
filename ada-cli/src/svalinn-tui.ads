-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: 2025 Hyperpolymath
--
-- Svalinn TUI - Text User Interface

package Svalinn.TUI is

   --  Run the interactive TUI
   procedure Run;

   --  TUI screen types
   type Screen_Type is
     (Screen_Main,
      Screen_Identities,
      Screen_Add_Identity,
      Screen_View_Identity,
      Screen_Settings,
      Screen_Audit_Log,
      Screen_MFA_Setup,
      Screen_Export_Import,
      Screen_Help);

   --  Navigate to screen
   procedure Navigate_To (Screen : Screen_Type);

   --  Refresh current screen
   procedure Refresh;

   --  Show modal dialog
   procedure Show_Modal (Title : String; Message : String);

   --  Password input (masked)
   function Get_Password (Prompt : String) return String;

   --  Confirm action
   function Confirm (Message : String) return Boolean;

end Svalinn.TUI;

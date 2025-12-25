-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: 2025 Hyperpolymath
--
-- Svalinn Vault CLI/TUI - Main Entry Point
--
-- Security-focused command-line and text user interface for
-- managing the Svalinn identity vault.

with Ada.Text_IO;             use Ada.Text_IO;
with Ada.Command_Line;        use Ada.Command_Line;
with Ada.Strings.Unbounded;   use Ada.Strings.Unbounded;
with Svalinn.Vault;
with Svalinn.Identity;
with Svalinn.TUI;
with Svalinn.Security;

procedure Svalinn_Main is

   --  Version information
   Version : constant String := "0.1.0";
   Banner : constant String :=
      "Svalinn Identity Vault v" & Version & " - Secure Credential Storage";

   --  Command types
   type Command_Type is
     (Cmd_Help,
      Cmd_Version,
      Cmd_Init,
      Cmd_Unlock,
      Cmd_Lock,
      Cmd_Add,
      Cmd_List,
      Cmd_Get,
      Cmd_Remove,
      Cmd_Export,
      Cmd_Import,
      Cmd_TUI,
      Cmd_Status,
      Cmd_Rotate,
      Cmd_Verify,
      Cmd_Unknown);

   --  Parse command from argument
   function Parse_Command (Arg : String) return Command_Type is
   begin
      if Arg = "help" or Arg = "-h" or Arg = "--help" then
         return Cmd_Help;
      elsif Arg = "version" or Arg = "-v" or Arg = "--version" then
         return Cmd_Version;
      elsif Arg = "init" then
         return Cmd_Init;
      elsif Arg = "unlock" then
         return Cmd_Unlock;
      elsif Arg = "lock" then
         return Cmd_Lock;
      elsif Arg = "add" then
         return Cmd_Add;
      elsif Arg = "list" or Arg = "ls" then
         return Cmd_List;
      elsif Arg = "get" then
         return Cmd_Get;
      elsif Arg = "remove" or Arg = "rm" then
         return Cmd_Remove;
      elsif Arg = "export" then
         return Cmd_Export;
      elsif Arg = "import" then
         return Cmd_Import;
      elsif Arg = "tui" or Arg = "interactive" then
         return Cmd_TUI;
      elsif Arg = "status" then
         return Cmd_Status;
      elsif Arg = "rotate" then
         return Cmd_Rotate;
      elsif Arg = "verify" then
         return Cmd_Verify;
      else
         return Cmd_Unknown;
      end if;
   end Parse_Command;

   --  Print usage information
   procedure Print_Help is
   begin
      Put_Line (Banner);
      New_Line;
      Put_Line ("USAGE:");
      Put_Line ("  svalinn-cli <command> [options]");
      New_Line;
      Put_Line ("COMMANDS:");
      Put_Line ("  init              Initialize a new vault");
      Put_Line ("  unlock            Unlock the vault");
      Put_Line ("  lock              Lock the vault");
      Put_Line ("  add <type>        Add a new identity");
      Put_Line ("  list [type]       List identities");
      Put_Line ("  get <id>          Get identity details");
      Put_Line ("  remove <id>       Remove an identity");
      Put_Line ("  export <file>     Export vault (armored)");
      Put_Line ("  import <file>     Import vault from backup");
      Put_Line ("  tui               Launch interactive TUI");
      Put_Line ("  status            Show vault status");
      Put_Line ("  rotate <id>       Rotate identity credentials");
      Put_Line ("  verify            Verify vault integrity");
      Put_Line ("  help              Show this help");
      Put_Line ("  version           Show version");
      New_Line;
      Put_Line ("IDENTITY TYPES:");
      Put_Line ("  ssh               SSH key pair");
      Put_Line ("  pgp               PGP/GPG key");
      Put_Line ("  pat               Personal Access Token");
      Put_Line ("  rest-api          REST API credential");
      Put_Line ("  graphql-api       GraphQL API credential");
      Put_Line ("  grpc-api          gRPC API credential");
      Put_Line ("  xpc               XPC service credential");
      Put_Line ("  x509              X.509 certificate");
      Put_Line ("  did               Decentralized Identifier");
      Put_Line ("  oauth2            OAuth2 token");
      Put_Line ("  jwt               JWT token");
      Put_Line ("  wireguard         WireGuard private key");
      New_Line;
      Put_Line ("SECURITY:");
      Put_Line ("  - Post-quantum cryptography (Kyber-1024, Dilithium)");
      Put_Line ("  - Argon2id key derivation");
      Put_Line ("  - AES-256-GCM encryption");
      Put_Line ("  - BLAKE3 integrity verification");
      Put_Line ("  - Time-locked access control");
      Put_Line ("  - MFA support (TOTP)");
   end Print_Help;

   --  Print version
   procedure Print_Version is
   begin
      Put_Line (Banner);
      Put_Line ("Crypto Suite: SVALINN-PQ-2025");
      Put_Line ("Build: Release with LTO");
   end Print_Version;

   --  Main command dispatcher
   procedure Run_Command (Cmd : Command_Type) is
   begin
      case Cmd is
         when Cmd_Help =>
            Print_Help;

         when Cmd_Version =>
            Print_Version;

         when Cmd_Init =>
            Put_Line ("Initializing new vault...");
            Svalinn.Vault.Initialize;

         when Cmd_Unlock =>
            Put_Line ("Unlocking vault...");
            Svalinn.Vault.Unlock;

         when Cmd_Lock =>
            Put_Line ("Locking vault...");
            Svalinn.Vault.Lock;

         when Cmd_Add =>
            if Argument_Count >= 2 then
               Svalinn.Identity.Add (Argument (2));
            else
               Put_Line ("Error: identity type required");
               Put_Line ("Usage: svalinn-cli add <type>");
            end if;

         when Cmd_List =>
            Svalinn.Identity.List_All;

         when Cmd_Get =>
            if Argument_Count >= 2 then
               Svalinn.Identity.Get (Argument (2));
            else
               Put_Line ("Error: identity ID required");
            end if;

         when Cmd_Remove =>
            if Argument_Count >= 2 then
               Svalinn.Identity.Remove (Argument (2));
            else
               Put_Line ("Error: identity ID required");
            end if;

         when Cmd_Export =>
            if Argument_Count >= 2 then
               Svalinn.Vault.Export_Armored (Argument (2));
            else
               Put_Line ("Error: output file required");
            end if;

         when Cmd_Import =>
            if Argument_Count >= 2 then
               Svalinn.Vault.Import_Armored (Argument (2));
            else
               Put_Line ("Error: input file required");
            end if;

         when Cmd_TUI =>
            Put_Line ("Launching interactive TUI...");
            Svalinn.TUI.Run;

         when Cmd_Status =>
            Svalinn.Vault.Show_Status;

         when Cmd_Rotate =>
            if Argument_Count >= 2 then
               Svalinn.Identity.Rotate (Argument (2));
            else
               Put_Line ("Error: identity ID required");
            end if;

         when Cmd_Verify =>
            Put_Line ("Verifying vault integrity...");
            Svalinn.Security.Verify_Integrity;

         when Cmd_Unknown =>
            Put_Line ("Unknown command. Use 'svalinn-cli help' for usage.");
            Set_Exit_Status (Failure);
      end case;
   end Run_Command;

   --  Entry point
   Cmd : Command_Type;

begin
   --  Security check: verify we're running in secure environment
   Svalinn.Security.Check_Environment;

   if Argument_Count = 0 then
      --  No arguments: show help
      Print_Help;
   else
      Cmd := Parse_Command (Argument (1));
      Run_Command (Cmd);
   end if;

exception
   when Svalinn.Vault.Vault_Locked =>
      Put_Line ("Error: Vault is locked. Use 'svalinn-cli unlock' first.");
      Set_Exit_Status (Failure);

   when Svalinn.Vault.Authentication_Failed =>
      Put_Line ("Error: Authentication failed.");
      Set_Exit_Status (Failure);

   when Svalinn.Security.Security_Violation =>
      Put_Line ("Error: Security violation detected. Operation aborted.");
      Set_Exit_Status (Failure);

   when others =>
      Put_Line ("Error: An unexpected error occurred.");
      Set_Exit_Status (Failure);
end Svalinn_Main;

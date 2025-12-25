-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: 2025 Hyperpolymath
--
-- Svalinn Vault - Ada interface to Rust vault core

package Svalinn.Vault is

   --  Exceptions
   Vault_Locked : exception;
   Authentication_Failed : exception;
   Integrity_Error : exception;
   MFA_Required : exception;

   --  Vault state
   type Vault_State is (Locked, MFA_Pending, Unlocked, Sealed);

   --  Initialize a new vault
   procedure Initialize;

   --  Unlock the vault with password
   procedure Unlock;

   --  Lock the vault
   procedure Lock;

   --  Get current vault state
   function Get_State return Vault_State;

   --  Show vault status
   procedure Show_Status;

   --  Export vault in armored format
   procedure Export_Armored (Filename : String);

   --  Import vault from armored backup
   procedure Import_Armored (Filename : String);

   --  Verify vault signature
   function Verify_Signature return Boolean;

   --  Enable TOTP MFA
   procedure Enable_TOTP (Account : String; Issuer : String);

   --  Verify MFA code
   procedure Verify_MFA (Code : String);

   --  Generate recovery codes
   procedure Generate_Recovery_Codes (Count : Positive);

private

   --  Current vault state
   Current_State : Vault_State := Locked;

   --  FFI bindings to Rust core
   pragma Import (C, Initialize, "svalinn_vault_init");
   pragma Import (C, Lock, "svalinn_vault_lock");

end Svalinn.Vault;

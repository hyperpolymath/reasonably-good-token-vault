-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: 2025 Hyperpolymath
--
-- Svalinn Security - Environment and integrity checks

package Svalinn.Security is

   --  Exceptions
   Security_Violation : exception;
   Insecure_Environment : exception;
   Integrity_Failed : exception;

   --  Check running environment for security
   procedure Check_Environment;

   --  Verify vault integrity
   procedure Verify_Integrity;

   --  Check if running as root (should fail)
   function Is_Running_As_Root return Boolean;

   --  Check if SELinux is enforcing
   function Is_SELinux_Enforcing return Boolean;

   --  Check if running in container
   function Is_Containerized return Boolean;

   --  Verify digital identity binding
   function Verify_Identity_Binding return Boolean;

   --  Check for debugger attachment
   function Is_Being_Debugged return Boolean;

   --  Secure memory wipe
   procedure Secure_Wipe (Data : in out String);

   --  Generate secure random bytes
   function Secure_Random (Length : Positive) return String;

   --  Check MAC randomization status
   function Is_MAC_Randomized return Boolean;

end Svalinn.Security;

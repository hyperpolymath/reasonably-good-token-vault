-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: 2025 Hyperpolymath
--
-- Svalinn Identity Management - Ada interface

package Svalinn.Identity is

   --  Identity types
   type Identity_Type is
     (SSH,
      PGP,
      PAT,
      REST_API,
      GraphQL_API,
      GRPC_API,
      XPC,
      X509_Certificate,
      DID,
      OAuth2_Token,
      JWT_Token,
      WireGuard,
      Custom);

   --  Exceptions
   Identity_Not_Found : exception;
   Identity_Exists : exception;
   Invalid_Type : exception;

   --  Add a new identity
   procedure Add (Type_Name : String);

   --  List all identities
   procedure List_All;

   --  List identities by type
   procedure List_By_Type (Type_Filter : Identity_Type);

   --  Get identity by ID
   procedure Get (ID : String);

   --  Remove identity by ID
   procedure Remove (ID : String);

   --  Rotate identity credentials
   procedure Rotate (ID : String);

   --  Search identities by host
   procedure Find_By_Host (Host : String);

   --  Search identities by tag
   procedure Find_By_Tag (Tag : String);

   --  Parse identity type from string
   function Parse_Type (Name : String) return Identity_Type;

   --  Convert identity type to display string
   function Type_To_String (T : Identity_Type) return String;

end Svalinn.Identity;

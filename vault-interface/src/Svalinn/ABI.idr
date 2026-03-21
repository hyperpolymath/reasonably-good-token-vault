-- SPDX-License-Identifier: PMPL-1.0-or-later
-- Svalinn Vault ABI Definitions (Idris2)

module Svalinn.ABI

import Data.Vect

-- ============================================================================
-- Core Types
-- ============================================================================

||| Identity type classification (matches Rust IdentityType)
public export
data IdentityType =
    Ssh
  | Pgp
  | Pat
  | RestApi
  | GraphqlApi
  | GrpcApi
  | Xpc
  | X509Certificate
  | Did
  | Oauth2Token
  | JwtToken
  | WireGuard
  | Custom

||| Memory layout of IdentityType (as u32)
public export
identityTypeToU32 : IdentityType -> Bits32
identityTypeToU32 Ssh             = 0
identityTypeToU32 Pgp             = 1
identityTypeToU32 Pat             = 2
identityTypeToU32 RestApi         = 3
identityTypeToU32 GraphqlApi      = 4
identityTypeToU32 GrpcApi         = 5
identityTypeToU32 Xpc             = 6
identityTypeToU32 X509Certificate = 7
identityTypeToU32 Did             = 8
identityTypeToU32 Oauth2Token     = 9
identityTypeToU32 JwtToken        = 10
identityTypeToU32 WireGuard       = 11
identityTypeToU32 Custom          = 12

-- ============================================================================
-- C ABI Mapping
-- ============================================================================

||| Representation of a C string (char*)
public export
data CString = MkCString Bits64

||| Representation of a C buffer (void* + length)
public export
record CBuffer where
  constructor MkCBuffer
  ptr : Bits64
  len : Bits64

||| Representation of an Identity location (matches Rust IdentityLocation)
public export
record CIdentityLocation where
  constructor MkCIdentityLocation
  path : CString
  host : CString
  port : Bits16
  protocol : CString
  env_var : CString
  service_id : CString

||| Representation of an Identity (matches Rust Identity)
public export
record CIdentity where
  constructor MkCIdentity
  id_hi : Bits64  -- UUID hi
  id_lo : Bits64  -- UUID lo
  name : CString
  identity_type : Bits32
  fingerprint : CString
  mfa_required : Bits8
  -- Locations would be a separate array pointer
  locations_ptr : Bits64
  locations_count : Bits64

-- ============================================================================
-- Layout Proofs
-- ============================================================================

-- In a real Idris2 environment, we would use Elab to verify these sizes:
-- %runElab verifySize CIdentity 64

||| Total size of CIdentity in bytes (assuming 64-bit pointers)
public export
cIdentitySize : Bits64
cIdentitySize = 64 -- 8+8+8+4+8+1+8+8 + padding = 64

||| Alignment of CIdentity (8 bytes for pointers)
public export
cIdentityAlign : Bits64
cIdentityAlign = 8

-- ============================================================================
-- FFI Declarations
-- ============================================================================

||| Lookup identity by host name
%foreign "C:svalinn_find_by_host,libaerie_ffi"
public export
find_by_host : (host : String) -> IO (Maybe CIdentity)

||| Get the secret from an identity
%foreign "C:svalinn_get_secret,libaerie_ffi"
public export
get_secret : (id_hi : Bits64) -> (id_lo : Bits64) -> IO (Maybe CBuffer)

||| Free a CBuffer returned by get_secret
%foreign "C:svalinn_free_buffer,libaerie_ffi"
public export
free_buffer : (buf : CBuffer) -> IO ()

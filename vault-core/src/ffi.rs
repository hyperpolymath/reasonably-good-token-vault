// SPDX-License-Identifier: PMPL-1.0-or-later
// Svalinn Vault Core FFI (Rust)
//
// Exports core vault functionality to Zig FFI via C ABI.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};
use std::ptr;
use crate::identity::{Identity, IdentityType};
use crate::vault::Vault;

// ============================================================================
// ABI-Compliant Structs (matching Zig/Idris2)
// ============================================================================

#[repr(C)]
pub struct CBuffer {
    pub ptr: *mut c_uchar,
    pub len: usize,
}

#[repr(C)]
pub struct CIdentity {
    pub id_hi: u64,
    pub id_lo: u64,
    pub name: *const c_char,
    pub identity_type: u32,
    pub fingerprint: *const c_char,
    pub mfa_required: u8,
    pub locations_ptr: *const CIdentityLocation,
    pub locations_count: usize,
}

#[repr(C)]
pub struct CIdentityLocation {
    pub path: *const c_char,
    pub host: *const c_char,
    pub port: u16,
    pub protocol: *const c_char,
    pub env_var: *const c_char,
    pub service_id: *const c_char,
}

// ============================================================================
// Global Vault State (Placeholder for thread-safe access)
// ============================================================================

static mut GLOBAL_VAULT: Option<Vault> = None;

// ============================================================================
// Exported Functions
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn svalinn_core_find_by_host(host: *const c_char) -> *mut CIdentity {
    if host.is_null() { return ptr::null_mut(); }
    let host_str = CStr::from_ptr(host).to_string_lossy();

    // In a real implementation, we would access the unlocked GLOBAL_VAULT.
    // This mock demonstrates the mapping logic:
    if let Some(ref mut vault) = GLOBAL_VAULT {
        if let Ok(identities) = vault.list_identities(None) {
            for identity in identities {
                for loc in &identity.locations {
                    if loc.host.as_ref().map(|h| h == &*host_str).unwrap_or(false) {
                        return Box::into_raw(Box::new(map_to_c_identity(identity)));
                    }
                }
            }
        }
    }

    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn svalinn_core_get_secret(id_hi: u64, id_lo: u64) -> *mut CBuffer {
    // Reconstruct UUID from hi/lo and lookup in vault
    // Then return decrypted secret as CBuffer
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn svalinn_core_free_identity(identity: *mut CIdentity) {
    if !identity.is_null() {
        let id = Box::from_raw(identity);
        // Free inner strings
        if !id.name.is_null() { let _ = CString::from_raw(id.name as *mut c_char); }
        if !id.fingerprint.is_null() { let _ = CString::from_raw(id.fingerprint as *mut c_char); }
    }
}

#[no_mangle]
pub unsafe extern "C" fn svalinn_core_free_buffer(buffer: *mut CBuffer) {
    if !buffer.is_null() {
        let buf = Box::from_raw(buffer);
        let _ = Vec::from_raw_parts(buf.ptr, buf.len, buf.len); // Zeroing happens via ZeroizeOnDrop if using that type
    }
}

// ============================================================================
// Mapping Helpers
// ============================================================================

fn map_to_c_identity(identity: &Identity) -> CIdentity {
    CIdentity {
        id_hi: (identity.id.as_u128() >> 64) as u64,
        id_lo: identity.id.as_u128() as u64,
        name: CString::new(identity.name.clone()).unwrap().into_raw(),
        identity_type: map_identity_type(identity.identity_type),
        fingerprint: CString::new(identity.fingerprint.clone()).unwrap().into_raw(),
        mfa_required: identity.mfa_required as u8,
        locations_ptr: ptr::null(), // Needs allocation for full mapping
        locations_count: identity.locations.len(),
    }
}

fn map_identity_type(t: IdentityType) -> u32 {
    match t {
        IdentityType::Ssh => 0,
        IdentityType::Pgp => 1,
        IdentityType::Pat => 2,
        IdentityType::RestApi => 3,
        IdentityType::GraphqlApi => 4,
        IdentityType::GrpcApi => 5,
        IdentityType::Xpc => 6,
        IdentityType::X509Certificate => 7,
        IdentityType::Did => 8,
        IdentityType::Oauth2Token => 9,
        IdentityType::JwtToken => 10,
        IdentityType::WireGuard => 11,
        IdentityType::Custom => 12,
    }
}

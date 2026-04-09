// SPDX-License-Identifier: PMPL-1.0-or-later
// Svalinn Vault Core FFI (Rust)
//
// Exports core vault functionality to Zig FFI via C ABI.

#[cfg(feature = "ffi")]
use std::ffi::{CStr, CString};
#[cfg(feature = "ffi")]
use std::os::raw::{c_char, c_uchar};
#[cfg(feature = "ffi")]
use std::ptr;
#[cfg(feature = "ffi")]
use crate::identity::{Identity, IdentityType};
#[cfg(feature = "ffi")]
use crate::vault::Vault;

// ============================================================================
// ABI-Compliant Structs (matching Zig/Idris2)
// ============================================================================

#[cfg(feature = "ffi")]
#[repr(C)]
pub struct CIdentity {
    pub id_hi: u64,
    pub id_lo: u64,
    pub identity_type: u32,
    pub name_ptr: *const c_char,
    pub name_len: usize,
}

#[cfg(feature = "ffi")]
#[repr(C)]
pub struct CBuffer {
    pub ptr: *mut c_uchar,
    pub len: usize,
}

// ============================================================================
// FFI Functions (C ABI)
// ============================================================================

#[cfg(feature = "ffi")]
#[no_mangle]
pub unsafe extern "C" fn svalinn_core_find_by_host(host: *const c_char) -> *mut CIdentity {
    if host.is_null() { return ptr::null_mut(); }
    let host_str = CStr::from_ptr(host).to_string_lossy();
    
    // TODO: Implement actual lookup
    // For now, return null to indicate not found
    ptr::null_mut()
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub unsafe extern "C" fn svalinn_core_get_secret(id_hi: u64, id_lo: u64) -> *mut CBuffer {
    // Reconstruct UUID from hi/lo and lookup in vault
    // Then return decrypted secret as CBuffer
    ptr::null_mut()
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub unsafe extern "C" fn svalinn_core_free_identity(identity: *mut CIdentity) {
    if !identity.is_null() {
        let id = Box::from_raw(identity);
        drop(id);
    }
}

#[cfg(feature = "ffi")]
#[no_mangle]
pub unsafe extern "C" fn svalinn_core_free_buffer(buffer: *mut CBuffer) {
    if !buffer.is_null() {
        let buf = Box::from_raw(buffer);
        drop(buf);
    }
}
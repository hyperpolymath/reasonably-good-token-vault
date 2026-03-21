// SPDX-License-Identifier: PMPL-1.0-or-later
// Svalinn Vault FFI Bridge (Zig)
//
// Bridges SPARK/Ada and Rust core via Idris2-proven ABI.

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

// ============================================================================
// ABI-Compliant Types (matching Idris2 Svalinn.ABI)
// ============================================================================

pub const CBuffer = extern struct {
    ptr: [*]u8,
    len: usize,
};

pub const CIdentity = extern struct {
    id_hi: u64,
    id_lo: u64,
    name: [*:0]const u8,
    identity_type: u32,
    fingerprint: [*:0]const u8,
    mfa_required: u8,
    locations_ptr: ?[*]const CIdentityLocation,
    locations_count: usize,
};

pub const CIdentityLocation = extern struct {
    path: ?[*:0]const u8,
    host: ?[*:0]const u8,
    port: u16,
    protocol: ?[*:0]const u8,
    env_var: ?[*:0]const u8,
    service_id: ?[*:0]const u8,
};

// ============================================================================
// External Rust Functions (to be implemented in vault-core)
// ============================================================================

extern "C" fn svalinn_core_find_by_host(host: [*:0]const u8) ?*CIdentity;
extern "C" fn svalinn_core_get_secret(id_hi: u64, id_lo: u64) ?*CBuffer;
extern "C" fn svalinn_core_free_identity(identity: *CIdentity) void;
extern "C" fn svalinn_core_free_buffer(buffer: *CBuffer) void;

// ============================================================================
// Exported C-compatible Functions (for Ada)
// ============================================================================

/// Find identity by host. Returns a pointer to an ABI-compliant CIdentity.
/// The caller is responsible for freeing it via svalinn_free_identity.
export fn svalinn_find_by_host(host: [*:0]const u8) callconv(.C) ?*CIdentity {
    // Audit log: Zig layer can perform early validation or logging here
    return svalinn_core_find_by_host(host);
}

/// Retrieve secret for an identity. Returns pointer to CBuffer.
/// Caller must free via svalinn_free_buffer.
export fn svalinn_get_secret(id_hi: u64, id_lo: u64) callconv(.C) ?*CBuffer {
    return svalinn_core_get_secret(id_hi, id_lo);
}

export fn svalinn_free_identity(identity: *CIdentity) callconv(.C) void {
    svalinn_core_free_identity(identity);
}

export fn svalinn_free_buffer(buffer: *CBuffer) callconv(.C) void {
    svalinn_core_free_buffer(buffer);
}

// ============================================================================
// Secure Allocator Helper
// ============================================================================

var gpa = std.heap.GeneralPurposeAllocator(.{
    .safety = true,
    .thread_safe = true,
}){};

const allocator = gpa.allocator();

/// Bridge helper for bi-directional calls (e.g. Rust calling back into Ada)
/// This follows the "Triple Adapter" pattern from the project context.
export fn svalinn_triple_adapter_invoke(cartridge_name: [*:0]const u8, method: [*:0]const u8, params_json: [*:0]const u8) callconv(.C) [*:0]const u8 {
    // Placeholder for complex multi-cartridge orchestration
    _ = cartridge_name;
    _ = method;
    _ = params_json;
    return "{\"status\": \"unsupported\"}";
}

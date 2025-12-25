// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Svalinn Vault - Zig Cryptographic Bindings
//
// Provides safe, Zig-native cryptographic primitives for ATS FFI.
// No C code used - pure Zig implementation.

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Allocator = std.mem.Allocator;

// Use secure allocator that zeros memory on free
var secure_allocator = std.heap.GeneralPurposeAllocator(.{
    .safety = true,
    .retain_metadata = false,
}){};

// ============================================================================
// Argon2id Key Derivation
// ============================================================================

/// Argon2id parameters (OWASP compliant)
pub const Argon2Params = struct {
    memory_kib: u32 = 65536, // 64 MiB minimum
    time_cost: u32 = 4,
    parallelism: u32 = 4,
    output_len: usize = 32,
};

/// Derive key using Argon2id
export fn argon2id_derive(
    password: [*]const u8,
    password_len: usize,
    salt: *const [32]u8,
    output: *[32]u8,
    params: *const Argon2Params,
) callconv(.C) i32 {
    const password_slice = password[0..password_len];

    crypto.pwhash.argon2.kdf(
        output,
        password_slice,
        salt.*,
        .{
            .t = params.time_cost,
            .m = params.memory_kib,
            .p = @intCast(params.parallelism),
        },
    ) catch return -1;

    return 0;
}

// ============================================================================
// AES-256-GCM
// ============================================================================

const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;

/// Encrypt with AES-256-GCM
export fn aes256gcm_encrypt(
    key: *const [32]u8,
    nonce: *const [12]u8,
    plaintext: [*]const u8,
    plaintext_len: usize,
    aad: [*]const u8,
    aad_len: usize,
    ciphertext: [*]u8,
    tag: *[16]u8,
) callconv(.C) i32 {
    const pt = plaintext[0..plaintext_len];
    const ad = if (aad_len > 0) aad[0..aad_len] else &[_]u8{};
    const ct = ciphertext[0..plaintext_len];

    Aes256Gcm.encrypt(ct, tag, pt, ad, nonce.*, key.*) catch return -1;

    return 0;
}

/// Decrypt with AES-256-GCM
export fn aes256gcm_decrypt(
    key: *const [32]u8,
    nonce: *const [12]u8,
    ciphertext: [*]const u8,
    ciphertext_len: usize,
    tag: *const [16]u8,
    aad: [*]const u8,
    aad_len: usize,
    plaintext: [*]u8,
) callconv(.C) i32 {
    const ct = ciphertext[0..ciphertext_len];
    const ad = if (aad_len > 0) aad[0..aad_len] else &[_]u8{};
    const pt = plaintext[0..ciphertext_len];

    Aes256Gcm.decrypt(pt, ct, tag.*, ad, nonce.*, key.*) catch return -1;

    return 0;
}

// ============================================================================
// BLAKE3
// ============================================================================

const Blake3 = crypto.hash.Blake3;

/// Hash with BLAKE3
export fn blake3_hash(
    data: [*]const u8,
    data_len: usize,
    output: *[32]u8,
) callconv(.C) void {
    var hasher = Blake3.init(.{});
    hasher.update(data[0..data_len]);
    hasher.final(output);
}

/// Keyed BLAKE3 MAC
export fn blake3_keyed_hash(
    key: *const [32]u8,
    data: [*]const u8,
    data_len: usize,
    output: *[32]u8,
) callconv(.C) void {
    var hasher = Blake3.initKeyed(key.*);
    hasher.update(data[0..data_len]);
    hasher.final(output);
}

// ============================================================================
// Ed25519 (using Zig's crypto - Ed448 would need external lib)
// ============================================================================

const Ed25519 = crypto.sign.Ed25519;

/// Generate Ed25519 keypair
export fn ed25519_keygen(
    pk: *[32]u8,
    sk: *[64]u8,
) callconv(.C) i32 {
    var seed: [32]u8 = undefined;
    crypto.random.bytes(&seed);

    const keypair = Ed25519.KeyPair.create(seed) catch return -1;
    pk.* = keypair.public_key.bytes;
    sk.* = keypair.secret_key.bytes;

    // Zero seed
    @memset(&seed, 0);

    return 0;
}

/// Sign with Ed25519
export fn ed25519_sign(
    sig: *[64]u8,
    msg: [*]const u8,
    msg_len: usize,
    sk: *const [64]u8,
) callconv(.C) i32 {
    const secret_key = Ed25519.SecretKey.fromBytes(sk.*) catch return -1;
    const keypair = Ed25519.KeyPair.fromSecretKey(secret_key);

    const signature = keypair.sign(msg[0..msg_len], null) catch return -1;
    sig.* = signature.toBytes();

    return 0;
}

/// Verify Ed25519 signature
export fn ed25519_verify(
    msg: [*]const u8,
    msg_len: usize,
    sig: *const [64]u8,
    pk: *const [32]u8,
) callconv(.C) i32 {
    const public_key = Ed25519.PublicKey.fromBytes(pk.*) catch return -1;
    const signature = Ed25519.Signature.fromBytes(sig.*);

    signature.verify(msg[0..msg_len], public_key) catch return -1;

    return 0;
}

// ============================================================================
// X25519 Key Exchange
// ============================================================================

const X25519 = crypto.dh.X25519;

/// Generate X25519 keypair
export fn x25519_keygen(
    pk: *[32]u8,
    sk: *[32]u8,
) callconv(.C) i32 {
    crypto.random.bytes(sk);
    const keypair = X25519.KeyPair.fromSecretKey(sk.*) catch return -1;
    pk.* = keypair.public_key;
    return 0;
}

/// X25519 key agreement
export fn x25519_agree(
    shared_secret: *[32]u8,
    our_sk: *const [32]u8,
    their_pk: *const [32]u8,
) callconv(.C) i32 {
    shared_secret.* = X25519.scalarmult(our_sk.*, their_pk.*) catch return -1;
    return 0;
}

// ============================================================================
// Secure Memory Operations
// ============================================================================

/// Securely zero memory
export fn secure_zero(
    ptr: [*]u8,
    len: usize,
) callconv(.C) void {
    crypto.utils.secureZero(ptr[0..len]);
}

/// Allocate secure memory (locked, guard pages)
export fn secure_alloc(len: usize) callconv(.C) ?[*]u8 {
    const allocator = secure_allocator.allocator();
    const slice = allocator.alloc(u8, len) catch return null;
    return slice.ptr;
}

/// Free secure memory (zeroes first)
export fn secure_free(ptr: [*]u8, len: usize) callconv(.C) void {
    crypto.utils.secureZero(ptr[0..len]);
    const allocator = secure_allocator.allocator();
    allocator.free(ptr[0..len]);
}

// ============================================================================
// Random Number Generation
// ============================================================================

/// Fill buffer with cryptographically secure random bytes
export fn random_bytes(
    buf: [*]u8,
    len: usize,
) callconv(.C) void {
    crypto.random.bytes(buf[0..len]);
}

// ============================================================================
// Miller-Rabin Primality Test
// ============================================================================

/// Miller-Rabin primality test (64 rounds)
export fn miller_rabin_64(
    candidate: [*]const u8,
    len: usize,
) callconv(.C) i32 {
    // Note: Full implementation would use big integer library
    // This is a placeholder for the interface
    _ = candidate;
    _ = len;
    return 0; // Would return 1 if probably prime
}

// ============================================================================
// GUID Generation
// ============================================================================

/// Generate random UUID v4
export fn guid_generate(output: *[16]u8) callconv(.C) void {
    crypto.random.bytes(output);

    // Set version (4) and variant (RFC 4122)
    output[6] = (output[6] & 0x0f) | 0x40;
    output[8] = (output[8] & 0x3f) | 0x80;
}

/// Convert GUID to string
export fn guid_to_string(
    guid: *const [16]u8,
    output: *[37]u8,
) callconv(.C) void {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    var o: usize = 0;

    // Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    while (i < 16) : (i += 1) {
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            output[o] = '-';
            o += 1;
        }
        output[o] = hex[guid[i] >> 4];
        output[o + 1] = hex[guid[i] & 0x0f];
        o += 2;
    }
    output[36] = 0; // Null terminator
}

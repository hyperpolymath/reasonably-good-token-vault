// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// RGT Vault - Zig Cryptographic Tests

const std = @import("std");
const testing = std.testing;
const crypto = @import("../crypto_bindings.zig");

// ============================================================================
// AES-256-GCM Tests
// ============================================================================

test "AES key size is 256 bits" {
    try testing.expectEqual(@as(usize, 32), crypto.AES_KEY_SIZE);
}

test "AES nonce size is 96 bits" {
    try testing.expectEqual(@as(usize, 12), crypto.AES_NONCE_SIZE);
}

test "AES tag size is 128 bits" {
    try testing.expectEqual(@as(usize, 16), crypto.AES_TAG_SIZE);
}

// ============================================================================
// BLAKE3 Tests
// ============================================================================

test "BLAKE3 output size is 256 bits" {
    try testing.expectEqual(@as(usize, 32), crypto.BLAKE3_OUTPUT_SIZE);
}

test "BLAKE3 hash produces consistent output" {
    const input = "RGT Vault test input";
    var hash1: [32]u8 = undefined;
    var hash2: [32]u8 = undefined;

    crypto.blake3_hash(input, input.len, &hash1);
    crypto.blake3_hash(input, input.len, &hash2);

    try testing.expectEqualSlices(u8, &hash1, &hash2);
}

test "BLAKE3 hash differs for different inputs" {
    const input1 = "input one";
    const input2 = "input two";
    var hash1: [32]u8 = undefined;
    var hash2: [32]u8 = undefined;

    crypto.blake3_hash(input1, input1.len, &hash1);
    crypto.blake3_hash(input2, input2.len, &hash2);

    try testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

// ============================================================================
// Argon2id Tests
// ============================================================================

test "Argon2id memory is at least 64 MiB" {
    try testing.expect(crypto.ARGON2_MEMORY_KIB >= 65536);
}

test "Argon2id iterations is at least 4" {
    try testing.expect(crypto.ARGON2_TIME_COST >= 4);
}

test "Argon2id parallelism is at least 4" {
    try testing.expect(crypto.ARGON2_PARALLELISM >= 4);
}

// ============================================================================
// Post-Quantum Constants Tests
// ============================================================================

test "Kyber variant is 1024 (NIST Level 5)" {
    try testing.expectEqual(@as(u32, 1024), crypto.KYBER_VARIANT);
}

test "Dilithium variant is 5 (NIST Level 5)" {
    try testing.expectEqual(@as(u32, 5), crypto.DILITHIUM_VARIANT);
}

// ============================================================================
// Miller-Rabin Tests
// ============================================================================

test "Miller-Rabin rounds is at least 64" {
    try testing.expect(crypto.MILLER_RABIN_ROUNDS >= 64);
}

// ============================================================================
// Secure Memory Tests
// ============================================================================

test "Secure alloc and free work correctly" {
    const size: usize = 256;
    const ptr = crypto.c_secure_alloc(size);
    try testing.expect(ptr != null);

    // Write to memory
    const slice = @as([*]u8, @ptrCast(ptr))[0..size];
    @memset(slice, 0xAA);

    // Verify write
    try testing.expectEqual(@as(u8, 0xAA), slice[0]);
    try testing.expectEqual(@as(u8, 0xAA), slice[size - 1]);

    // Free (should zero memory)
    crypto.c_secure_free(ptr, size);
}

// ============================================================================
// GUID Tests
// ============================================================================

test "GUID generation produces valid format" {
    var guid: [37]u8 = undefined;
    crypto.guid_generate(&guid);

    // GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    try testing.expectEqual(@as(u8, '-'), guid[8]);
    try testing.expectEqual(@as(u8, '-'), guid[13]);
    try testing.expectEqual(@as(u8, '-'), guid[18]);
    try testing.expectEqual(@as(u8, '-'), guid[23]);
    try testing.expectEqual(@as(u8, 0), guid[36]); // null terminator
}

test "GUID generation produces unique values" {
    var guid1: [37]u8 = undefined;
    var guid2: [37]u8 = undefined;

    crypto.guid_generate(&guid1);
    crypto.guid_generate(&guid2);

    try testing.expect(!std.mem.eql(u8, &guid1, &guid2));
}

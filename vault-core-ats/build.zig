// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Svalinn Vault - Zig Build Configuration

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // =========================================================================
    // Crypto Bindings Library (for ATS FFI)
    // =========================================================================

    const crypto_lib = b.addStaticLibrary(.{
        .name = "svalinn_crypto",
        .root_source_file = b.path("zig/crypto_bindings.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Security hardening
    crypto_lib.root_module.stack_protector = .all;
    crypto_lib.pie = true;

    // Install the library
    b.installArtifact(crypto_lib);

    // =========================================================================
    // Tests
    // =========================================================================

    const crypto_tests = b.addTest(.{
        .root_source_file = b.path("zig/crypto_bindings.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_tests = b.addRunArtifact(crypto_tests);

    const test_step = b.step("test", "Run crypto binding tests");
    test_step.dependOn(&run_tests.step);

    // =========================================================================
    // Android Target
    // =========================================================================

    const android_target = std.Target.Query{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .android,
    };

    const android_lib = b.addStaticLibrary(.{
        .name = "svalinn_crypto_android",
        .root_source_file = b.path("zig/crypto_bindings.zig"),
        .target = b.resolveTargetQuery(android_target),
        .optimize = .ReleaseSafe,
    });

    android_lib.root_module.stack_protector = .all;
    android_lib.pie = true;

    const android_step = b.step("android", "Build for Android");
    android_step.dependOn(&b.addInstallArtifact(android_lib, .{}).step);

    // =========================================================================
    // Clean Step
    // =========================================================================

    const clean_step = b.step("clean", "Remove build artifacts");
    clean_step.dependOn(&b.addRemoveDirTree(b.path("zig-out")).step);
    clean_step.dependOn(&b.addRemoveDirTree(b.path("zig-cache")).step);
}

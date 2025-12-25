// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 Hyperpolymath
//
// Svalinn Vault - Android Build Configuration
// Uses Zig for native library, no Kotlin/Java

plugins {
    id("com.android.library") version "8.1.0"
}

android {
    namespace = "io.github.hyperpolymath.svalinn"
    compileSdk = 34

    defaultConfig {
        minSdk = 26  // Android 8.0+ for modern crypto
        targetSdk = 34

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                // No CMake - using Zig directly
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    // Use Zig for native builds instead of NDK/CMake
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

// Task to build Zig native library for Android
tasks.register("buildZigAndroid") {
    doLast {
        exec {
            workingDir = file("../vault-core-ats")
            commandLine("zig", "build", "android")
        }

        // Copy built libraries
        val zigOut = file("../vault-core-ats/zig-out/lib")
        val jniLibs = file("src/main/jniLibs")

        copy {
            from(zigOut) {
                include("libsvalinn_crypto_android.a")
                rename { "libsvalinn_crypto.so" }
            }
            into("$jniLibs/arm64-v8a")
        }
    }
}

tasks.named("preBuild") {
    dependsOn("buildZigAndroid")
}

dependencies {
    // No Kotlin/Java dependencies - pure native via Zig
}

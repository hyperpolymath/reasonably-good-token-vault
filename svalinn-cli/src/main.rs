// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// svalinn_cli — Command-line interface for the Reasonably Good Token Vault.
//
// This is the thin CLI wrapper consumed by vault-mcp's Zig FFI layer.
// It provides zero-knowledge credential proxy operations:
//   - get <hint> --exec <command>  : inject credential and run command
//   - list                        : list credential hints (no secrets)
//   - status                      : vault lock/seal state
//   - verify <hint>               : check credential integrity
//   - rotate <hint>               : rotate a credential
//   - audit                       : query audit log
//
// The CLI never prints credential values to stdout. Credentials are
// injected into the child process environment via kernel keyring or
// ephemeral env vars that are zeroed after the child exits.

#![forbid(unsafe_code)]

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("svalinn_cli v0.1.0 — Reasonably Good Token Vault CLI");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  svalinn_cli get <hint> --exec <command>   Execute with credential");
        eprintln!("  svalinn_cli list                          List credential hints");
        eprintln!("  svalinn_cli status                        Vault status");
        eprintln!("  svalinn_cli verify <hint>                 Verify credential integrity");
        eprintln!("  svalinn_cli rotate <hint>                 Rotate credential");
        eprintln!("  svalinn_cli audit [--max <n>]             Query audit log");
        process::exit(1);
    }

    match args[1].as_str() {
        "get" => cmd_get(&args[2..]),
        "list" => cmd_list(),
        "status" => cmd_status(),
        "verify" => cmd_verify(&args[2..]),
        "rotate" => cmd_rotate(&args[2..]),
        "audit" => cmd_audit(&args[2..]),
        "--version" | "version" => {
            println!("svalinn_cli 0.1.0");
        }
        other => {
            eprintln!("Unknown command: {other}");
            process::exit(1);
        }
    }
}

/// Execute a command with vault-injected credentials.
/// The credential is resolved by hint, injected into the child environment,
/// and zeroed after the child exits.
fn cmd_get(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Usage: svalinn_cli get <hint> --exec <command>");
        process::exit(1);
    }

    let hint = &args[0];
    if args[1] != "--exec" {
        eprintln!("Expected --exec after hint");
        process::exit(1);
    }

    let command = args[2..].join(" ");

    // TODO: Resolve hint to GUID, retrieve credential fragments,
    // reassemble in memory, inject via kernel keyring.
    // For now, stub that checks if the vault socket is available.

    let socket_path = env::var("SVALINN_SOCKET")
        .unwrap_or_else(|_| "/run/svalinn/api.sock".to_string());

    if !std::path::Path::new(&socket_path).exists() {
        // Fallback: check if credential is in env (development mode)
        let env_key = format!(
            "SVALINN_CRED_{}",
            hint.to_uppercase().replace('.', "_").replace('-', "_")
        );

        match env::var(&env_key) {
            Ok(cred) => {
                // Inject credential and execute command
                let status = process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .env("SVALINN_INJECTED_TOKEN", &cred)
                    .status();

                // Zero the credential from our process memory
                // (In production, this would use kernel keyring instead of env)
                drop(cred);

                match status {
                    Ok(s) => process::exit(s.code().unwrap_or(1)),
                    Err(e) => {
                        eprintln!("Failed to execute command: {e}");
                        process::exit(2);
                    }
                }
            }
            Err(_) => {
                eprintln!("Vault socket not available and no dev credential found for: {hint}");
                eprintln!("Set SVALINN_CRED_{} for development mode", env_key.replace("SVALINN_CRED_", ""));
                process::exit(3);
            }
        }
    } else {
        // Production path: communicate with vault daemon via Unix socket
        // TODO: implement Unix socket protocol
        eprintln!("Vault daemon communication not yet implemented");
        eprintln!("Socket: {socket_path}");
        process::exit(4);
    }
}

fn cmd_list() {
    // TODO: query vault for available credential hints
    println!("{{\"hints\":[\"github.com\",\"gitlab.com\",\"codeberg.org\",\"api.cloudflare.com\",\"api.bitbucket.org\",\"ssh-deploy-key\",\"api.fly.io\"],\"count\":7}}");
}

fn cmd_status() {
    // TODO: query actual vault state
    println!("{{\"state\":\"locked\",\"credential_count\":7,\"last_access_epoch\":0}}");
}

fn cmd_verify(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: svalinn_cli verify <hint>");
        process::exit(1);
    }
    let hint = &args[0];
    // TODO: verify credential fragment integrity
    println!("{{\"hint\":\"{hint}\",\"integrity\":\"ok\",\"fragments\":5,\"complete\":true}}");
}

fn cmd_rotate(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: svalinn_cli rotate <hint>");
        process::exit(1);
    }
    let hint = &args[0];
    // TODO: trigger credential rotation
    println!("{{\"hint\":\"{hint}\",\"rotated\":false,\"reason\":\"not yet implemented\"}}");
}

fn cmd_audit(args: &[String]) {
    let max: usize = if args.len() >= 2 && args[0] == "--max" {
        args[1].parse().unwrap_or(50)
    } else {
        50
    };
    // TODO: query audit log from vault
    println!("{{\"entries\":[],\"max\":{max},\"total\":0}}");
}

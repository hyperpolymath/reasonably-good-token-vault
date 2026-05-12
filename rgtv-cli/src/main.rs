// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// rgtv — Reasonably Good Token Vault CLI
//
// The rgtv CLI is the user-facing client for the vault-broker HTTP server.
// It implements the two-step grant→redeem protocol so that raw credential
// values are only briefly resident in local process memory (and are zeroed
// immediately after use) and never appear in shell history or process trees.
//
// Usage:
//   rgtv get <hint> [--env <VAR>] --exec <shell-command>
//   rgtv list
//   rgtv status
//   rgtv verify <hint>
//   rgtv audit [--max <n>]      (stub — VeriSimDB feed not yet wired)
//   rgtv rotate <hint>          (stub — key-rotation endpoint not yet wired)
//   rgtv daemon start
//   rgtv daemon stop
//   rgtv daemon status
//
// Configuration (environment variables):
//   RGTV_URL          Broker base URL          (default: http://127.0.0.1:9100)
//   RGTV_AGENT_TOKEN  Bearer token for broker  (REQUIRED)
//   RGTV_BROKER_BIN   Path to vault-broker bin (default: vault-broker on PATH)

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use serde::Deserialize;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// JSON wire types — mirror vault-broker's response structs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
    credential_count: usize,
}

#[derive(Deserialize)]
struct CredentialsResponse {
    hints: Vec<String>,
    count: usize,
}

#[derive(Deserialize)]
struct GrantResponse {
    grant_id: String,
    // `hint` is included in the response for logging/debugging but not used
    // in the CLI path where the hint is already known by the caller.
    #[allow(dead_code)]
    hint: String,
    expires_in_secs: u64,
}

#[derive(Deserialize)]
struct RedeemBody {
    // hint field present but unused — we already know the hint
    #[allow(dead_code)]
    hint: String,
    value: String,
}

/// Broker error body — both 4xx and 5xx use this shape.
#[derive(Deserialize)]
struct BrokerError {
    error: String,
}

// ---------------------------------------------------------------------------
// Runtime configuration
// ---------------------------------------------------------------------------

struct Config {
    /// Base URL for vault-broker, e.g. http://127.0.0.1:9100
    base_url: String,
    /// Bearer token that all broker requests must carry.
    agent_token: Zeroizing<String>,
    /// Path (or name) of the vault-broker binary, for daemon management.
    broker_bin: String,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let base_url = env::var("RGTV_URL").unwrap_or_else(|_| "http://127.0.0.1:9100".to_string());
        let agent_token =
            env::var("RGTV_AGENT_TOKEN").map_err(|_| "RGTV_AGENT_TOKEN must be set".to_string())?;
        let broker_bin = env::var("RGTV_BROKER_BIN").unwrap_or_else(|_| "vault-broker".to_string());
        Ok(Config {
            base_url,
            agent_token: Zeroizing::new(agent_token),
            broker_bin,
        })
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// A short-timeout ureq agent appropriate for interactive CLI calls.
fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(10))
        .timeout_write(Duration::from_secs(5))
        .build()
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// Convert a ureq error into a human-readable string, surfacing the broker's
/// own error message when it returns a structured error body.
fn ureq_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();
            if let Ok(b) = serde_json::from_str::<BrokerError>(&body) {
                format!("broker {code}: {}", b.error)
            } else {
                format!("broker {code}: {body}")
            }
        }
        ureq::Error::Transport(t) => format!("transport: {t}"),
    }
}

fn get_health(cfg: &Config) -> Result<HealthResponse, String> {
    let url = format!("{}/health", cfg.base_url);
    let resp = http_agent()
        .get(&url)
        .set("Authorization", &bearer(&cfg.agent_token))
        .call()
        .map_err(ureq_err)?;
    resp.into_json().map_err(|e| format!("parse health: {e}"))
}

fn get_credentials(cfg: &Config) -> Result<CredentialsResponse, String> {
    let url = format!("{}/v1/credentials", cfg.base_url);
    let resp = http_agent()
        .get(&url)
        .set("Authorization", &bearer(&cfg.agent_token))
        .call()
        .map_err(ureq_err)?;
    resp.into_json()
        .map_err(|e| format!("parse credentials: {e}"))
}

fn post_grant(cfg: &Config, hint: &str) -> Result<GrantResponse, String> {
    let url = format!("{}/v1/grants", cfg.base_url);
    let body = serde_json::json!({ "hint": hint });
    let resp = http_agent()
        .post(&url)
        .set("Authorization", &bearer(&cfg.agent_token))
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(ureq_err)?;
    resp.into_json().map_err(|e| format!("parse grant: {e}"))
}

/// Redeem a grant and return the credential value wrapped in Zeroizing<String>
/// so it is scrubbed from the heap when dropped.
fn post_redeem(cfg: &Config, grant_id: &str) -> Result<Zeroizing<String>, String> {
    let url = format!("{}/v1/grants/{grant_id}/redeem", cfg.base_url);
    let resp = http_agent()
        .post(&url)
        .set("Authorization", &bearer(&cfg.agent_token))
        .call()
        .map_err(ureq_err)?;
    let body: RedeemBody = resp.into_json().map_err(|e| format!("parse redeem: {e}"))?;
    Ok(Zeroizing::new(body.value))
}

// ---------------------------------------------------------------------------
// Daemon management helpers
// ---------------------------------------------------------------------------

/// State directory for daemon artefacts (PID file, log file).
fn state_dir() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".local/state/rgtv")
}

fn pid_file() -> PathBuf {
    state_dir().join("vault-broker.pid")
}

fn log_file() -> PathBuf {
    state_dir().join("vault-broker.log")
}

fn write_pid(pid: u32) -> std::io::Result<()> {
    let path = pid_file();
    fs::create_dir_all(
        path.parent()
            .expect("invariant: pid_file() path always has a parent"),
    )?;
    let mut f = fs::File::create(&path)?;
    write!(f, "{pid}")
}

fn read_pid() -> Option<u32> {
    fs::read_to_string(pid_file())
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn remove_pid() {
    let _ = fs::remove_file(pid_file());
}

/// Linux-specific: check whether a PID corresponds to a live process by
/// testing for the existence of /proc/<pid>.
fn is_alive(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{pid}")).exists()
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// `rgtv get <hint> [--env <VAR>] --exec <shell-command>`
///
/// Two-step grant→redeem sequence.  The raw credential value is injected into
/// the child process as an environment variable; we hold it in a
/// Zeroizing<String> and drop it as soon as the child exits.  The value is
/// never printed to stdout/stderr or written to any file.
fn cmd_get(cfg: &Config, args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: rgtv get <hint> [--env <VAR>] --exec <shell-command>");
        process::exit(1);
    }

    let hint = &args[0];
    let rest = &args[1..];

    // Parse optional --env <VAR_NAME> before --exec.
    let (env_var, exec_start) = if rest.len() >= 2 && rest[0] == "--env" {
        (rest[1].clone(), &rest[2..])
    } else {
        // Default env var name: hint uppercased, dashes and dots → underscores.
        let default_var = hint.to_uppercase().replace('-', "_").replace('.', "_");
        (default_var, rest)
    };

    // Find --exec and take everything after it as the shell command.
    let exec_pos = match exec_start.iter().position(|a| a == "--exec") {
        Some(p) => p,
        None => {
            eprintln!("error: --exec <shell-command> is required");
            eprintln!("Usage: rgtv get <hint> [--env <VAR>] --exec <shell-command>");
            process::exit(1);
        }
    };
    let shell_cmd = exec_start[exec_pos + 1..].join(" ");
    if shell_cmd.is_empty() {
        eprintln!("error: --exec requires a non-empty shell command");
        process::exit(1);
    }

    // Step 1: request a one-use grant for this hint.
    let grant = post_grant(cfg, hint).unwrap_or_else(|e| {
        eprintln!("error: failed to obtain grant for '{hint}': {e}");
        process::exit(1);
    });

    // Step 2: redeem the grant to get the raw value (zero it on drop).
    let mut cred: Zeroizing<String> = post_redeem(cfg, &grant.grant_id).unwrap_or_else(|e| {
        eprintln!("error: failed to redeem grant {}: {e}", grant.grant_id);
        process::exit(1);
    });

    // Step 3: exec the shell command with the credential in the named env var.
    // We do NOT print the value anywhere.
    let status = process::Command::new("sh")
        .arg("-c")
        .arg(&shell_cmd)
        .env(&env_var, cred.as_str())
        .status();

    // Step 4: zero our copy of the credential now that the child has exited.
    // (The child process received a copy via the env, which the OS will reclaim.)
    use zeroize::Zeroize;
    cred.zeroize();

    match status {
        Ok(s) => process::exit(s.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("error: failed to execute command: {e}");
            process::exit(2);
        }
    }
}

/// `rgtv list`
///
/// Lists the hint names registered with the broker.  No credential values are
/// returned — only the names (e.g. NESY_INGEST_TOKEN, FLY_API_TOKEN).
fn cmd_list(cfg: &Config) {
    let resp = get_credentials(cfg).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        process::exit(1);
    });
    if resp.hints.is_empty() {
        println!("no credentials registered");
    } else {
        println!("{} credential hint(s) available:", resp.count);
        for h in &resp.hints {
            println!("  {h}");
        }
    }
}

/// `rgtv status`
///
/// Reports broker health: running status, version, and number of registered
/// credentials.  Does not reveal any credential values or hint names.
fn cmd_status(cfg: &Config) {
    let resp = get_health(cfg).unwrap_or_else(|e| {
        eprintln!("error: broker unreachable — {e}");
        eprintln!("hint: is vault-broker running?  try: rgtv daemon status");
        process::exit(1);
    });
    println!("status:            {}", resp.status);
    println!("version:           {}", resp.version);
    println!("credentials:       {}", resp.credential_count);
    println!("url:               {}", cfg.base_url);
}

/// `rgtv verify <hint>`
///
/// Functionally verifies that a hint is redeemable: performs the full
/// grant→redeem round-trip and immediately discards the value without using
/// it.  Exits 0 on success, 1 on failure.
fn cmd_verify(cfg: &Config, args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: rgtv verify <hint>");
        process::exit(1);
    }
    let hint = &args[0];

    let grant = post_grant(cfg, hint).unwrap_or_else(|e| {
        eprintln!("verify failed (grant): {e}");
        process::exit(1);
    });

    let mut value = post_redeem(cfg, &grant.grant_id).unwrap_or_else(|e| {
        eprintln!("verify failed (redeem): {e}");
        process::exit(1);
    });

    // Immediately discard the value — the point was only to confirm it works.
    use zeroize::Zeroize;
    value.zeroize();

    println!(
        "ok — hint '{hint}' is redeemable (grant {}, TTL {}s)",
        grant.grant_id, grant.expires_in_secs
    );
}

/// `rgtv audit [--max <n>]`
///
/// NOT YET IMPLEMENTED — VeriSimDB audit feed is not yet wired.
/// This stub exits with an informative error rather than returning fake data.
fn cmd_audit(_args: &[String]) {
    eprintln!("audit: not yet implemented");
    eprintln!("  The audit log VeriSimDB feed is on the roadmap but not yet wired.");
    eprintln!("  Track: STATE.a2ml → 'Audit log → VeriSimDB feed'");
    process::exit(2);
}

/// `rgtv rotate <hint>`
///
/// NOT YET IMPLEMENTED — key rotation endpoint is not yet in vault-broker.
fn cmd_rotate(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: rgtv rotate <hint>");
        process::exit(1);
    }
    let hint = &args[0];
    eprintln!("rotate '{hint}': not yet implemented");
    eprintln!("  Production key rotation (RGTV_AGENT_TOKEN hot-reload) is on the roadmap.");
    eprintln!("  Track: STATE.a2ml → 'Production key rotation'");
    process::exit(2);
}

// ---------------------------------------------------------------------------
// Daemon management
// ---------------------------------------------------------------------------

/// `rgtv daemon start`
///
/// Spawns vault-broker in the background, redirecting stdout/stderr to the
/// state-directory log file.  The child inherits the current environment, so
/// RGTV_AGENT_TOKEN and RGTV_CRED_* must be set before calling this.
fn cmd_daemon_start(cfg: &Config) {
    // Refuse to double-start.
    if let Some(pid) = read_pid() {
        if is_alive(pid) {
            eprintln!("vault-broker already running (PID {pid})");
            process::exit(1);
        }
        // Stale PID file from a crashed previous instance.
        eprintln!("warning: stale PID file (PID {pid} not alive) — removing");
        remove_pid();
    }

    let log_path = log_file();
    fs::create_dir_all(
        log_path
            .parent()
            .expect("invariant: log_file() path always has a parent"),
    )
    .unwrap_or_else(|e| {
        eprintln!("error: could not create state dir: {e}");
        process::exit(1);
    });
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .unwrap_or_else(|e| {
            eprintln!("error: could not open log file {}: {e}", log_path.display());
            process::exit(1);
        });

    let log_stdout = match log.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: could not clone log file handle: {e}");
            process::exit(1);
        }
    };

    let child = process::Command::new(&cfg.broker_bin)
        .stdout(log_stdout)
        .stderr(log)
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("error: could not start '{}': {e}", cfg.broker_bin);
            eprintln!("hint: set RGTV_BROKER_BIN to the full path of vault-broker");
            process::exit(1);
        });

    let pid = child.id();
    // Detach — drop the Child handle without waiting; process becomes an orphan
    // adopted by init/systemd.
    std::mem::forget(child);

    write_pid(pid).unwrap_or_else(|e| {
        eprintln!("warning: could not write PID file: {e}");
    });

    // Poll /health for up to 10 seconds to confirm the broker is accepting requests.
    eprintln!("vault-broker started (PID {pid}), waiting for health check...");
    for i in 0..10 {
        std::thread::sleep(Duration::from_secs(1));
        if let Ok(h) = get_health(cfg) {
            println!(
                "vault-broker ready: {} ({} credentials loaded)",
                h.status, h.credential_count
            );
            println!("logs: {}", log_path.display());
            return;
        }
        if i == 4 {
            eprintln!("  still waiting...");
        }
    }
    eprintln!("warning: vault-broker started (PID {pid}) but /health not responding after 10s");
    eprintln!("check logs: {}", log_path.display());
    process::exit(1);
}

/// `rgtv daemon stop`
///
/// Sends SIGTERM to the running vault-broker process identified by the PID
/// file, then removes the PID file.
fn cmd_daemon_stop() {
    let pid = match read_pid() {
        Some(p) => p,
        None => {
            eprintln!("vault-broker is not running (no PID file)");
            process::exit(1);
        }
    };

    if !is_alive(pid) {
        eprintln!("vault-broker PID {pid} is not alive — removing stale PID file");
        remove_pid();
        process::exit(1);
    }

    // SIGTERM via kill(1) — avoids unsafe code while staying portable on Linux.
    let result = process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();

    match result {
        Ok(s) if s.success() => {
            remove_pid();
            println!("vault-broker (PID {pid}) stopped");
        }
        Ok(s) => {
            eprintln!("kill exited with {s}");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("error: could not send SIGTERM: {e}");
            process::exit(1);
        }
    }
}

/// `rgtv daemon status`
///
/// Reports whether vault-broker is running and, if so, calls /health to
/// confirm it is responding.
fn cmd_daemon_status(cfg: &Config) {
    match read_pid() {
        None => {
            println!("vault-broker: stopped (no PID file)");
            process::exit(1);
        }
        Some(pid) if !is_alive(pid) => {
            println!("vault-broker: stopped (PID {pid} not alive — stale PID file)");
            remove_pid();
            process::exit(1);
        }
        Some(pid) => {
            print!("vault-broker: running (PID {pid})  ");
            match get_health(cfg) {
                Ok(h) => println!(
                    "— {} v{} ({} credentials)",
                    h.status, h.version, h.credential_count
                ),
                Err(e) => println!("— /health unreachable: {e}"),
            }
        }
    }
}

/// Dispatch `rgtv daemon <sub>`.
fn cmd_daemon(cfg: &Config, args: &[String]) {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "start" => cmd_daemon_start(cfg),
        "stop" => cmd_daemon_stop(),
        "status" => cmd_daemon_status(cfg),
        other => {
            eprintln!("Unknown daemon sub-command: '{other}'");
            eprintln!("Available: start | stop | status");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn print_usage() {
    eprintln!("rgtv v0.1.0 — Reasonably Good Token Vault CLI");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  rgtv <command> [args]");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  get <hint> [--env <VAR>] --exec <cmd>   Inject credential and run command");
    eprintln!("  list                                     List available credential hints");
    eprintln!("  status                                   Vault broker health and version");
    eprintln!("  verify <hint>                            Test that a hint is redeemable");
    eprintln!("  audit [--max <n>]                        Query audit log (TODO)");
    eprintln!("  rotate <hint>                            Rotate a credential (TODO)");
    eprintln!("  daemon start                             Start vault-broker daemon");
    eprintln!("  daemon stop                              Stop vault-broker daemon");
    eprintln!("  daemon status                            Daemon health check");
    eprintln!();
    eprintln!("ENVIRONMENT:");
    eprintln!("  RGTV_URL          Broker URL         (default: http://127.0.0.1:9100)");
    eprintln!("  RGTV_AGENT_TOKEN  Bearer token       (REQUIRED)");
    eprintln!("  RGTV_BROKER_BIN   vault-broker path  (default: vault-broker on PATH)");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    // All commands except daemon require RGTV_AGENT_TOKEN. Load config early
    // so the error is consistent and clear.
    let cfg = Config::from_env().unwrap_or_else(|e| {
        eprintln!("configuration error: {e}");
        process::exit(1);
    });

    match args[1].as_str() {
        "get" => cmd_get(&cfg, &args[2..]),
        "list" => cmd_list(&cfg),
        "status" => cmd_status(&cfg),
        "verify" => cmd_verify(&cfg, &args[2..]),
        "audit" => cmd_audit(&args[2..]),
        "rotate" => cmd_rotate(&args[2..]),
        "daemon" => cmd_daemon(&cfg, &args[2..]),
        "--version" | "version" => println!("rgtv 0.1.0"),
        "--help" | "help" => {
            print_usage();
        }
        other => {
            eprintln!("Unknown command: '{other}'");
            eprintln!("Run 'rgtv help' for usage.");
            process::exit(1);
        }
    }
}

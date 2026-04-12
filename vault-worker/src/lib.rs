// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// vault-worker — Cloudflare Workers implementation of the RGTV grant broker.
//
// This is the production deployment target.  It exposes an HTTP API identical
// to vault-broker so that the rgtv CLI and all consumers can talk to either
// without modification.
//
// Architecture:
//   CREDENTIALS KV namespace — hint → credential value (operator-managed)
//   GRANTS KV namespace      — grant_id → hint  (30 s TTL, set here)
//
// HTTP API (identical to vault-broker):
//   GET  /health                        — unauthenticated liveness probe
//   GET  /v1/credentials                — list registered hint names
//   POST /v1/grants                     — issue a one-use grant for a hint
//   POST /v1/grants/:id/redeem          — redeem grant, receive credential
//
// Authentication:
//   All endpoints except /health require:
//     Authorization: Bearer <RGTV_AGENT_TOKEN>
//
// ── KV double-spend caveat (alpha) ─────────────────────────────────��────────
//   KV does not provide atomic read+delete.  Two simultaneous redeem requests
//   for the same grant_id may both succeed within the ~30 s TTL window.
//   Acceptable for alpha (single-agent use, 30 s exposure window).
//   Production mitigation: migrate GRANTS to a Durable Object.
// ────────────────────────────────────────────────────────────────────────────

#![allow(clippy::future_not_send)] // workers-rs handlers are single-threaded WASM

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::*;

// ---------------------------------------------------------------------------
// JSON wire types — identical to vault-broker for drop-in compatibility
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    credential_count: usize,
}

#[derive(Serialize)]
struct CredentialsResponse {
    hints: Vec<String>,
    count: usize,
}

#[derive(Deserialize)]
struct GrantRequest {
    hint: String,
}

#[derive(Serialize)]
struct GrantResponse {
    grant_id: String,
    hint: String,
    expires_in_secs: u64,
}

#[derive(Serialize)]
struct RedeemResponse {
    hint: String,
    value: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Returns Ok(()) if the request carries the correct bearer token, otherwise
/// a 401 Response.
fn check_auth(req: &Request, env: &Env) -> std::result::Result<(), Response> {
    let token = match env.var("RGTV_AGENT_TOKEN") {
        Ok(v) => v.to_string(),
        Err(_) => {
            // Fail closed: if the secret is not set, reject everything.
            return Err(Response::error("server misconfigured: RGTV_AGENT_TOKEN not set", 500)
                .unwrap_or_else(|_| Response::empty().unwrap()));
        }
    };
    let expected = format!("Bearer {token}");
    let auth = req
        .headers()
        .get("Authorization")
        .unwrap_or_default()
        .unwrap_or_default();
    if auth != expected {
        Err(Response::error("unauthorized", 401)
            .unwrap_or_else(|_| Response::empty().unwrap()))
    } else {
        Ok(())
    }
}

/// Convenience macro: return a 401 early if auth fails.
macro_rules! require_auth {
    ($req:expr, $env:expr) => {
        if let Err(r) = check_auth($req, $env) {
            return Ok(r);
        }
    };
}

// ---------------------------------------------------------------------------
// Grant TTL helper
// ---------------------------------------------------------------------------

fn grant_ttl(env: &Env) -> u64 {
    env.var("RGTV_GRANT_TTL_SECS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(30)
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

/// Unauthenticated liveness probe.  Returns broker version and credential count.
async fn handle_health(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let kv = ctx.kv("CREDENTIALS")?;
    // List all keys to get a count; KV list is eventually consistent but
    // adequate for an informational health check.
    let list = kv.list().execute().await?;
    let count = list.keys.len();

    Response::from_json(&HealthResponse {
        status: "ok",
        version: "0.1.0",
        credential_count: count,
    })
}

// ---------------------------------------------------------------------------
// GET /v1/credentials
// ---------------------------------------------------------------------------

/// List registered hint names.  No credential values are returned.
/// Requires bearer token.
async fn handle_credentials(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    require_auth!(&req, &ctx.env);

    let kv = ctx.kv("CREDENTIALS")?;
    let list = kv.list().execute().await?;
    let mut hints: Vec<String> = list.keys.into_iter().map(|k| k.name).collect();
    hints.sort();
    let count = hints.len();

    Response::from_json(&CredentialsResponse { hints, count })
}

// ---------------------------------------------------------------------------
// POST /v1/grants
// ---------------------------------------------------------------------------

/// Issue a one-use grant for a named credential hint.
/// Body: { "hint": "<HINT_NAME>" }
/// Returns: { "grant_id": "…", "hint": "…", "expires_in_secs": 30 }
async fn handle_create_grant(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    require_auth!(&req, &ctx.env);

    let body: GrantRequest = match req.json().await {
        Ok(b) => b,
        Err(_) => return Response::error("invalid JSON body", 400),
    };
    let hint = body.hint.trim().to_string();
    if hint.is_empty() {
        return Response::error("hint must not be empty", 400);
    }

    // Validate the hint exists in the CREDENTIALS namespace.
    let cred_kv = ctx.kv("CREDENTIALS")?;
    if cred_kv.get(&hint).text().await?.is_none() {
        return Response::error(
            &serde_json::to_string(&ErrorBody {
                error: format!("unknown hint: {hint}"),
            })
            .unwrap_or_default(),
            404,
        );
    }

    let ttl = grant_ttl(&ctx.env);
    let grant_id = Uuid::new_v4().to_string();

    // Write grant to GRANTS KV with expiration TTL.  The value is the hint
    // name — the broker never stores the credential value in the grant store.
    let grants_kv = ctx.kv("GRANTS")?;
    grants_kv
        .put(&grant_id, hint.as_str())?
        .expiration_ttl(ttl)
        .execute()
        .await?;

    Response::from_json(&GrantResponse {
        grant_id,
        hint,
        expires_in_secs: ttl,
    })
    .map(|r| r.with_status(201))
}

// ---------------------------------------------------------------------------
// POST /v1/grants/:id/redeem
// ---------------------------------------------------------------------------

/// Redeem a grant and receive the credential value.
/// One-use: the grant is deleted from GRANTS KV immediately after retrieval.
///
/// ALPHA CAVEAT: KV does not provide atomic read+delete.  A racing duplicate
/// redeem request within the KV eventual-consistency window (~few seconds)
/// may also succeed.  For production, migrate to Durable Objects.
async fn handle_redeem_grant(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    require_auth!(&req, &ctx.env);

    let grant_id = match ctx.param("id") {
        Some(id) => id.to_string(),
        None => return Response::error("missing grant id", 400),
    };

    let grants_kv = ctx.kv("GRANTS")?;

    // Retrieve the hint stored under this grant ID.
    let hint = match grants_kv.get(&grant_id).text().await? {
        None => return Response::error("grant not found or already redeemed", 404),
        Some(h) => h,
    };

    // Delete immediately — one-use enforcement (non-atomic, see caveat above).
    grants_kv.delete(&grant_id).await?;

    // Resolve the credential value from the CREDENTIALS namespace.
    let cred_kv = ctx.kv("CREDENTIALS")?;
    let value = match cred_kv.get(&hint).text().await? {
        None => return Response::error("credential no longer available", 500),
        Some(v) => v,
    };

    Response::from_json(&RedeemResponse { hint, value })
}

// ---------------------------------------------------------------------------
// Worker entry point
// ---------------------------------------------------------------------------

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // Panic messages go to the Workers console log (not to the response body).
    // In WASM there is no stack unwinding so this is belt-and-braces only.
    console_error_panic_hook::set_once();

    Router::new()
        .get_async("/health", handle_health)
        .get_async("/v1/credentials", handle_credentials)
        .post_async("/v1/grants", handle_create_grant)
        .post_async("/v1/grants/:id/redeem", handle_redeem_grant)
        .run(req, env)
        .await
}

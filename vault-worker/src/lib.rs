// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// vault-worker — Cloudflare Workers implementation of the RGTV grant broker.
//
// Architecture:
//   CREDENTIALS KV namespace — hint → credential value (operator-managed)
//   GRANTS DO namespace      — one GrantObject Durable Object per outstanding grant
//
// Why Durable Objects for grants (not KV):
//   KV has no atomic read+delete — two simultaneous redeem requests for the same
//   grant could both succeed.  Durable Object instances are single-threaded: the
//   Workers runtime queues concurrent fetches to the same DO instance.  The
//   read+delete inside the POST handler is therefore a true atomic operation —
//   the second request sees the key gone when it starts.
//
// HTTP API (identical to vault-broker — rgtv CLI works against both):
//   GET  /health                     — unauthenticated liveness probe
//   GET  /v1/credentials             — list registered hint names (authenticated)
//   POST /v1/grants                  — issue a one-use grant (authenticated)
//   POST /v1/grants/:id/redeem       — redeem grant, get credential (authenticated)
//
// Authentication:
//   All endpoints except /health require:
//     Authorization: Bearer <RGTV_AGENT_TOKEN>   (Worker Secret)

#![allow(clippy::future_not_send)] // workers-rs handlers run in single-threaded WASM

use js_sys::Date;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::*;

// ---------------------------------------------------------------------------
// Timestamp helper
// ---------------------------------------------------------------------------

/// Current time as Unix seconds, sourced from the JS runtime clock.
fn now_secs() -> u64 {
    (Date::now() / 1000.0) as u64
}

// ---------------------------------------------------------------------------
// Grant record — stored in GrantObject DO storage
// ---------------------------------------------------------------------------

/// A pending, unredeemed grant.  Stored as a single DO storage entry under
/// the key "record".  The DO instance is identified by the grant_id UUID, so
/// there is a 1:1 correspondence between DO instances and outstanding grants.
#[derive(Serialize, Deserialize)]
struct GrantRecord {
    hint: String,
    /// Unix seconds at which the grant expires.
    expires_at: u64,
}

// ---------------------------------------------------------------------------
// GrantObject — Durable Object (one instance per outstanding grant)
// ---------------------------------------------------------------------------

/// A single DO instance owns exactly one grant record.  The Workers runtime
/// serialises all fetches to a given instance, so the check-and-delete in the
/// POST (redeem) handler is atomic — no locks, no races.
#[durable_object]
pub struct GrantObject {
    state: State,
    env: Env,
}

impl DurableObject for GrantObject {
    fn new(state: State, env: Env) -> Self {
        GrantObject { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        match req.method() {
            // PUT — store a new grant record.
            // Called once by handle_create_grant immediately after the grant_id
            // is assigned.  Body: JSON-encoded GrantRecord.
            Method::Put => {
                let record: GrantRecord = req.json().await?;
                self.state.storage().put("record", record).await?;
                Response::ok("")
            }

            // POST — redeem: atomic read + delete.
            // Because DO instances are single-threaded, no two POST requests
            // to this instance can interleave.  The second one will find the
            // key absent and receive 404.
            Method::Post => {
                let storage = self.state.storage();
                // storage.get returns Result<Option<T>> in workers-rs 0.8.
                match storage.get::<GrantRecord>("record").await {
                    Ok(Some(record)) => {
                        // Delete first — one-use is enforced before expiry is
                        // checked so an expired grant is also consumed and gone.
                        storage.delete("record").await?;

                        if record.expires_at <= now_secs() {
                            Response::error("grant expired", 410)
                        } else {
                            // Return only the hint; the worker resolves the
                            // actual credential value from CREDENTIALS KV.
                            Response::from_json(&serde_json::json!({ "hint": record.hint }))
                        }
                    }
                    // Key absent (None) or storage error → treat as not found.
                    Ok(None) | Err(_) => {
                        Response::error("grant not found or already redeemed", 404)
                    }
                }
            }

            _ => Response::error("method not allowed", 405),
        }
    }
}

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

/// Returns `Ok(())` if the request carries the correct bearer token, or an
/// error-carrying `Response` (caller should return it immediately).
fn check_auth(req: &Request, env: &Env) -> std::result::Result<(), Response> {
    let token = match env.var("RGTV_AGENT_TOKEN") {
        Ok(v) => v.to_string(),
        Err(_) => {
            // Fail closed — if the secret is missing, reject every request.
            return Err(
                Response::error("server misconfigured: RGTV_AGENT_TOKEN not set", 500)
                    .unwrap_or_else(|_| {
                        Response::empty()
                            .expect("invariant: Response::empty() construction always succeeds")
                    }),
            );
        }
    };
    let expected = format!("Bearer {token}");
    let auth = req
        .headers()
        .get("Authorization")
        .unwrap_or_default()
        .unwrap_or_default();
    if auth != expected {
        Err(Response::error("unauthorized", 401).unwrap_or_else(|_| {
            Response::empty().expect("invariant: Response::empty() construction always succeeds")
        }))
    } else {
        Ok(())
    }
}

macro_rules! require_auth {
    ($req:expr, $env:expr) => {
        if let Err(r) = check_auth($req, $env) {
            return Ok(r);
        }
    };
}

// ---------------------------------------------------------------------------
// Grant TTL
// ---------------------------------------------------------------------------

fn grant_ttl(env: &Env) -> u64 {
    env.var("RGTV_GRANT_TTL_SECS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(30)
}

// ---------------------------------------------------------------------------
// DO call helper — build a Request to send to a GrantObject stub
// ---------------------------------------------------------------------------

/// Build a PUT request carrying `body_json` for the DO store operation.
fn do_put_request(body_json: &str) -> Result<Request> {
    let mut headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let body = wasm_bindgen::JsValue::from_str(body_json);
    let mut init = RequestInit::new();
    init.with_method(Method::Put)
        .with_headers(headers)
        .with_body(Some(body));
    Request::new_with_init("https://do/grant", &init)
}

/// Build a POST request (no body) for the DO redeem operation.
fn do_post_request() -> Result<Request> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    Request::new_with_init("https://do/grant", &init)
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

/// Unauthenticated — returns broker status and number of registered credentials.
async fn handle_health(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let kv = ctx.kv("CREDENTIALS")?;
    let count = kv.list().execute().await?.keys.len();
    Response::from_json(&HealthResponse {
        status: "ok",
        version: "0.1.0",
        credential_count: count,
    })
}

// ---------------------------------------------------------------------------
// GET /v1/credentials
// ---------------------------------------------------------------------------

/// List registered hint names — no credential values returned.
async fn handle_credentials(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    require_auth!(&req, &ctx.env);

    let kv = ctx.kv("CREDENTIALS")?;
    let mut hints: Vec<String> = kv
        .list()
        .execute()
        .await?
        .keys
        .into_iter()
        .map(|k| k.name)
        .collect();
    hints.sort();
    let count = hints.len();
    Response::from_json(&CredentialsResponse { hints, count })
}

// ---------------------------------------------------------------------------
// POST /v1/grants
// ---------------------------------------------------------------------------

/// Issue a one-use grant for a named credential hint.
///
/// Creates a GrantObject DO instance keyed by the new grant_id UUID and PUTs
/// the GrantRecord into it.  The DO instance will hold the record until it is
/// redeemed (POST /v1/grants/:id/redeem) or the TTL elapses and the grant
/// expires.
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

    // Validate the hint exists in CREDENTIALS before issuing a grant.
    if ctx.kv("CREDENTIALS")?.get(&hint).text().await?.is_none() {
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
    let record = GrantRecord {
        hint: hint.clone(),
        expires_at: now_secs() + ttl,
    };

    // Store the grant record in its DO instance.
    let body_str = serde_json::to_string(&record).map_err(|e| Error::RustError(e.to_string()))?;
    let ns = ctx.durable_object("GRANTS")?;
    let stub = ns.id_from_name(&grant_id)?.get_stub()?;
    stub.fetch_with_request(do_put_request(&body_str)?).await?;

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
///
/// POSTs to the GrantObject DO instance for this grant_id.  The DO's
/// single-threaded handler performs an atomic read+delete — if two redeem
/// requests race, only the first succeeds; the second receives 404.
async fn handle_redeem_grant(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    require_auth!(&req, &ctx.env);

    let grant_id = match ctx.param("id") {
        Some(id) => id.to_string(),
        None => return Response::error("missing grant id", 400),
    };

    // Dispatch to the DO instance for this grant.
    let ns = ctx.durable_object("GRANTS")?;
    let stub = ns.id_from_name(&grant_id)?.get_stub()?;
    let mut do_resp = stub.fetch_with_request(do_post_request()?).await?;

    let status = do_resp.status_code();
    if status != 200 {
        // 404 = not found or already redeemed; 410 = expired.
        // Pass the DO's error text directly to the caller.
        let msg = do_resp.text().await.unwrap_or_default();
        return Response::error(&msg, status);
    }

    // Extract the hint from the DO's JSON response.
    let payload: serde_json::Value = do_resp.json().await?;
    let hint = payload["hint"]
        .as_str()
        .ok_or_else(|| Error::RustError("malformed DO response: missing hint".into()))?
        .to_string();

    // Resolve the raw credential value from CREDENTIALS KV.
    let value = match ctx.kv("CREDENTIALS")?.get(&hint).text().await? {
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
    console_error_panic_hook::set_once();

    Router::new()
        .get_async("/health", handle_health)
        .get_async("/v1/credentials", handle_credentials)
        .post_async("/v1/grants", handle_create_grant)
        .post_async("/v1/grants/:id/redeem", handle_redeem_grant)
        .run(req, env)
        .await
}

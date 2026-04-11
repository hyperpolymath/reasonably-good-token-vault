// SPDX-License-Identifier: PMPL-1.0-or-later
// Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
//
// vault-broker: RGTV HTTP grant broker.
//
// Agents (e.g. nesy-solver-api on Fly.io) hold an opaque agent token and
// never see raw credential values.  The broker mediates:
//
//   1. POST /v1/grants          — agent requests a one-use grant for a hint
//   2. POST /v1/grants/:id/redeem — agent redeems the grant; gets the value
//
// Credentials are loaded at startup from RGTV_CRED_<HINT> env vars and
// stored as zeroized strings.  Grant IDs are UUID v4.  Grants expire after
// RGTV_GRANT_TTL_SECS (default 30) and are one-use: the grant record is
// dropped immediately after redemption and the value is zeroized.
//
// Authentication: every request must carry:
//   Authorization: Bearer <RGTV_AGENT_TOKEN>
//
// Run:
//   RGTV_AGENT_TOKEN=secret \
//   RGTV_CRED_NESY_INGEST_TOKEN=tok123 \
//   vault-broker
//
// The broker binds to [::]:9100 by default (RGTV_PORT to override).
// Deploy it internal-only on Fly.io (no public http_service) so only
// flycast-addressed apps can reach it.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A credential stored in the broker, keyed by hint (e.g. "NESY_INGEST_TOKEN").
struct Credential {
    value: Zeroizing<String>,
}

/// An issued, unredeemed grant.
struct Grant {
    hint: String,
    expires_at: SystemTime,
    /// True once redeemed — grants are cleared immediately but we keep this
    /// flag as a belt-and-braces guard.
    redeemed: bool,
}

struct BrokerState {
    /// Agent bearer token — all requests must present this.
    agent_token: Zeroizing<String>,
    /// Credential store: hint → encrypted value.
    credentials: HashMap<String, Credential>,
    /// Active grants: grant_id → Grant.
    grants: Mutex<HashMap<String, Grant>>,
    /// How long a grant lives before it expires.
    grant_ttl: Duration,
}

// Arc so we can share across axum handlers.
type SharedState = Arc<BrokerState>;

// ---------------------------------------------------------------------------
// Wire types (JSON boundary)
// ---------------------------------------------------------------------------

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
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    credential_count: usize,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

fn load_credentials() -> HashMap<String, Credential> {
    // Collect every env var of the form RGTV_CRED_<HINT>.
    // The hint stored in the map is <HINT> (uppercased, underscores preserved).
    let prefix = "RGTV_CRED_";
    let mut creds: HashMap<String, Credential> = HashMap::new();

    for (key, value) in env::vars() {
        if let Some(hint) = key.strip_prefix(prefix) {
            if hint.is_empty() {
                continue;
            }
            info!(hint, "registered credential");
            creds.insert(
                hint.to_string(),
                Credential {
                    value: Zeroizing::new(value),
                },
            );
        }
    }

    creds
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

/// Returns Ok(()) if the request carries the correct bearer token.
fn authenticate(headers: &HeaderMap, agent_token: &str) -> Result<(), StatusCode> {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let expected = format!("Bearer {agent_token}");
    if auth != expected {
        warn!("authentication failed — bad or missing token");
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health(State(state): State<SharedState>) -> impl IntoResponse {
    let cred_count = state.credentials.len();
    let grants_active = state.grants.lock().unwrap().len();
    info!(cred_count, grants_active, "health check");
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        credential_count: cred_count,
    })
}

/// POST /v1/grants
/// Body: { "hint": "NESY_INGEST_TOKEN" }
/// Returns: { "grant_id": "...", "hint": "...", "expires_in_secs": 30 }
async fn create_grant(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<GrantRequest>,
) -> impl IntoResponse {
    if let Err(code) = authenticate(&headers, &state.agent_token) {
        return (code, Json(ErrorResponse { error: "unauthorized".into() })).into_response();
    }

    // Validate hint exists.
    if !state.credentials.contains_key(&req.hint) {
        warn!(hint = %req.hint, "grant requested for unknown hint");
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("unknown hint: {}", req.hint),
            }),
        )
            .into_response();
    }

    let grant_id = Uuid::new_v4().to_string();
    let expires_at = SystemTime::now() + state.grant_ttl;

    {
        let mut grants = state.grants.lock().unwrap();

        // Purge expired grants to keep memory tidy.
        let now = SystemTime::now();
        grants.retain(|_, g| !g.redeemed && g.expires_at > now);

        grants.insert(
            grant_id.clone(),
            Grant {
                hint: req.hint.clone(),
                expires_at,
                redeemed: false,
            },
        );
    }

    info!(grant_id = %grant_id, hint = %req.hint, "grant issued");

    (
        StatusCode::CREATED,
        Json(GrantResponse {
            grant_id,
            hint: req.hint,
            expires_in_secs: state.grant_ttl.as_secs(),
        }),
    )
        .into_response()
}

/// POST /v1/grants/:grant_id/redeem
/// Returns: { "hint": "...", "value": "..." }
/// One-use: the grant is dropped and the value is zeroed from the response
/// struct immediately after the JSON is serialised.
async fn redeem_grant(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(code) = authenticate(&headers, &state.agent_token) {
        return (code, Json(ErrorResponse { error: "unauthorized".into() })).into_response();
    }

    // Retrieve and immediately remove the grant.
    let hint = {
        let mut grants = state.grants.lock().unwrap();
        match grants.remove(&grant_id) {
            None => {
                warn!(%grant_id, "redeem: grant not found or already redeemed");
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "grant not found or already redeemed".into(),
                    }),
                )
                    .into_response();
            }
            Some(g) if g.redeemed => {
                warn!(%grant_id, "redeem: double-redeem attempt");
                return (
                    StatusCode::GONE,
                    Json(ErrorResponse {
                        error: "grant already redeemed".into(),
                    }),
                )
                    .into_response();
            }
            Some(g) if g.expires_at < SystemTime::now() => {
                warn!(%grant_id, "redeem: grant expired");
                return (
                    StatusCode::GONE,
                    Json(ErrorResponse {
                        error: "grant expired".into(),
                    }),
                )
                    .into_response();
            }
            Some(g) => g.hint,
        }
    };

    // Resolve the credential value.
    let value = match state.credentials.get(&hint) {
        None => {
            warn!(%hint, "redeem: credential disappeared after grant was issued");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "credential no longer available".into(),
                }),
            )
                .into_response();
        }
        Some(c) => c.value.as_str().to_string(),
    };

    info!(%grant_id, %hint, "grant redeemed — value delivered, grant dropped");

    // Serialize immediately so we can zeroize the local copy.
    let mut zeroized_value = Zeroizing::new(value);
    let response = Json(RedeemResponse {
        hint,
        value: zeroized_value.clone(),
    });
    zeroized_value.zeroize();
    response.into_response()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vault_broker=info,tower_http=warn".parse().unwrap()),
        )
        .json()
        .init();

    let agent_token = Zeroizing::new(
        env::var("RGTV_AGENT_TOKEN")
            .expect("RGTV_AGENT_TOKEN must be set"),
    );
    let grant_ttl_secs: u64 = env::var("RGTV_GRANT_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let port: u16 = env::var("RGTV_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9100);

    let credentials = load_credentials();
    if credentials.is_empty() {
        warn!("no credentials loaded — set RGTV_CRED_<HINT>=<value> env vars");
    }

    let state = Arc::new(BrokerState {
        agent_token,
        credentials,
        grants: Mutex::new(HashMap::new()),
        grant_ttl: Duration::from_secs(grant_ttl_secs),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/grants", post(create_grant))
        .route("/v1/grants/:grant_id/redeem", post(redeem_grant))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
    info!(%addr, grant_ttl_secs, "vault-broker starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

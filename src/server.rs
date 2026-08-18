//! # Enlil — the source-available agent control plane
//!
//! This module is the **entire OSS server**: a single-tenant, zero-config,
//! self-hostable proxy that shows and controls what your AI agents actually do.
//!
//! It is deliberately built *only* from the OSS core ([`EnlilState`]) and uses the
//! default (no-op) [`ProxyEnv`] hooks, which proves the carve described in
//! `DEVELOPMENT_PLAN.md`: none of the proprietary cloud concerns (Postgres,
//! DynamoDB, Redis, multi-tenant auth, billing/quotas, the memory fabric, the
//! PII-vault RBAC surface) are reachable from here.
//!
//! What a developer gets, with no signup and no configuration:
//!
//! * **Observability** — every agent action recorded and queryable
//!   (`GET /api/traces`, `GET /api/traces/{id}`). This is the wedge: see what your
//!   agent just did.
//! * **Control** — the full inline enforcement engine: prompt-injection and
//!   tool-poisoning defense, declarative policy rules, PII redaction, the agent
//!   loop-breaker, RiskChain behavioural checks, and the context-window guard.
//! * **Efficiency** — exact-intent response caching and per-request cost accounting.
//!
//! Deliberately *not* here (these are the paid org-wrapper): multi-tenancy, SSO/RBAC,
//! signed compliance evidence packs, long-term retention, and the managed cloud.

use axum::{
    extract::{Path, Query, State},
    routing::{any, get},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::config::ProxyConfig;
use crate::middleware::payload_size::payload_size_middleware;
use crate::middleware::telemetry::telemetry_middleware;
use crate::routing::proxy::handle_proxy;
use crate::state::EnlilState;
use crate::usage::ProxyEnv;

/// The OSS application state.
///
/// A thin newtype over the OSS core so it can implement [`ProxyEnv`]. Every hook
/// uses the trait's default (OSS) behaviour — no billing, no quota service, no
/// per-tenant upstream overrides, no webhook delivery.
pub struct OssState(pub EnlilState);

impl std::ops::Deref for OssState {
    type Target = EnlilState;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// All hooks intentionally left at their OSS defaults.
impl ProxyEnv for OssState {}

#[derive(Deserialize)]
pub struct TraceListQuery {
    limit: Option<usize>,
}

/// `GET /api/traces` — the most recent agent actions this proxy has seen.
///
/// Single-user by design: the local operator owns the process, so traces are not
/// tenant-gated here (that gating is a multi-tenant/cloud concern).
async fn list_traces(
    State(state): State<Arc<OssState>>,
    Query(q): Query<TraceListQuery>,
) -> impl axum::response::IntoResponse {
    let limit = q.limit.unwrap_or(100).min(1000);
    let traces = state.trace_store.list("", true, limit).await;
    Json(serde_json::json!({ "count": traces.len(), "traces": traces }))
}

/// `GET /api/traces/{id}` — the full governance decision path for one request.
async fn get_trace(
    State(state): State<Arc<OssState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    match state.trace_store.get_scoped(&id, "", true).await {
        Some(trace) => Ok(Json(
            serde_json::to_value(trace).unwrap_or_else(|_| serde_json::json!({})),
        )),
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

/// `GET /api/stats` — local counters: requests, cache hits, blocks, tokens, latency.
async fn stats(State(state): State<Arc<OssState>>) -> Json<serde_json::Value> {
    use std::sync::atomic::Ordering::Relaxed;
    let m = &state.metrics;
    Json(serde_json::json!({
        "total_requests": m.total_requests.load(Relaxed),
        "cache_hits": m.cache_hits.load(Relaxed),
        "cache_misses": m.cache_misses.load(Relaxed),
        "avg_latency_us": m.avg_latency_us(),
        "total_tokens_used": m.total_tokens_used.load(Relaxed),
        "pii_redactions": m.pii_redactions.load(Relaxed),
        "policy_blocks": m.policy_blocks.load(Relaxed),
        "injection_blocks": m.injection_blocks.load(Relaxed),
        "loop_breaks": m.loop_breaks.load(Relaxed),
        "risk_chain_alerts": m.risk_chain_alerts.load(Relaxed),
        "rule_alerts": m.rule_alerts.load(Relaxed),
    }))
}

/// `GET /api/rules` — the active policy rules.
async fn rules(State(state): State<Arc<OssState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "rules": state.rule_engine.list_rules() }))
}

/// `GET /api/events/recent` — the local governance event feed.
async fn recent_events(State(state): State<Arc<OssState>>) -> Json<serde_json::Value> {
    let events = state.metrics.events.lock().unwrap().clone();
    Json(serde_json::json!({ "events": events }))
}

/// The embedded web UI served at `/ui`.
const UI_HTML: &str = include_str!("ui.html");

/// Builds the Enlil OSS router.
///
/// Note there is **no auth middleware**: the OSS build is single-tenant and the
/// operator owns the process. `routing::proxy` falls back to a default identity
/// when no `TenantContext` extension is present (see `crate::identity`).
pub async fn build_oss_app(config: ProxyConfig) -> Router {
    let state = Arc::new(OssState(EnlilState::from_config(config).await));

    let api = Router::new()
        .route("/", get(|| async { axum::response::Html(UI_HTML) }))
        .route(
            "/api",
            get(|| async {
                Json(serde_json::json!({
                    "service": "enlil",
                    "description": "Source-available control and audit plane for AI agent actions",
                    "endpoints": {
                        "health": "/health",
                        "ui": "/",
                        "traces": "/api/traces",
                        "trace": "/api/traces/{id}",
                        "stats": "/api/stats",
                        "rules": "/api/rules",
                        "events": "/api/events/recent"
                    }
                }))
            }),
        )
        .route("/health", get(|| async { "ok" }))
        .route("/api/traces", get(list_traces))
        .route("/api/traces/{id}", get(get_trace))
        .route("/api/stats", get(stats))
        .route("/api/rules", get(rules))
        .route("/api/events/recent", get(recent_events))
        .with_state(state.clone());

    // Background: periodically flush traces to local storage (SQLite backend only).
    let bg = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            bg.metrics.snapshot();
            bg.trace_store.persist_snapshot();
        }
    });

    let proxy = Router::new()
        .route("/{*path}", any(handle_proxy::<OssState>))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            telemetry_middleware::<OssState>,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            payload_size_middleware::<OssState>,
        ))
        .with_state(state);

    api.merge(proxy)
}

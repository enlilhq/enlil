//! # Enlil — the source-available control and audit plane for AI agent actions
//!
//! Enlil sits inline between your agents and any upstream model or tool, and
//! answers the question that blocks agents from reaching production: **what is
//! this agent allowed to do, and can you prove what it did?**
//!
//! *Claude secures Claude. Enlil governs everything your agents touch* — every
//! model, every tool, one audit trail you own.
//!
//! ## What's here
//!
//! * [`engine`] — the inline enforcement engine: prompt-injection and
//!   tool-poisoning defense, declarative policy rules, reversible PII redaction,
//!   the agent loop-breaker, RiskChain behavioural checks, anomaly detection,
//!   SafeFix remediation and the context-window guard.
//! * [`observability`] — per-request traces with the full governance decision path.
//! * [`routing`] — the proxy hot path, protocol detection (OpenAI / MCP / A2A) and
//!   the per-provider circuit breaker.
//! * [`cache`] — exact-intent response deduplication (blake3 over request intent;
//!   *not* embedding-based similarity).
//! * [`tokens`] — token attribution and model pricing.
//! * [`usage`] — the [`usage::ProxyEnv`] extension seam (see below).
//! * [`server`] — the zero-config single-tenant OSS server.
//!
//! ## Extending it
//!
//! The proxy is generic over [`usage::ProxyEnv`], whose hooks all default to
//! OSS-appropriate no-ops. A downstream deployment can implement them to attach
//! billing, quotas, per-tenant upstream overrides or alert delivery without
//! forking the hot path. The commercial `plumb` crate does exactly this.

pub mod cache;
pub mod config;
pub mod engine;
pub mod error;
pub mod identity;
pub mod middleware;
pub mod observability;
pub mod routing;
pub mod server;
pub mod state;
pub mod tokens;
pub mod usage;

pub use state::EnlilState;

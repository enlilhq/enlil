//! The **OSS ↔ cloud seam** for the proxy hot path.
//!
//! `routing::proxy` is the heart of the open-source `enlil` binary, but it needs
//! two things the OSS build deliberately does not have: per-tenant billing/quota
//! accounting, and a database-backed per-tenant upstream override.
//!
//! Rather than have the OSS proxy depend on `finops::cost_tracker`, `redis_store`
//! and `db` (which are proprietary), it is generic over [`ProxyEnv`]. Both hooks
//! have no-op defaults, so the OSS build gets correct behaviour for free, while
//! the cloud build implements them on `AppState`.
//!
//! See DEVELOPMENT_PLAN.md, Step 2.

use crate::state::EnlilState;
use crate::tokens::TokenUsage;
use std::future::Future;

/// A completed upstream call, described for downstream accounting.
///
/// Owned rather than borrowed: this is built once per request *after* the response
/// has been handled (off the latency-critical path), so the allocations are
/// irrelevant and owning the data keeps the hook free of lifetime plumbing.
pub struct UsageEvent {
    pub tenant_id: String,
    pub api_key_id: Option<uuid::Uuid>,
    pub model: String,
    pub usage: TokenUsage,
    /// Actual (cache-aware) cost in microdollars.
    pub cost_micro: u64,
    pub total_tokens: u32,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub protocol: String,
    pub path: String,
}

/// The environment the proxy handler runs in.
///
/// Requires `Deref<Target = EnlilState>` so that every existing `state.<field>`
/// access in the proxy continues to resolve against the OSS core state.
///
/// Both methods default to OSS behaviour (no proprietary accounting), so the
/// open-source build simply does not implement them.
pub trait ProxyEnv: std::ops::Deref<Target = EnlilState> + Send + Sync + 'static {
    /// A per-tenant upstream override, if the deployment has one configured.
    ///
    /// OSS default: `None` — the upstream is resolved purely from local config.
    /// Cloud: looks up the tenant's configured upstream in Postgres.
    fn resolve_tenant_upstream(
        &self,
        _tenant_id: &str,
    ) -> impl Future<Output = Option<String>> + Send {
        async { None }
    }

    /// Record a completed call for billing, quota and usage-log purposes.
    ///
    /// OSS default: no-op. Local per-request cost and token counts are already
    /// recorded by the OSS core (metrics, agent registry, trace store) before
    /// this is called.
    /// Cloud: cost tracker, token quota, shared Redis counters, Postgres usage log.
    fn record_usage(&self, _ev: UsageEvent) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Deliver an out-of-band alert about a governance event (loop break, risk
    /// alert, prompt injection, policy alert, budget exceeded...).
    ///
    /// OSS default: no-op — the event is already recorded in local metrics, the
    /// event feed and the trace store. Cloud: POSTs to the tenant's configured
    /// webhook URL.
    fn send_alert(
        &self,
        _tenant_id: &str,
        _event: &str,
        _message: &str,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }
}

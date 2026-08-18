//! The **OSS ↔ cloud seam** for the proxy hot path.
//!
//! `routing::proxy` is the heart of the source-available `enlil` binary, but it needs
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
/// Adding a field here is a breaking change for anyone constructing this by hand, which is why
/// it is `#[non_exhaustive]`: downstream crates consume `UsageEvent` in `record_usage` rather
/// than building it, so marking it now means the next field costs nobody a major version.
#[non_exhaustive]
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
    /// End-to-end handling time for this request.
    ///
    /// Previously the cloud implementation wrote a hardcoded `0` into `usage_logs.latency_ms`
    /// for every row, so the column was uniformly false and any latency shown per tenant was
    /// either fabricated or came from process-local counters that reset on restart.
    pub latency_us: u64,
    /// Whether this request was served from the response cache instead of the provider.
    ///
    /// Also previously hardcoded, to `false`. Combined with cache hits never reaching
    /// `record_usage` at all, that made `usage_logs.cache_hit` always false and undercounted
    /// `total_requests` by exactly the number of cached responses.
    pub cache_hit: bool,
}

/// The environment the proxy handler runs in.
///
/// Requires `Deref<Target = EnlilState>` so that every existing `state.<field>`
/// access in the proxy continues to resolve against the OSS core state.
///
/// Both methods default to OSS behaviour (no proprietary accounting), so the
/// source-available build simply does not implement them.
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

    /// How long a trace for this tenant should be retained, in days, before it is
    /// eligible for deletion.
    ///
    /// OSS default: `None`, meaning no expiry — `enlil` is single-tenant and
    /// self-hosted, so there is no tier to derive a retention policy from, and
    /// the operator owns their own storage and eviction (`TRACE_CAPACITY` /
    /// `TRACE_DB_CAPACITY` still apply as a size bound regardless).
    /// Cloud: looks up the tenant's tier and returns its retention window
    /// (free/growth/enterprise), so `Trace.expires_at` can be set at write time —
    /// see `crate::observability::Trace::with_retention`.
    fn retention_days(&self, _tenant_id: &str) -> Option<u32> {
        None
    }
}

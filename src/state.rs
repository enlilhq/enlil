//! The Enlil core state.

use reqwest::Client;
use std::sync::Arc;

use crate::cache::store::CacheManager;
use crate::config::ProxyConfig;
use crate::engine::pii_redact::PiiVault;
use crate::engine::risk_chain::RiskChain;
use crate::middleware::telemetry::MetricsCollector;
use crate::routing::circuit_breaker::CircuitBreaker;

/// The **OSS (Enlil) core state.**
///
/// Holds only the concerns that ship in the open-source `enlil` binary: the inline
/// enforcement engine, the exact-intent cache, local observability, and the HTTP
/// client/config needed to proxy a request.
///
/// Structural invariant (now enforced by the crate boundary, see
/// `DEVELOPMENT_PLAN.md`): nothing reachable from here may depend on multi-tenant
/// persistence, billing/quotas, Redis, or the memory fabric. Those live in the
/// `plumb` crate and attach via the [`crate::usage::ProxyEnv`] hooks.
pub struct EnlilState {
    pub client: Client,
    pub upstream_url: String,
    pub config: ProxyConfig,
    pub cache_manager: CacheManager,
    pub metrics: Arc<MetricsCollector>,
    pub risk_chain: RiskChain,
    pub circuit_breaker: CircuitBreaker,
    pub pii_vault: PiiVault,
    pub agent_registry: Arc<crate::engine::agent_identity::AgentRegistry>,
    pub loop_breaker: crate::engine::loop_breaker::LoopBreaker,
    pub anomaly_detector: crate::engine::anomaly::AnomalyDetector,
    pub rule_engine: crate::engine::rules::RuleEngine,
    pub prompt_guard: crate::engine::prompt_guard::PromptGuard,
    pub trace_store: crate::observability::TraceBackend,
}

impl EnlilState {
    /// Builds the OSS core from configuration.
    ///
    /// Shared by the open-source `enlil` binary and the cloud `plumb` binary, so
    /// both run an identical enforcement engine.
    pub async fn from_config(config: ProxyConfig) -> Self {
        let client = Client::builder()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            upstream_url: config.upstream_url.clone(),
            cache_manager: CacheManager::new_with_config(
                config.cache_ttl_secs,
                config.cache_max_capacity,
            ),
            config,
            metrics: Arc::new(MetricsCollector::new()),
            risk_chain: RiskChain::new(),
            circuit_breaker: CircuitBreaker::new(),
            pii_vault: PiiVault::new(),
            agent_registry: crate::engine::agent_identity::AgentRegistry::new(),
            loop_breaker: crate::engine::loop_breaker::LoopBreaker::new(),
            anomaly_detector: crate::engine::anomaly::AnomalyDetector::new(),
            rule_engine: crate::engine::rules::RuleEngine::new(),
            prompt_guard: crate::engine::prompt_guard::PromptGuard::new(),
            trace_store: crate::observability::TraceBackend::from_env().await,
        }
    }
}

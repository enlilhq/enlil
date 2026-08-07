use crate::usage::ProxyEnv;
use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct MetricsCollector {
    pub total_requests: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_savings_microdollars: AtomicU64,
    pub pii_redactions: AtomicU64,
    pub kill_switch_triggers: AtomicU64,
    pub risk_chain_alerts: AtomicU64,
    pub loop_breaks: AtomicU64,
    pub policy_blocks: AtomicU64,
    pub rule_alerts: AtomicU64,
    pub injection_blocks: AtomicU64,
    pub total_tokens_used: AtomicU64,
    pub latency_sum_us: AtomicU64,
    pub latency_max_us: AtomicU64,
    pub events: Mutex<Vec<ProxyEvent>>,
    pub time_series: Mutex<Vec<TimeSeriesPoint>>,
}

#[derive(Clone, serde::Serialize)]
pub struct ProxyEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub tenant_id: String,
    pub detail: String,
}

#[derive(Clone, serde::Serialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub requests: u64,
    pub avg_latency_us: u64,
    pub cache_hits: u64,
    pub cost_microdollars: u64,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            cache_savings_microdollars: AtomicU64::new(0),
            pii_redactions: AtomicU64::new(0),
            kill_switch_triggers: AtomicU64::new(0),
            risk_chain_alerts: AtomicU64::new(0),
            loop_breaks: AtomicU64::new(0),
            policy_blocks: AtomicU64::new(0),
            rule_alerts: AtomicU64::new(0),
            injection_blocks: AtomicU64::new(0),
            total_tokens_used: AtomicU64::new(0),
            latency_sum_us: AtomicU64::new(0),
            latency_max_us: AtomicU64::new(0),
            events: Mutex::new(Vec::new()),
            time_series: Mutex::new(Vec::new()),
        }
    }

    pub fn record_event(&self, event_type: &str, tenant_id: &str, detail: &str) {
        let event = ProxyEvent {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type: event_type.to_string(),
            tenant_id: tenant_id.to_string(),
            detail: detail.to_string(),
        };
        let mut events = self.events.lock().unwrap();
        events.push(event);
        // Keep last 100 events
        if events.len() > 100 {
            let drain_to = events.len() - 100;
            events.drain(0..drain_to);
        }
    }

    pub fn avg_latency_us(&self) -> u64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        self.latency_sum_us.load(Ordering::Relaxed) / total
    }

    pub fn snapshot(&self) {
        let point = TimeSeriesPoint {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            requests: self.total_requests.load(Ordering::Relaxed),
            avg_latency_us: self.avg_latency_us(),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cost_microdollars: self.cache_savings_microdollars.load(Ordering::Relaxed),
        };
        let mut ts = self.time_series.lock().unwrap();
        ts.push(point);
        if ts.len() > 360 {
            // keep ~1 hour at 10s intervals
            let drain_to = ts.len() - 360;
            ts.drain(0..drain_to);
        }
    }

    pub fn get_time_series(&self) -> Vec<TimeSeriesPoint> {
        self.time_series.lock().unwrap().clone()
    }
}

pub async fn telemetry_middleware<E: ProxyEnv>(
    State(state): State<Arc<E>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = next.run(req).await;

    let elapsed_us = start.elapsed().as_micros() as u64;
    state.metrics.total_requests.fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .latency_sum_us
        .fetch_add(elapsed_us, Ordering::Relaxed);
    state
        .metrics
        .latency_max_us
        .fetch_max(elapsed_us, Ordering::Relaxed);

    tracing::info!(
        method = %method,
        path = %path,
        latency_us = elapsed_us,
        status = response.status().as_u16(),
        "request completed"
    );

    Ok(response)
}

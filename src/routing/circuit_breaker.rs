use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,   // healthy — requests flow normally
    Open,     // tripped — all requests fail-fast to fallback
    HalfOpen, // testing — allow one request through to check recovery
}

struct ProviderState {
    failures: AtomicU32,
    successes: AtomicU32,
    last_failure: AtomicU64, // epoch millis
    state: std::sync::atomic::AtomicU8, // 0=Closed, 1=Open, 2=HalfOpen
}

impl Default for ProviderState {
    fn default() -> Self {
        Self {
            failures: AtomicU32::new(0),
            successes: AtomicU32::new(0),
            last_failure: AtomicU64::new(0),
            state: std::sync::atomic::AtomicU8::new(0),
        }
    }
}

impl ProviderState {
    fn get_state(&self) -> CircuitState {
        match self.state.load(Ordering::Relaxed) {
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }

    fn set_state(&self, s: CircuitState) {
        self.state.store(match s {
            CircuitState::Closed => 0,
            CircuitState::Open => 1,
            CircuitState::HalfOpen => 2,
        }, Ordering::Relaxed);
    }
}

pub struct CircuitBreaker {
    providers: DashMap<String, ProviderState>,
    failure_threshold: u32,
    recovery_timeout: Duration,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            providers: DashMap::new(),
            failure_threshold: 3,
            recovery_timeout: Duration::from_secs(30),
        }
    }

    /// Check if a provider is available. Returns the circuit state.
    pub fn check(&self, provider: &str) -> CircuitState {
        let entry = self.providers.entry(provider.to_string()).or_default();
        let state = entry.get_state();

        if state == CircuitState::Open {
            // Check if recovery timeout has elapsed
            let last = entry.last_failure.load(Ordering::Relaxed);
            let now = epoch_millis();
            if now - last > self.recovery_timeout.as_millis() as u64 {
                entry.set_state(CircuitState::HalfOpen);
                return CircuitState::HalfOpen;
            }
        }
        state
    }

    /// Record a successful response from a provider
    pub fn record_success(&self, provider: &str) {
        let entry = self.providers.entry(provider.to_string()).or_default();
        entry.successes.fetch_add(1, Ordering::Relaxed);
        entry.failures.store(0, Ordering::Relaxed);
        entry.set_state(CircuitState::Closed);
    }

    /// Record a failure from a provider
    pub fn record_failure(&self, provider: &str) {
        let entry = self.providers.entry(provider.to_string()).or_default();
        let failures = entry.failures.fetch_add(1, Ordering::Relaxed) + 1;
        entry.last_failure.store(epoch_millis(), Ordering::Relaxed);

        if failures >= self.failure_threshold {
            entry.set_state(CircuitState::Open);
            tracing::warn!("Circuit OPEN for provider: {} ({} failures)", provider, failures);
        }
    }

    /// Check if provider is healthy (Closed or HalfOpen)
    pub fn is_available(&self, provider: &str) -> bool {
        self.check(provider) != CircuitState::Open
    }
}

fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

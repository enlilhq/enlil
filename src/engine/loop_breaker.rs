//! Agent loop-breaker.
//!
//! Autonomous agents can get stuck in reasoning loops, re-issuing the same (or a
//! near-identical) request over and over and burning budget with nothing to show for it.
//! The [`LoopBreaker`] tracks a per-session sliding window of request-intent fingerprints
//! and hard-stops a request once the same intent has repeated too many times inside the
//! window — severing the loop *before* the spend, rather than reporting it afterwards.
//!
//! Fingerprints reuse the same semantic-intent extraction as the L1 cache (messages +
//! tools, ignoring volatile fields like `temperature`), so trivially different payloads
//! that mean the same thing still collide. Non-LLM bodies fall back to a raw-body hash.

use dashmap::DashMap;
use std::time::{Duration, Instant};

/// Default detection window if `LOOP_WINDOW_SECS` is unset.
const DEFAULT_WINDOW_SECS: u64 = 30;
/// Default number of prior identical intents tolerated before breaking, if
/// `LOOP_MAX_REPEATS` is unset. The (N+1)th identical request in the window is broken.
const DEFAULT_MAX_REPEATS: usize = 5;
/// Hard cap on retained fingerprints per session (memory bound).
const MAX_SAMPLES_PER_SESSION: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopDecision {
    /// Request may proceed.
    Allow,
    /// The request repeats an intent too many times in the window; sever the loop.
    Break { repeats: usize },
}

pub struct LoopBreaker {
    /// session_id → recent (intent_fingerprint, seen_at) samples.
    sessions: DashMap<String, Vec<(u64, Instant)>>,
    window: Duration,
    /// Prior identical intents tolerated within the window. `0` disables the breaker.
    max_repeats: usize,
}

impl Default for LoopBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopBreaker {
    /// Build from environment: `LOOP_WINDOW_SECS` (default 30) and
    /// `LOOP_MAX_REPEATS` (default 5; `0` disables loop-breaking).
    pub fn new() -> Self {
        let window_secs = std::env::var("LOOP_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_WINDOW_SECS);
        let max_repeats = std::env::var("LOOP_MAX_REPEATS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_REPEATS);
        Self::with_config(window_secs, max_repeats)
    }

    pub fn with_config(window_secs: u64, max_repeats: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            window: Duration::from_secs(window_secs),
            max_repeats,
        }
    }

    /// Whether loop-breaking is active.
    pub fn enabled(&self) -> bool {
        self.max_repeats > 0
    }

    /// Record a request intent for a session and decide whether it should proceed.
    pub fn check(&self, session_id: &str, intent_fingerprint: u64) -> LoopDecision {
        if !self.enabled() {
            return LoopDecision::Allow;
        }

        let now = Instant::now();
        let mut samples = self.sessions.entry(session_id.to_string()).or_default();

        // Drop samples outside the sliding window.
        samples.retain(|(_, t)| now.duration_since(*t) < self.window);

        let prior_repeats = samples
            .iter()
            .filter(|(h, _)| *h == intent_fingerprint)
            .count();

        samples.push((intent_fingerprint, now));
        if samples.len() > MAX_SAMPLES_PER_SESSION {
            let drain_to = samples.len() - MAX_SAMPLES_PER_SESSION;
            samples.drain(0..drain_to);
        }

        if prior_repeats >= self.max_repeats {
            LoopDecision::Break {
                repeats: prior_repeats + 1,
            }
        } else {
            LoopDecision::Allow
        }
    }

    pub fn tracked_sessions(&self) -> usize {
        self.sessions.len()
    }
}

/// Computes a stable 64-bit fingerprint of a request's *intent* for loop detection.
///
/// Uses the same semantic-intent extraction as the cache (messages + tools) so that
/// volatile fields don't defeat detection; falls back to the raw body for non-LLM
/// payloads. The path is mixed in so distinct endpoints in one session don't collide.
pub fn intent_fingerprint(path: &str, body: &[u8]) -> u64 {
    let intent = crate::engine::parser::extract_intent(body)
        .and_then(|v| serde_json::to_string(&v).ok())
        .unwrap_or_else(|| String::from_utf8_lossy(body).to_string());
    fingerprint_from_basis(path, &intent)
}

/// Same as [`intent_fingerprint`] but from an already-parsed JSON value (avoids re-parsing).
pub fn intent_fingerprint_value(path: &str, json: &serde_json::Value) -> u64 {
    let intent = crate::engine::parser::extract_intent_value(json)
        .and_then(|v| serde_json::to_string(&v).ok())
        .unwrap_or_else(|| json.to_string());
    fingerprint_from_basis(path, &intent)
}

fn fingerprint_from_basis(path: &str, intent: &str) -> u64 {
    let basis = format!("{}\n{}", path, intent);
    let hash = blake3::hash(basis.as_bytes());
    let bytes = hash.as_bytes();
    u64::from_le_bytes(bytes[0..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breaks_after_threshold() {
        // Tolerate 3 prior repeats → the 4th identical intent is broken.
        let lb = LoopBreaker::with_config(60, 3);
        let fp = 42;
        assert_eq!(lb.check("s1", fp), LoopDecision::Allow); // 1st
        assert_eq!(lb.check("s1", fp), LoopDecision::Allow); // 2nd
        assert_eq!(lb.check("s1", fp), LoopDecision::Allow); // 3rd
        assert_eq!(lb.check("s1", fp), LoopDecision::Break { repeats: 4 }); // 4th
    }

    #[test]
    fn test_distinct_intents_do_not_trip() {
        let lb = LoopBreaker::with_config(60, 3);
        for i in 0..10 {
            assert_eq!(lb.check("s1", i as u64), LoopDecision::Allow);
        }
    }

    #[test]
    fn test_sessions_isolated() {
        let lb = LoopBreaker::with_config(60, 1);
        assert_eq!(lb.check("a", 7), LoopDecision::Allow);
        assert_eq!(lb.check("b", 7), LoopDecision::Allow); // different session
        assert_eq!(lb.check("a", 7), LoopDecision::Break { repeats: 2 });
    }

    #[test]
    fn test_disabled_when_max_repeats_zero() {
        let lb = LoopBreaker::with_config(60, 0);
        assert!(!lb.enabled());
        for _ in 0..100 {
            assert_eq!(lb.check("s1", 1), LoopDecision::Allow);
        }
    }

    #[test]
    fn test_fingerprint_stable_and_intent_aware() {
        // Same messages but different temperature → same fingerprint (intent-based).
        let a =
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.1}"#;
        let b =
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.9}"#;
        assert_eq!(
            intent_fingerprint("/v1/chat", a),
            intent_fingerprint("/v1/chat", b)
        );

        // Different content → different fingerprint.
        let c = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"bye"}]}"#;
        assert_ne!(
            intent_fingerprint("/v1/chat", a),
            intent_fingerprint("/v1/chat", c)
        );

        // Same body, different path → different fingerprint.
        assert_ne!(
            intent_fingerprint("/v1/chat", a),
            intent_fingerprint("/v2/chat", a)
        );
    }
}

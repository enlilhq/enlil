//! Eval harness for the PRD §6 acceptance criteria.
//!
//! - PII detection accuracy against a small labeled dataset (recall on positives,
//!   no false positives on clean negatives).
//! - Semantic cache dedup / hit-rate on a workload with a known duplicate ratio.
//!
//! These are deterministic evals (no model calls) that gate the core AgentTrust and
//! caching guarantees the product advertises.

use enlil::cache::semantic::generate_hash;
use enlil::engine::pii_redact::{redact_pii, PiiVault};
use std::collections::HashSet;

/// (input, expected PII token substring that must appear after redaction)
fn pii_positives() -> Vec<(&'static str, &'static str)> {
    vec![
        ("My social is 123-45-6789 please", "[PII_SSN_"),
        ("contact me at jane.doe@example.com", "[PII_EMAIL_"),
        ("pay with card 4111 1111 1111 1111", "[PII_CC_"),
        ("phone: 415-555-0132", "[PII_PHONE_"),
        ("SSN 987-65-4321 and email bob@corp.io", "[PII_SSN_"),
    ]
}

/// Clean strings that must NOT trigger any redaction (false-positive guard).
fn pii_negatives() -> Vec<&'static str> {
    vec![
        "the meeting is scheduled for 3pm tomorrow",
        "please order 42 units of product X",
        "we shipped version 2.0.1 last week",
        "the temperature outside is 72 degrees",
        "chapter 5 covers distributed systems",
    ]
}

#[test]
fn eval_pii_detection_accuracy() {
    let vault = PiiVault::new();
    let mut correct = 0usize;
    let mut total = 0usize;

    // Positives: the expected PII must be detected and masked.
    for (input, expected_token) in pii_positives() {
        total += 1;
        let mut text = input.to_string();
        let modified = redact_pii(&mut text, &vault, "eval");
        if modified && text.contains(expected_token) {
            correct += 1;
        } else {
            eprintln!("MISS (positive): {:?} -> {:?}", input, text);
        }
    }

    // Negatives: nothing should be redacted.
    for input in pii_negatives() {
        total += 1;
        let mut text = input.to_string();
        let modified = redact_pii(&mut text, &vault, "eval");
        if !modified {
            correct += 1;
        } else {
            eprintln!("FALSE POSITIVE (negative): {:?} -> {:?}", input, text);
        }
    }

    let accuracy = correct as f64 / total as f64 * 100.0;
    println!(
        "PII detection accuracy: {:.1}% ({}/{})",
        accuracy, correct, total
    );
    // PRD §6 target: >99% on the adversarial set.
    assert!(
        accuracy >= 99.0,
        "PII accuracy {:.1}% below the 99% target",
        accuracy
    );
}

#[test]
fn eval_semantic_cache_hit_rate() {
    // Workload: 100 requests drawn from a pool of 65 distinct intents → 35 are exact
    // repeats a warm cache would serve (35% hit rate).
    let distinct = 65usize;
    let total = 100usize;
    let mut seen: HashSet<String> = HashSet::new();
    let mut hits = 0usize;

    for i in 0..total {
        let body = serde_json::to_vec(&serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": format!("question number {}", i % distinct)}]
        }))
        .unwrap();
        let hash = generate_hash("eval-tenant", &body).expect("hashable intent");
        if !seen.insert(hash) {
            hits += 1;
        }
    }

    let hit_rate = hits as f64 / total as f64 * 100.0;
    println!(
        "Semantic cache hit rate: {:.1}% ({} hits / {})",
        hit_rate, hits, total
    );
    assert_eq!(
        seen.len(),
        distinct,
        "dedup should collapse to exactly the distinct intents"
    );
    // PRD §6 target: intercept 30–40% of redundant queries.
    assert!(
        hit_rate >= 30.0,
        "cache hit rate {:.1}% below the 30% target",
        hit_rate
    );
}

#[test]
fn eval_cache_ignores_volatile_fields() {
    // Same intent, different temperature / max_tokens → must hash identically so the
    // cache isn't defeated by trivial metadata changes.
    let a = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "what is 2+2?"}],
        "temperature": 0.1, "max_tokens": 10
    }))
    .unwrap();
    let b = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "what is 2+2?"}],
        "temperature": 0.9, "max_tokens": 500
    }))
    .unwrap();
    assert_eq!(generate_hash("t", &a), generate_hash("t", &b));

    // Cross-tenant isolation: identical intent, different tenant → different hash.
    assert_ne!(generate_hash("tenant-a", &a), generate_hash("tenant-b", &a));
}

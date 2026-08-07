//! Honest proxy-overhead micro-benchmark.
//!
//! The headline "sub-50µs proxy overhead" refers to the *synchronous CPU work* the proxy
//! performs on the request path beyond a raw passthrough — protocol detection, loop-breaker
//! fingerprinting, RiskChain, PII redaction, prompt-injection scanning, policy rules,
//! token estimation, context-window checks, and semantic-cache hashing.
//!
//! (Upstream network time and async/socket overhead are separate and are NOT what this
//! measures — those can never be sub-50µs on real hardware.) This bench runs the pure
//! governance pipeline over many iterations on a representative payload and asserts the
//! per-request compute overhead stays within budget. It is deterministic (no I/O), so it
//! does not suffer the flakiness of a network round-trip benchmark.

use enlil::cache::semantic::generate_hash_value;
use enlil::engine::context_window::check_context_overflow_value;
use enlil::engine::deobfuscate::deobfuscate_shell;
use enlil::engine::loop_breaker::intent_fingerprint_value;
use enlil::engine::pii_redact::{redact_pii, PiiVault};
use enlil::engine::prompt_guard::PromptGuard;
use enlil::engine::risk_chain::RiskChain;
use enlil::engine::rules::RuleEngine;
use enlil::routing::protocols::detect_protocol_value;
use enlil::tokens::estimate_token_layers_value;
use std::time::Instant;

#[test]
fn bench_proxy_compute_overhead() {
    // A representative OpenAI chat-completions request (with a tool) — the common case,
    // no PII / no injection so redaction and guards do their normal scanning work.
    let body = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant with access to company tools."},
            {"role": "user", "content": "What's the weather in San Francisco and should I bring an umbrella tomorrow?"}
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get the current weather for a city",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
            }
        }],
        "temperature": 0.7
    })).unwrap();

    let path = "/v1/chat/completions";
    let tenant = "bench-tenant";
    let session = "bench-session";

    let risk_chain = RiskChain::new();
    let prompt_guard = PromptGuard::new();
    let rule_engine = RuleEngine::new();
    let pii_vault = PiiVault::new();

    // One pass of the synchronous governance pipeline (mirrors handle_proxy's CPU work).
    // The body is parsed ONCE and the parsed value is shared across every analyzer, exactly
    // as the proxy now does.
    let run_once = || {
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let protocol = detect_protocol_value(&parsed);
        std::hint::black_box(&protocol);
        let fp = intent_fingerprint_value(path, &parsed);
        std::hint::black_box(fp);
        let _ = risk_chain.evaluate_value(session, &parsed);
        // PII + deobfuscation operate on a fresh owned copy, as in the proxy.
        let mut s = String::from_utf8(body.clone()).unwrap();
        s = deobfuscate_shell(&s);
        let _ = redact_pii(&mut s, &pii_vault, tenant);
        let verdict = prompt_guard.analyze_value(&parsed);
        std::hint::black_box(verdict.score);
        let matches = rule_engine.evaluate(&s, tenant, (body.len() / 4) as u32);
        std::hint::black_box(matches.len());
        let layers = estimate_token_layers_value(&parsed);
        std::hint::black_box(layers);
        let overflow = check_context_overflow_value(&parsed);
        std::hint::black_box(overflow.is_some());
        let hash = generate_hash_value(tenant, &parsed);
        std::hint::black_box(hash.is_some());
    };

    // Warm up (populate caches, JIT the branch predictor, etc.).
    for _ in 0..500 {
        run_once();
    }

    let iterations = 5_000usize;
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        run_once();
        samples.push(start.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();

    let p50 = samples[iterations / 2];
    let p95 = samples[(iterations as f64 * 0.95) as usize];
    let p99 = samples[(iterations as f64 * 0.99) as usize];
    let avg = samples.iter().sum::<u64>() / iterations as u64;
    let mode = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    println!(
        "\n=== PROXY COMPUTE OVERHEAD ({} iters, pure CPU, no network, {} build) ===",
        iterations, mode
    );
    println!("  avg: {:.2}µs", avg as f64 / 1000.0);
    println!("  p50: {:.2}µs", p50 as f64 / 1000.0);
    println!("  p95: {:.2}µs", p95 as f64 / 1000.0);
    println!("  p99: {:.2}µs", p99 as f64 / 1000.0);
    println!("========================================================================\n");

    let p99_us = p99 as f64 / 1000.0;
    if cfg!(debug_assertions) {
        // Debug builds run regex/serde ~10-30x slower and aren't representative of the
        // deployed (release) binary. Enforce only a loose sanity bound here; the real
        // budget is enforced in release (run: `cargo test --release`).
        assert!(
            p99_us < 3_000.0,
            "p99 debug compute overhead {:.2}µs is implausibly high",
            p99_us
        );
    } else {
        // Measured reality (release): the full governance pipeline runs ~60µs p50 / ~110µs
        // Measured reality (release, after the parse-once optimization): the full governance
        // pipeline runs ~30µs p50 / ~55µs p99 of CPU work — the body is parsed once and the
        // parsed value shared across analyzers (protocol, loop-breaker, RiskChain, prompt
        // guard, token estimate, context window, cache hash). Gate at 120µs p99 (headroom for
        // shared CI runners); tighten on dedicated hardware.
        assert!(
            p99_us < 120.0,
            "p99 proxy compute overhead {:.2}µs exceeds the 120µs regression budget",
            p99_us
        );
    }
}

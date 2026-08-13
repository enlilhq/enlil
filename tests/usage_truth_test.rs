//! Every figure the dashboard shows has to be derivable from something real.
//!
//! Three defects motivated these, all in the same flow and all silent:
//!
//! 1. The cache-hit branch returned before calling `record_usage`, so a cached response never
//!    reached `usage_logs`. `total_requests` undercounted by exactly the number of cache hits,
//!    and `usage_logs.cache_hit` was never once true.
//! 2. `record_usage` wrote a hardcoded `0` latency and `false` cache_hit for every row, so both
//!    columns were uniformly wrong even for the requests that were recorded.
//! 3. A cache hit added a flat `4000` microdollars — $0.004 — to a running "cache savings"
//!    total, which the dashboard presented as a dollar figure. That number was invented; it had
//!    no relationship to the model, the tokens, or the provider's pricing.

use bytes::Bytes;
use enlil::cache::store::CachedResponse;

#[test]
fn a_cache_entry_remembers_what_the_call_cost() {
    // The saving reported on a hit is this figure, so it has to be the real one.
    let entry =
        CachedResponse::with_cost(Bytes::from("body"), "application/json".into(), 12_345, 678);
    assert_eq!(entry.cost_micro, 12_345);
    assert_eq!(entry.total_tokens, 678);
}

#[test]
fn an_entry_with_no_known_cost_claims_no_saving() {
    // Used where the cost genuinely is not known — overwriting a corrupted entry, or a response
    // whose usage block could not be parsed. Reporting zero is honest; reporting a constant is
    // what was wrong before.
    let entry = CachedResponse::new(Bytes::from("body"), "application/json".into());
    assert_eq!(
        entry.cost_micro, 0,
        "an unknown cost must be zero, never a placeholder figure"
    );
    assert_eq!(entry.total_tokens, 0);
}

#[test]
fn the_flat_four_thousand_microdollar_saving_is_gone() {
    // Pins the specific fabricated constant so it cannot come back. 4000 microdollars was added
    // per cache hit regardless of anything about the request.
    let src = include_str!("../src/routing/proxy.rs");
    assert!(
        !src.contains("cache_savings_microdollars\n                        .fetch_add(4000"),
        "the fabricated flat cache saving has returned"
    );
    assert!(
        src.contains("fetch_add(cached_res.cost_micro"),
        "the cache saving should come from the entry's recorded cost"
    );
}

#[test]
fn a_cache_hit_is_recorded_as_a_request() {
    // The hit path must call record_usage before returning, or a cached response is invisible to
    // every figure derived from usage_logs.
    let src = include_str!("../src/routing/proxy.rs");
    let hit = src
        .split("info!(\"Cache HIT for hash: {}\", hash);")
        .nth(1)
        .expect("the cache-hit branch should exist");
    // Up to the early return that ends the branch.
    let branch = hit.split("return Ok(response);").next().unwrap();
    assert!(
        branch.contains("record_usage"),
        "a cache hit must be recorded, not returned silently"
    );
    assert!(
        branch.contains("cache_hit: true"),
        "the recorded row must be marked as a cache hit"
    );
    assert!(
        branch.contains("cost_micro: 0"),
        "a cache hit costs nothing upstream, so the recorded cost must be zero"
    );
}

// The companion check — that the *cloud* `record_usage` implementation forwards
// `ev.latency_us`/`ev.cache_hit` instead of writing literals — lives in plumb's own suite
// (`plumb/tests/usage_recording_test.rs`). It used to live here and read
// `../../plumb/src/server.rs` via `include_str!`, which gave this crate a build-time path
// into the proprietary crate: `cargo test` could not pass standalone, contradicting the
// documented OSS boundary, and the published crate shipped a test that could not compile
// for anyone who downloaded it.

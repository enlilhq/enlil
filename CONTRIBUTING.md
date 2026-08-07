# Contributing to Enlil

Thanks for looking. Enlil is a security tool, so the bar for changes on the
request path is "demonstrated with a test", not "looks right".

## The most valuable contribution: a new detection

If you know a technique Enlil misses — a prompt-injection phrasing, an
exfiltration pattern, a tool-poisoning vector, an encoding trick — that is the
most useful thing you can send.

**Send it as a failing test first.** A test that fails before your change and
passes after is worth more than a long explanation:

```rust
#[test]
fn test_my_bypass_is_caught() {
    let v = analyze(&serde_json::json!({
        "messages": [{"role": "user", "content": "<the payload that gets through>"}]
    }));
    assert_eq!(v.action, GuardAction::Block, "findings {:?}", v.findings);
}
```

If you'd rather not open a public issue for a bypass, email **security@samji.in**
and we'll handle it privately and credit you in the release notes.

## Ground rules for the hot path

Enforcement runs synchronously on every request, so:

1. **Don't re-parse the body.** The request is parsed once into a
   `serde_json::Value` and shared across every analyzer. Take the parsed value.
2. **Bound your work.** Anything that recurses needs a depth cap; anything that
   scans needs a byte budget. A hostile payload will find an unbounded loop.
3. **Watch the budget.** `tests/proxy_overhead_bench.rs` asserts a per-request
   overhead budget and runs in CI. If your change makes it fail, that's a real
   signal, not a flaky test.
4. **Scan structurally, not per-vendor.** Do not add a detection that only works
   for one provider's field names. Enlil walks the whole payload precisely so it
   isn't playing catch-up with every new API shape.

## False positives matter as much as false negatives

A control plane that blocks legitimate traffic gets turned off, and then it
protects nothing. Any new detection should come with a benign case proving it
doesn't fire on ordinary traffic. See
`test_benign_multivendor_payloads_still_allowed`.

## Before you open a PR

```bash
cargo test                          # unit + integration
cargo clippy --all-targets -- -D warnings
cargo fmt --all
cargo test --release --test proxy_overhead_bench -- --nocapture
```

Clippy is a hard gate in CI. Formatting is checked but non-blocking.

## Scope

Enlil is deliberately single-tenant with no auth layer — it assumes the operator
owns the process. Multi-tenancy, SSO/RBAC, and long-term retention are out of
scope here by design; they live in the commercial build. PRs adding them will be
declined, not because they're bad ideas, but because they'd change what this
crate is.

Bug fixes, detections, performance, protocol coverage, docs, and packaging are
all in scope and welcome.

## Licence

Contributions are accepted under the repository's [BSL 1.1](LICENSE), which
converts to Apache 2.0 on the Change Date. By opening a PR you agree your
contribution ships under those terms.

# Changelog

All notable changes to Enlil are documented here.

Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semver](https://semver.org/).

## [0.3.0] — 2026-08-13

### Added

- **Per-trace retention windows.** `Trace.expires_at: Option<u64>` and
  `Trace::set_retention(Option<u32>)` stamp an expiry once, at record time. Deliberately
  **not retroactive**: changing the retention that applies to a tenant affects traces
  recorded from then on, not ones already written.
- **`ProxyEnv::retention_days(&self, tenant_id: &str) -> Option<u32>`**, a new trait hook
  whose default is `None` (no expiry). The OSS build is single-tenant and self-hosted, so
  there is no tier to derive a window from and nothing changes unless you implement it.
- **`TraceSummary.block_reason: Option<String>`** — *why* a request was blocked, not just
  that something stopped it.
- **`delete_by_tenant(tenant_id) -> usize`** on the trace stores (SQLite/in-memory and the
  optional DynamoDB one), for deleting everything one tenant owns.

### Changed

- **Breaking: the `lambda` Cargo feature is renamed `aws`.** It only ever gated the optional
  AWS SDK dependencies behind the DynamoDB trace store — it never implied the Lambda
  runtime, and this crate has no Lambda-runtime dependency at all. If you build with
  `features = ["lambda"]`, switch to `features = ["aws"]`.
- **Breaking: `Trace` gained a public field** (`expires_at`). `Trace` is not
  `#[non_exhaustive]`, so code constructing one via a struct literal needs updating;
  `Trace::start` is unaffected and is the intended constructor.
- **Trace eviction is now per tenant instead of globally oldest-first.** A high-volume
  tenant could previously evict a quiet tenant's history out of the store entirely, since
  both the in-memory capacity bound and the SQLite one shared a single global queue. Both
  are now bounded per tenant (the SQLite side via a
  `ROW_NUMBER() OVER (PARTITION BY tenant_id ...)` window).
- **SQLite trace persistence now deletes expired rows** (past their `expires_at`) before
  applying the capacity bound.
- `docs/` is excluded from the published package. The README references its images by
  absolute URL — which is what crates.io requires anyway — so shipping them added roughly
  1.2 MB to every download for no benefit.

### Security

- Mutex poisoning no longer propagates panics through the trace store, the telemetry
  middleware, or the PII redaction path. A thread panicking while holding one of these
  locks previously poisoned it and turned every later access into a panic; they now
  recover the guard with `unwrap_or_else(|e| e.into_inner())`.

## [0.2.0] — never published

Bumped in-tree but never released to crates.io, which is why the published history jumps
from 0.1.1 to 0.3.0. Its changes ship as part of 0.3.0 and are recorded here so the
version history isn't misleading.

### Added

- `UsageEvent.latency_us: u64` and `UsageEvent.cache_hit: bool`.
- `UsageEvent` is now `#[non_exhaustive]`. Downstream crates consume it in `record_usage`
  rather than constructing it, so marking it means the next added field costs nobody a
  major version.

### Fixed

- **Cache hits never reached `record_usage`.** Responses served from the cache bypassed
  usage recording entirely, so they were missing from request totals and `cache_hit` was
  uniformly `false`.
- **Latency was hardcoded to `0`** rather than measured, making any reported per-request
  latency either fabricated or sourced from process-local counters that reset on restart.

## [0.1.1] — 2026-08-08

### Fixed

- **The built-in dashboard rendered empty.** The stats grid showed nothing and the
  trace table showed no rows even when the API had data, because the dashboard's
  JavaScript was written against guessed field names rather than the real API
  responses:

  | Dashboard expected | API actually returns | Symptom |
  |---|---|---|
  | `latency_ms` | `latency_us` | latency column showed `-` |
  | `cache_hit` (bool) | `cache: "hit" \| "miss" \| "n/a"` | cache hits never shown |
  | `timestamp` in milliseconds | unix **seconds** | timestamps rendered as 1970 |
  | `rule.pattern` | `rule.condition.BodyRegex` | rule patterns blank |
  | `action === "block"` | `"Block"` (capitalised enum) | wrong rule badge colours |

  The API itself was correct throughout; only the presentation layer was wrong.
  Every formatter is now verified against real captured responses.

### Added

- Trace table now shows a **Protocol** column (OpenAI / MCP / A2A / Generic), so
  the same engine governing different payload types is visible at a glance.
- Colour-coded HTTP status badges, and human-readable durations (`240µs`,
  `256.3ms`) instead of raw microseconds.
- Empty states that tell you what to do next rather than rendering a blank table.
- Keyboard focus styles on trace rows.
- `CHANGELOG.md`, `SECURITY.md`, and `CONTRIBUTING.md`.

## [0.1.0] — 2026-08-07

First public release.

### Added

- **Inline enforcement**: prompt-injection and tool-poisoning defense (including
  MCP tool-description scanning for hidden imperatives, encoded blobs, and
  Unicode-tag smuggling), declarative block/redact/alert policy rules, reversible
  PII redaction, shell deobfuscation, encoded-exfiltration detection, agent
  loop-breaker, RiskChain behavioural checks, context-window guard, and SafeFix
  command advisories.
- **Audit**: per-request traces carrying the full governance decision path,
  stored locally in SQLite. Optional DynamoDB backend behind the `lambda` feature.
- **Efficiency**: exact-intent response caching (blake3 over request intent —
  exact-match deduplication, *not* embedding similarity), token attribution with
  provider prompt-cache pricing, and a per-provider circuit breaker with local
  fallback.
- **Vendor-neutral scanning**: payloads are inspected structurally rather than by
  schema, so OpenAI (including multimodal content arrays), Anthropic, Gemini, MCP
  `tools/call` arguments, bare `prompt` fields, and unrecognised shapes are all
  covered without per-vendor adapters.
- Dashboard embedded in the binary, served at `/`.
- `ProxyEnv` extension trait, whose hooks default to no-ops, for attaching usage
  accounting or alerting without forking the request path.
- Per-request governance overhead of ~18µs median / ~28µs p99, asserted against a
  budget in CI.

### Known limitations

- No authentication layer, by design. Enlil is single-tenant and assumes the
  operator owns the process. Don't expose it to untrusted networks without your
  own auth in front.
- Injection detection is pattern-based. It raises attacker cost and catches
  published techniques; it is not a semantic classifier and should not be your
  only control.
- The loop-breaker extracts intent from `messages` + `tools`. For other schemas it
  falls back to fingerprinting the whole body, which catches identical repeats but
  can be defeated by a changing nonce or timestamp.

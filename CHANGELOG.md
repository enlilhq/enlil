# Changelog

All notable changes to Enlil are documented here.

Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [semver](https://semver.org/).

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

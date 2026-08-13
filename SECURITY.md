# Security Policy

## Reporting a vulnerability

**Please don't open a public issue for a vulnerability.**

Email **security@samji.in** with:

- what the issue is, and what an attacker gains
- the smallest payload or steps that reproduce it
- the version (`enlil --help` or the crates.io version you installed)

You'll get an acknowledgement within **72 hours** and an assessment within a week.
If you don't hear back, assume the mail went astray and open a public issue
asking us to check our inbox — an unanswered report is worse than a public one.

We'll credit you in the release notes and `CHANGELOG.md` unless you'd rather stay
anonymous. There's no bug bounty; Enlil is a small source-available project and
we'd rather be honest about that than imply a payout.

## Scope

Enlil is a security control, so the most valuable reports are **bypasses**: a
payload that should be blocked and isn't.

In scope:

- Injection, tool-poisoning, or exfiltration payloads that evade detection
- PII that passes through unredacted
- Policy rules that can be circumvented
- A crash, hang, or unbounded resource use triggered by a crafted payload
  (the request path is inline, so a panic is a denial of service)
- Anything that causes a request to skip enforcement entirely
- Leakage of the PII vault, trace contents, or the `Authorization` header

Out of scope — these are documented design decisions, not vulnerabilities:

- **No authentication.** Enlil is single-tenant and assumes the operator owns the
  process. "Anyone who can reach the port can use the proxy" is expected; put your
  own auth in front of it.
- **Pattern-based detection being incomplete.** A novel phrasing that slips past a
  regex is a welcome *contribution* (see [CONTRIBUTING.md](CONTRIBUTING.md)), but
  it isn't a vulnerability report unless it defeats a control that claims to be
  complete. We don't claim the classifier is complete.
- Findings against the commercial Plumb service rather than this crate.

## Known advisories in dependencies

Honesty is more useful here than a clean-looking `cargo audit`, so:

**`cargo audit` currently reports 3 advisories against `rustls-webpki 0.101.7`**
([RUSTSEC-2026-0098](https://rustsec.org/advisories/RUSTSEC-2026-0098),
[-0099](https://rustsec.org/advisories/RUSTSEC-2026-0099),
[-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104) — two certificate
name-constraint issues and a reachable panic in CRL parsing).

**They are not reachable from a default build.** That version is pulled in only by
the optional `aws` feature, via `aws-config` → `aws-smithy-http-client` →
`hyper-rustls 0.24` → `rustls 0.21`. Verified:

| Build | TLS stack | Affected |
|---|---|---|
| default (`cargo install enlil`, the Docker image, release binaries) | `rustls 0.23` + `rustls-webpki 0.103.13` | **No** |
| `--features aws` | `rustls 0.21` + `rustls-webpki 0.101.7` | Yes |

Reproduce with `cargo tree | grep rustls-webpki` versus
`cargo tree --features aws | grep rustls-webpki`. Removing the AWS
dependencies entirely takes the tree from 316 to 250 crates and the advisory
count to zero.

`cargo audit` reads `Cargo.lock`, which is feature-agnostic, so it reports these
regardless of whether you can reach them. There is no fix available upstream yet:
`aws-config` exposes only a `rustls` feature, which *is* the legacy stack.

If you enable `--features aws`, you are trusting the AWS SDK's TLS stack for
calls to AWS endpoints. If that isn't acceptable, don't enable the feature — the
default SQLite trace backend has no AWS dependency at all. We intend to move the
DynamoDB backend out of this crate so the OSS engine has no AWS dependency in any
configuration.


## Supported versions

Enlil is pre-1.0 and only the latest minor version receives fixes.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## What Enlil does with your data

Worth stating plainly, since it's a proxy and sees everything:

- **Provider API keys are never stored.** The upstream `Authorization` header is
  passed through untouched.
- **Traces are local.** They go to SQLite under `DATA_DIR` on your own disk.
- **Nothing is sent anywhere.** There is no telemetry, no phone-home, no analytics,
  and no network egress other than the upstream request you asked for.
- **Redacted PII** is held in a local in-process vault so redaction can be
  reversed. It is not persisted to disk in the open-source build.

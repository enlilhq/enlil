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
anonymous. There's no bug bounty; Enlil is an unfunded open-source project and
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

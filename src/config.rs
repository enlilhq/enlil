//! Environment-driven configuration for the Enlil core.
//!
//! Multi-tenant policy (`TenantRegistry`/`TenantPolicy`) is a cloud concern and
//! lives in the `plumb` crate — see DEVELOPMENT_PLAN.md.

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize)]
pub struct ProxyConfig {
    pub port: u16,
    pub upstream_url: String,
    pub upstream_routes: Vec<UpstreamRoute>,
    pub global_token_limit: u32,
    pub cache_ttl_secs: u64,
    pub cache_max_capacity: u64,
    pub max_payload_bytes: usize,
    /// Only used by the cloud build (`plumb`) for dashboard/JWT auth. The OSS
    /// `enlil` binary is single-tenant and does not issue or validate tokens.
    pub jwt_secret: String,
    pub database_url: Option<String>,
    /// When true, proxy requests without any tenant identity (proxy key, x-tenant-id,
    /// or a valid JWT) are rejected with 401 instead of falling back to `default_tenant`.
    /// Cloud-only.
    #[serde(default)]
    pub require_auth: bool,
    /// Optional shared admin key. When set, presenting it via `x-admin-key` grants
    /// super-admin (cross-tenant) access to the PII vault reveal/audit endpoints and
    /// allows minting privileged JWT roles. When unset, that path is disabled. Cloud-only.
    #[serde(default)]
    pub admin_api_key: Option<String>,
}

// Manual Debug impl so the JWT secret is never leaked into logs (main.rs logs `?config`).
impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("port", &self.port)
            .field("upstream_url", &self.upstream_url)
            .field("upstream_routes", &self.upstream_routes)
            .field("global_token_limit", &self.global_token_limit)
            .field("cache_ttl_secs", &self.cache_ttl_secs)
            .field("cache_max_capacity", &self.cache_max_capacity)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field("jwt_secret", &"***REDACTED***")
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "***REDACTED***"),
            )
            .field("require_auth", &self.require_auth)
            .field(
                "admin_api_key",
                &self.admin_api_key.as_ref().map(|_| "***REDACTED***"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamRoute {
    pub path_prefix: String,
    pub target: String,
    pub name: String,
}

impl ProxyConfig {
    pub fn from_env() -> Self {
        Self {
            port: env_or("PORT", "8080").parse().unwrap_or(8080),
            upstream_url: env_or("UPSTREAM_URL", DEFAULT_UPSTREAM),
            upstream_routes: vec![
                UpstreamRoute {
                    path_prefix: "/v1/".into(),
                    target: env_or("OPENAI_UPSTREAM", "https://api.openai.com"),
                    name: "OpenAI".into(),
                },
                UpstreamRoute {
                    path_prefix: "/anthropic/".into(),
                    target: env_or("ANTHROPIC_UPSTREAM", "https://api.anthropic.com"),
                    name: "Anthropic".into(),
                },
                UpstreamRoute {
                    path_prefix: "/mcp/".into(),
                    target: env_or("MCP_UPSTREAM", "http://localhost:3001"),
                    name: "MCP Server".into(),
                },
            ],
            global_token_limit: env_or("GLOBAL_TOKEN_LIMIT", "100000")
                .parse()
                .unwrap_or(100_000),
            cache_ttl_secs: env_or("CACHE_TTL_SECS", "900").parse().unwrap_or(900),
            cache_max_capacity: env_or("CACHE_MAX_CAPACITY", "10000")
                .parse()
                .unwrap_or(10_000),
            max_payload_bytes: env_or("MAX_PAYLOAD_BYTES", "1048576")
                .parse()
                .unwrap_or(1_048_576),
            jwt_secret: resolve_jwt_secret(),
            database_url: std::env::var("DATABASE_URL").ok(),
            require_auth: env_or("REQUIRE_AUTH", "false").parse().unwrap_or(false),
            admin_api_key: std::env::var("ADMIN_API_KEY")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        }
    }

    /// Configuration for the **open-source, single-tenant** build.
    ///
    /// Identical to [`from_env`](Self::from_env) except that it does not touch any
    /// of the multi-tenant/cloud fields. In particular it does not resolve a JWT
    /// signing secret: the OSS server issues and validates no tokens (it has no
    /// auth layer at all — the operator owns the process), so warning about a
    /// missing `JWT_SECRET` would be noise that implies a security control the
    /// OSS build does not claim to have.
    ///
    /// `jwt_secret` is therefore left empty here. This is only sound because no
    /// OSS code path reads it; the cloud build must keep using `from_env`.
    pub fn from_env_oss() -> Self {
        Self {
            jwt_secret: String::new(),
            database_url: None,
            require_auth: false,
            admin_api_key: None,
            ..Self::from_env_common()
        }
    }

    /// The fields shared by both builds.
    fn from_env_common() -> Self {
        Self {
            port: env_or("PORT", "8080").parse().unwrap_or(8080),
            upstream_url: env_or("UPSTREAM_URL", DEFAULT_UPSTREAM),
            upstream_routes: vec![
                UpstreamRoute {
                    path_prefix: "/v1/".into(),
                    target: env_or("OPENAI_UPSTREAM", "https://api.openai.com"),
                    name: "OpenAI".into(),
                },
                UpstreamRoute {
                    path_prefix: "/anthropic/".into(),
                    target: env_or("ANTHROPIC_UPSTREAM", "https://api.anthropic.com"),
                    name: "Anthropic".into(),
                },
                UpstreamRoute {
                    path_prefix: "/mcp/".into(),
                    target: env_or("MCP_UPSTREAM", "http://localhost:3001"),
                    name: "MCP Server".into(),
                },
            ],
            global_token_limit: env_or("GLOBAL_TOKEN_LIMIT", "100000")
                .parse()
                .unwrap_or(100_000),
            cache_ttl_secs: env_or("CACHE_TTL_SECS", "900").parse().unwrap_or(900),
            cache_max_capacity: env_or("CACHE_MAX_CAPACITY", "10000")
                .parse()
                .unwrap_or(10_000),
            max_payload_bytes: env_or("MAX_PAYLOAD_BYTES", "1048576")
                .parse()
                .unwrap_or(1_048_576),
            jwt_secret: String::new(),
            database_url: None,
            require_auth: false,
            admin_api_key: None,
        }
    }

    pub fn resolve_upstream(&self, path: &str) -> &str {
        for route in &self.upstream_routes {
            if path.starts_with(&route.path_prefix) {
                return &route.target;
            }
        }
        &self.upstream_url
    }
}

/// Fallback upstream for requests that match none of the configured route prefixes.
///
/// Deliberately a real provider rather than a public echo service: an audit and
/// control plane must not silently forward unmatched agent traffic to a third-party
/// endpoint the operator did not choose.
const DEFAULT_UPSTREAM: &str = "https://api.openai.com";

pub fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Resolves the on-disk path for a SQLite-backed store file.
///
/// Defaults to `data/<name>`. Set `DATA_DIR` to override — e.g. the Lambda binary
/// points this at `/tmp/data`, since `/tmp` is the only writable filesystem in the
/// Lambda execution environment. Note this is a stopgap: `/tmp` is not guaranteed to
/// persist or be shared across invocations/concurrent execution environments, so
/// metrics/traces/memory history is not reliably durable on Lambda until migrated
/// to DynamoDB.
pub fn data_path(name: &str) -> String {
    let dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string());
    format!("{}/{}", dir.trim_end_matches('/'), name)
}

/// Resolves the JWT signing secret.
///
/// In production `JWT_SECRET` must be set. If it is missing we generate a random
/// ephemeral secret (so we never ship a well-known, forgeable default). Tokens
/// signed with an ephemeral secret do not survive a restart — this is logged loudly.
fn resolve_jwt_secret() -> String {
    match std::env::var("JWT_SECRET") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => {
            let ephemeral = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            tracing::warn!(
                "JWT_SECRET is not set — generated an ephemeral random secret. \
                 Issued tokens will be invalidated on restart. Set JWT_SECRET for production."
            );
            ephemeral
        }
    }
}

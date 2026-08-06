//! Request identity — **OSS (Enlil) core.**
//!
//! This is deliberately minimal and dependency-free so the open-source `enlil`
//! binary can attribute a request to a caller without pulling in the proprietary
//! multi-tenant auth stack (`middleware::auth`), which owns JWT validation,
//! API-key lookup, admin authorization and the tenant registry.
//!
//! In OSS single-tenant mode this is populated with a default identity; in the
//! cloud build it is populated by `middleware::auth::auth_middleware` from a
//! proxy key, `x-tenant-id` header, or a signed JWT.
//!
//! `middleware::auth` re-exports `TenantContext` from here, so existing call
//! sites keep working unchanged (see DEVELOPMENT_PLAN.md, Step 2).

/// Identifies the caller a request is attributed to.
///
/// Carried in Axum request extensions.
#[derive(Clone, Debug)]
pub struct TenantContext {
    /// The tenant this request is attributed to. In OSS single-tenant mode this
    /// is the default tenant.
    pub tenant_id: String,
    /// The API key used, when the request was authenticated by one. Always
    /// `None` in OSS single-tenant mode (no key store).
    pub api_key_id: Option<uuid::Uuid>,
}

impl TenantContext {
    /// The identity used by the OSS single-tenant build when no auth is configured.
    pub fn single_tenant() -> Self {
        Self {
            tenant_id: "default_tenant".to_string(),
            api_key_id: None,
        }
    }
}

use dashmap::DashMap;
use lazy_static::lazy_static;
use regex::Regex;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

lazy_static! {
    static ref SSN_REGEX: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    static ref EMAIL_REGEX: Regex =
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
    static ref CC_REGEX: Regex = Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap();
    static ref PHONE_REGEX: Regex =
        Regex::new(r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap();
}

static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Maximum number of audit events retained in memory.
const AUDIT_LOG_CAPACITY: usize = 1000;

/// Stores PII token → original value mappings for reversibility, plus an audit log
/// of every reveal attempt. Reveals are tenant-scoped and access-controlled at the
/// HTTP layer (see `routing::vault`). The vault's originals are treated as secured
/// production data and are never returned without an explicit, audited reveal.
pub struct PiiVault {
    /// Maps token (e.g. "PII_SSN_001") → original value + metadata.
    vault: DashMap<String, PiiEntry>,
    /// Bounded ring buffer of reveal/list audit events (newest last).
    audit: Mutex<Vec<AuditEvent>>,
}

#[derive(Clone)]
pub struct PiiEntry {
    pub original: String,
    pub pii_type: String,
    pub tenant_id: String,
    pub created_at: u64,
}

/// Non-sensitive metadata about a stored PII token (never includes the original value).
#[derive(Clone, Serialize)]
pub struct PiiTokenInfo {
    pub token: String,
    pub pii_type: String,
    pub tenant_id: String,
    pub created_at: u64,
}

/// An entry in the reveal audit trail.
#[derive(Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    /// Who performed the action (e.g. "admin-key", "jwt:tenant=acme").
    pub actor: String,
    /// One of: "reveal", "reveal_denied", "reveal_not_found", "list".
    pub action: String,
    pub token: String,
    pub tenant_id: String,
    pub pii_type: String,
}

/// Result of an access-controlled reveal.
pub enum RevealResult {
    Revealed(String),
    /// Token exists but belongs to another tenant and the caller is not a super-admin.
    Forbidden,
    NotFound,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Default for PiiVault {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiVault {
    pub fn new() -> Self {
        Self {
            vault: DashMap::new(),
            audit: Mutex::new(Vec::new()),
        }
    }

    /// Low-level, unaudited reveal. Prefer [`PiiVault::reveal_for`] for access-controlled paths.
    pub fn reveal(&self, token: &str) -> Option<String> {
        self.vault.get(token).map(|e| e.original.clone())
    }

    /// Access-controlled, audited reveal.
    ///
    /// `super_admin` callers may reveal any tenant's token; otherwise the token's
    /// `tenant_id` must equal `caller_tenant`. Every attempt is recorded to the audit log.
    pub fn reveal_for(
        &self,
        token: &str,
        actor: &str,
        caller_tenant: &str,
        super_admin: bool,
    ) -> RevealResult {
        match self.vault.get(token) {
            None => {
                self.record_audit(actor, "reveal_not_found", token, caller_tenant, "");
                RevealResult::NotFound
            }
            Some(entry) => {
                if !super_admin && entry.tenant_id != caller_tenant {
                    self.record_audit(
                        actor,
                        "reveal_denied",
                        token,
                        &entry.tenant_id,
                        &entry.pii_type,
                    );
                    RevealResult::Forbidden
                } else {
                    self.record_audit(actor, "reveal", token, &entry.tenant_id, &entry.pii_type);
                    RevealResult::Revealed(entry.original.clone())
                }
            }
        }
    }

    /// List token metadata (never originals), scoped to the caller's tenant unless super-admin.
    pub fn list_tokens(&self, caller_tenant: &str, super_admin: bool) -> Vec<PiiTokenInfo> {
        self.vault
            .iter()
            .filter(|e| super_admin || e.value().tenant_id == caller_tenant)
            .map(|e| PiiTokenInfo {
                token: e.key().clone(),
                pii_type: e.value().pii_type.clone(),
                tenant_id: e.value().tenant_id.clone(),
                created_at: e.value().created_at,
            })
            .collect()
    }

    /// Return recent audit events, scoped to the caller's tenant unless super-admin.
    pub fn get_audit(
        &self,
        caller_tenant: &str,
        super_admin: bool,
        limit: usize,
    ) -> Vec<AuditEvent> {
        let audit = self.audit.lock().unwrap();
        audit
            .iter()
            .rev()
            .filter(|e| super_admin || e.tenant_id == caller_tenant)
            .take(limit)
            .cloned()
            .collect()
    }

    fn record_audit(
        &self,
        actor: &str,
        action: &str,
        token: &str,
        tenant_id: &str,
        pii_type: &str,
    ) {
        let event = AuditEvent {
            timestamp: now_secs(),
            actor: actor.to_string(),
            action: action.to_string(),
            token: token.to_string(),
            tenant_id: tenant_id.to_string(),
            pii_type: pii_type.to_string(),
        };
        let mut audit = self.audit.lock().unwrap();
        audit.push(event);
        if audit.len() > AUDIT_LOG_CAPACITY {
            let drain_to = audit.len() - AUDIT_LOG_CAPACITY;
            audit.drain(0..drain_to);
        }
    }

    /// Store a PII value and return its token
    fn store(&self, original: &str, pii_type: &str, tenant_id: &str) -> String {
        let id = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
        let token = format!("PII_{}_{:04}", pii_type, id);
        self.vault.insert(
            token.clone(),
            PiiEntry {
                original: original.to_string(),
                pii_type: pii_type.to_string(),
                tenant_id: tenant_id.to_string(),
                created_at: now_secs(),
            },
        );
        token
    }
}

/// Scans and masks PII with reversible tokens.
/// Returns `true` if the payload was modified.
pub fn redact_pii(text: &mut String, vault: &PiiVault, tenant_id: &str) -> bool {
    let mut modified = false;

    // SSN
    let matches: Vec<String> = SSN_REGEX
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();
    for m in matches {
        let token = vault.store(&m, "SSN", tenant_id);
        *text = text.replace(&m, &format!("[{}]", token));
        modified = true;
    }

    // Email
    let matches: Vec<String> = EMAIL_REGEX
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();
    for m in matches {
        let token = vault.store(&m, "EMAIL", tenant_id);
        *text = text.replace(&m, &format!("[{}]", token));
        modified = true;
    }

    // Credit Card
    let matches: Vec<String> = CC_REGEX
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();
    for m in matches {
        let token = vault.store(&m, "CC", tenant_id);
        *text = text.replace(&m, &format!("[{}]", token));
        modified = true;
    }

    // Phone
    let matches: Vec<String> = PHONE_REGEX
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect();
    for m in matches {
        let token = vault.store(&m, "PHONE", tenant_id);
        *text = text.replace(&m, &format!("[{}]", token));
        modified = true;
    }

    modified
}

/// Legacy API compatibility — strips PII without vault (non-reversible)
pub fn redact_pii_strip(text: &mut String) -> bool {
    let mut modified = false;
    if SSN_REGEX.is_match(text) {
        *text = SSN_REGEX.replace_all(text, "[REDACTED_SSN]").to_string();
        modified = true;
    }
    if EMAIL_REGEX.is_match(text) {
        *text = EMAIL_REGEX
            .replace_all(text, "[REDACTED_EMAIL]")
            .to_string();
        modified = true;
    }
    if CC_REGEX.is_match(text) {
        *text = CC_REGEX.replace_all(text, "[REDACTED_CC]").to_string();
        modified = true;
    }
    if PHONE_REGEX.is_match(text) {
        *text = PHONE_REGEX
            .replace_all(text, "[REDACTED_PHONE]")
            .to_string();
        modified = true;
    }
    modified
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reversible_pii_masking() {
        let vault = PiiVault::new();
        let mut text = "My SSN is 123-45-6789 and email is test@example.com".to_string();
        let modified = redact_pii(&mut text, &vault, "test-tenant");
        assert!(modified);
        assert!(!text.contains("123-45-6789"));
        assert!(!text.contains("test@example.com"));
        assert!(text.contains("[PII_SSN_"));
        assert!(text.contains("[PII_EMAIL_"));

        // Verify reversibility
        let ssn_token = text.split('[').nth(1).unwrap().split(']').next().unwrap();
        let revealed = vault.reveal(ssn_token).unwrap();
        assert_eq!(revealed, "123-45-6789");
    }

    #[test]
    fn test_no_pii() {
        let vault = PiiVault::new();
        let mut text = "Hello world, no PII here".to_string();
        assert!(!redact_pii(&mut text, &vault, "test"));
    }
}

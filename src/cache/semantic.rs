use crate::engine::parser::{extract_intent, extract_intent_value};
use serde_json::Value;

/// Generates a deterministic hash for a given request payload, isolated by tenant.
/// It parses the semantic intent first so that trivial payload differences don't cause cache misses.
pub fn generate_hash(tenant_id: &str, payload: &[u8]) -> Option<String> {
    let intent = extract_intent(payload)?;
    hash_intent(tenant_id, &intent)
}

/// Same as [`generate_hash`] but from an already-parsed JSON value (avoids re-parsing).
pub fn generate_hash_value(tenant_id: &str, json: &Value) -> Option<String> {
    let intent = extract_intent_value(json)?;
    hash_intent(tenant_id, &intent)
}

fn hash_intent(tenant_id: &str, intent: &Value) -> Option<String> {
    // Convert the normalized JSON intent back to a string for hashing
    // We use to_string to ensure object keys are consistently serialized.
    let intent_str = serde_json::to_string(intent).ok()?;

    // Incorporate the tenant_id into the hash to prevent cross-tenant data leaks
    let hash_input = format!("{}:{}", tenant_id, intent_str);

    // Hash using blake3 for ultra-low latency
    let hash = blake3::hash(hash_input.as_bytes());

    Some(hash.to_hex().to_string())
}

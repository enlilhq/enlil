use blake3;
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;

/// Tracks agent identities within a tenant via explicit header or system prompt fingerprint.
pub struct AgentRegistry {
    /// Maps fingerprint hash → agent_id (user-provided or auto-generated)
    fingerprints: DashMap<String, String>,
    /// Maps (tenant_id, agent_id) → AgentStats
    pub stats: DashMap<(String, String), AgentStats>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AgentStats {
    pub agent_id: String,
    pub fingerprint: String,
    pub requests: u64,
    pub tokens: u64,
    pub cost_microdollars: u64,
    pub last_seen: u64,
}

impl AgentRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            fingerprints: DashMap::new(),
            stats: DashMap::new(),
        })
    }

    /// Resolve agent identity from request.
    /// Priority: x-agent-id header > system prompt fingerprint > "default"
    pub fn resolve_agent_id(&self, header_value: Option<&str>, body: &[u8]) -> String {
        if let Some(id) = header_value {
            if !id.is_empty() {
                return id.to_string();
            }
        }

        // Fingerprint the system prompt
        if let Some(fp) = extract_system_fingerprint(body) {
            // Check if we've seen this fingerprint before
            if let Some(existing) = self.fingerprints.get(&fp) {
                return existing.clone();
            }
            // Auto-generate an agent name from first 8 chars of hash
            let auto_id = format!("agent-{}", &fp[..8]);
            self.fingerprints.insert(fp, auto_id.clone());
            return auto_id;
        }

        "default".to_string()
    }

    /// Record a request for an agent
    pub fn record(&self, tenant_id: &str, agent_id: &str, tokens: u32, cost_microdollars: u64) {
        let key = (tenant_id.to_string(), agent_id.to_string());
        let mut entry = self.stats.entry(key).or_insert_with(|| AgentStats {
            agent_id: agent_id.to_string(),
            fingerprint: String::new(),
            ..Default::default()
        });
        entry.requests += 1;
        entry.tokens += tokens as u64;
        entry.cost_microdollars += cost_microdollars;
        entry.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Get all agents for a tenant
    pub fn get_tenant_agents(&self, tenant_id: &str) -> Vec<AgentStats> {
        self.stats
            .iter()
            .filter(|e| e.key().0 == tenant_id)
            .map(|e| e.value().clone())
            .collect()
    }
}

/// Extract and hash the system prompt from a chat completions request body.
fn extract_system_fingerprint(body: &[u8]) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
    let messages = parsed.get("messages")?.as_array()?;

    // Find system message(s)
    let system_content: String = messages
        .iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
        .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
        .collect::<Vec<_>>()
        .join("\n");

    if system_content.is_empty() {
        return None;
    }

    // Hash the system prompt to create a stable fingerprint
    let hash = blake3::hash(system_content.as_bytes());
    Some(hash.to_hex().to_string())
}

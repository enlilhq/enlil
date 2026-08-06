use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Mcp,
    OpenAI,
    A2A,
    Generic,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Mcp => write!(f, "MCP"),
            Protocol::OpenAI => write!(f, "OpenAI"),
            Protocol::A2A => write!(f, "A2A"),
            Protocol::Generic => write!(f, "Generic"),
        }
    }
}

/// Detects the protocol from a request body.
pub fn detect_protocol(body: &[u8]) -> Protocol {
    match serde_json::from_slice::<Value>(body) {
        Ok(json) => detect_protocol_value(&json),
        Err(_) => Protocol::Generic,
    }
}

/// Detects the protocol from an already-parsed JSON value (avoids re-parsing).
pub fn detect_protocol_value(json: &Value) -> Protocol {
    // JSON-RPC / MCP: has "jsonrpc" field
    if json.get("jsonrpc").is_some() {
        // Check if it's A2A JSON-RPC (methods like tasks/send, tasks/get, tasks/cancel)
        if let Some(method) = json.get("method").and_then(|m| m.as_str()) {
            if method.starts_with("tasks/") || method.starts_with("agent/") {
                return Protocol::A2A;
            }
        }
        return Protocol::Mcp;
    }

    // A2A: has "task" or "agent" top-level fields with specific structure
    if json.get("task").is_some() || json.get("agent_card").is_some() {
        return Protocol::A2A;
    }

    // OpenAI: has "model" and "messages" fields
    if json.get("model").is_some() && json.get("messages").is_some() {
        return Protocol::OpenAI;
    }

    Protocol::Generic
}

/// A2A task states per Google's Agent-to-Agent protocol spec
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum A2ATaskState {
    Submitted,
    Working,
    InputRequired,
    Completed,
    Canceled,
    Failed,
}

/// Extract A2A method from JSON-RPC request
pub fn extract_a2a_method(body: &[u8]) -> Option<String> {
    let json: Value = serde_json::from_slice(body).ok()?;
    json.get("method").and_then(|m| m.as_str()).map(String::from)
}

/// Validate A2A agent card structure
pub fn validate_agent_card(body: &[u8]) -> bool {
    let Ok(json) = serde_json::from_slice::<Value>(body) else { return false };
    // Agent card must have name, description, and capabilities
    json.get("name").is_some() && json.get("capabilities").is_some()
}

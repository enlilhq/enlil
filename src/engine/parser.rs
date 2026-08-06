use serde_json::Value;

/// Extracts the core "intent" from an LLM request payload.
/// This prevents caching from breaking if trivial metadata (like temperature, max_tokens, or a changing session ID) changes.
pub fn extract_intent(payload: &[u8]) -> Option<Value> {
    let json: Value = serde_json::from_slice(payload).ok()?;
    extract_intent_value(&json)
}

/// Extracts the core "intent" from an already-parsed request value (avoids re-parsing).
pub fn extract_intent_value(json: &Value) -> Option<Value> {
    // For standard OpenAI / MCP payloads, the core intent is usually in the "messages"
    // or the specific "tools" defined. We extract only those.
    let messages = json.get("messages")?.clone();
    let tools = json.get("tools").cloned().unwrap_or(Value::Null);

    Some(serde_json::json!({
        "messages": messages,
        "tools": tools,
    }))
}

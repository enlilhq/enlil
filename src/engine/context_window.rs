/// Returns the max context window (input tokens) for a given model.
pub fn get_model_context_limit(model: &str) -> u32 {
    match model {
        m if m.contains("gpt-4o") => 128_000,
        m if m.contains("gpt-4-turbo") => 128_000,
        m if m.contains("gpt-4") => 8_192,
        m if m.contains("gpt-3.5") => 16_385,
        m if m.contains("claude-3-5") => 200_000,
        m if m.contains("claude-3-opus") => 200_000,
        m if m.contains("claude-3") => 200_000,
        m if m.contains("llama-3.1") => 131_072,
        m if m.contains("llama-3") => 8_192,
        m if m.contains("mixtral") => 32_768,
        m if m.contains("gemma") => 8_192,
        _ => 128_000, // default generous limit
    }
}

/// Estimates input token count from request body (chars / 4).
/// Returns (estimated_tokens, model_name) if parseable.
pub fn check_context_overflow(body: &[u8]) -> Option<(u32, String, u32)> {
    let json: serde_json::Value = serde_json::from_slice(body).ok()?;
    check_context_overflow_value(&json)
}

/// Same as [`check_context_overflow`] but from an already-parsed JSON value.
pub fn check_context_overflow_value(json: &serde_json::Value) -> Option<(u32, String, u32)> {
    let model = json.get("model")?.as_str()?.to_string();
    let limit = get_model_context_limit(&model);

    // Estimate total input tokens from messages + tools
    let messages_chars = json.get("messages")
        .map(|v| v.to_string().len())
        .unwrap_or(0);
    let tools_chars = json.get("tools")
        .or_else(|| json.get("functions"))
        .map(|v| v.to_string().len())
        .unwrap_or(0);

    let estimated_tokens = ((messages_chars + tools_chars) / 4) as u32;

    if estimated_tokens > limit {
        Some((estimated_tokens, model, limit))
    } else {
        None
    }
}

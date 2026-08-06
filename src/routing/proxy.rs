use crate::error::AppError;
use crate::usage::{ProxyEnv, UsageEvent};
use crate::identity::TenantContext;
use axum::{
    body::Body,
    extract::{Request, State},
    response::IntoResponse,
};
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tracing::info;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use crate::tokens::{calculate_attribution, parse_usage};
use crate::cache::semantic::generate_hash_value;
use crate::cache::store::CachedResponse;
use crate::routing::protocols::{detect_protocol_value, Protocol};
use crate::observability::Trace;

pub enum StreamMessage {
    Chunk(Bytes),
    Done,
    Error,
}

pub async fn handle_proxy<E: ProxyEnv>(
    State(state): State<Arc<E>>,
    req: Request,
) -> Result<impl IntoResponse, AppError> {
    let tenant_ctx = req.extensions().get::<TenantContext>().cloned();
    let tenant_id = tenant_ctx.as_ref()
        .map(|t| t.tenant_id.clone())
        .unwrap_or_else(|| {
            req.headers()
                .get("x-tenant-id")
                .and_then(|val| val.to_str().ok())
                .unwrap_or("default_tenant")
                .to_string()
        });
    let api_key_id = tenant_ctx.as_ref().and_then(|t| t.api_key_id);

    // Time-travel trace: assign an id up-front so it can be returned as x-trace-id.
    let trace_start = Instant::now();
    let trace_id = uuid::Uuid::new_v4().simple().to_string();

    let session_id = req
        .headers()
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&tenant_id)
        .to_string();

    let agent_id_header = req
        .headers()
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or_default().to_string();

    // Upstream resolution priority:
    // 1. x-upstream header (client override per-request)
    // 2. Tenant's configured upstream (from DB)
    // 3. Path-based routing from config
    let upstream_base = if let Some(override_header) = req.headers().get("x-upstream") {
        let provider = override_header.to_str().unwrap_or("");
        match provider {
            "openrouter" => "https://openrouter.ai/api".to_string(),
            "groq" => "https://api.groq.com/openai".to_string(),
            "anthropic" => "https://api.anthropic.com".to_string(),
            "together" => "https://api.together.xyz".to_string(),
            "local" => "http://localhost:11434".to_string(),
            url if url.starts_with("http") => url.to_string(),
            _ => state.config.resolve_upstream(&path).to_string(),
        }
    } else if let Some(tenant_upstream) = state.resolve_tenant_upstream(&tenant_id).await {
        // Deployment-provided per-tenant upstream override (cloud only; the OSS
        // default returns None and falls through to local config below).
        tenant_upstream
    } else {
        state.config.resolve_upstream(&path).to_string()
    };

    let target_uri = if query.is_empty() {
        format!("{}{}", upstream_base, path)
    } else {
        format!("{}{}?{}", upstream_base, path, query)
    };

    let method = req.method().clone();
    let mut headers = req.headers().clone();
    headers.remove("host");
    headers.remove("content-length");
    headers.remove("accept-encoding");

    use http_body_util::BodyExt;
    let mut req_bytes: Bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .to_bytes();

    // Enforce the payload cap on the actual body size. The payload_size middleware only
    // inspects the (spoofable / optional) content-length header, so we re-check here after
    // buffering the real bytes to defend against chunked/oversized bodies.
    if req_bytes.len() > state.config.max_payload_bytes {
        tracing::warn!(
            len = req_bytes.len(),
            max = state.config.max_payload_bytes,
            "Request body exceeds max payload size"
        );
        return Err(AppError::PayloadTooLarge);
    }

    // Parse the JSON body once and share the parsed value across all analyzers below,
    // instead of each one re-parsing the same bytes (~7 parses → 1, or 2 if redaction
    // mutates the body). This is the dominant per-request CPU cost — see AUDIT.md.
    let mut parsed = serde_json::from_slice::<serde_json::Value>(&req_bytes).ok();

    // Protocol detection
    let protocol = parsed.as_ref().map(detect_protocol_value).unwrap_or(Protocol::Generic);
    info!("Detected protocol: {} for {}", protocol, path);
    state.metrics.record_event("request", &tenant_id, &format!("{} {} [{}]", method, path, protocol));

    // Resolve agent identity (header > system prompt fingerprint > "default").
    // Done before the loop-breaker so it is captured in the trace.
    let agent_id = state.agent_registry.resolve_agent_id(
        agent_id_header.as_deref(),
        &req_bytes,
    );

    // Begin the time-travel trace for this request.
    let mut trace = Trace::start(
        trace_id.clone(),
        tenant_id.clone(),
        session_id.clone(),
        agent_id.clone(),
        method.to_string(),
        path.clone(),
        protocol.to_string(),
        upstream_base.clone(),
    );
    trace.step(format!("protocol_detected={}", protocol));

    // Statistical anomaly detection (per-tenant request-interval + payload-size z-score).
    let anomaly_score = state.anomaly_detector.record(&tenant_id, req_bytes.len());
    if anomaly_score > 3.0 {
        tracing::warn!(tenant_id = %tenant_id, score = anomaly_score, "Traffic anomaly detected");
        state.metrics.record_event("anomaly", &tenant_id, &format!("Traffic anomaly (z-score {:.1})", anomaly_score));
        trace.step(format!("anomaly_score={:.1}", anomaly_score));
    }

    // Agent loop-breaker: sever a session stuck re-issuing the same intent before it burns
    // budget. Runs before caching/upstream so runaway loops are stopped regardless of cache.
    if method == axum::http::Method::POST {
        use crate::engine::loop_breaker::{intent_fingerprint, intent_fingerprint_value, LoopDecision};
        let fp = match &parsed {
            Some(v) => intent_fingerprint_value(&path, v),
            None => intent_fingerprint(&path, &req_bytes),
        };
        if let LoopDecision::Break { repeats } = state.loop_breaker.check(&session_id, fp) {
            tracing::warn!(
                session_id = %session_id,
                tenant_id = %tenant_id,
                repeats,
                "AGENT LOOP DETECTED — severing request to prevent budget burn"
            );
            state.metrics.loop_breaks.fetch_add(1, Ordering::Relaxed);
            state.metrics.record_event(
                "loop_break",
                &tenant_id,
                &format!("Agent loop severed: identical request repeated {} times in session", repeats),
            );

            // Fire webhook alert (best-effort, off the request path).
            let state_clone = state.clone();
            let tid = tenant_id.clone();
            let msg = format!("Agent loop detected and severed after {} identical requests", repeats);
            tokio::spawn(async move {
                state_clone.send_alert(&tid, "loop_break", &msg).await;
            });

            trace.step(format!("loop_break: {} repeats", repeats));
            trace.blocked = true;
            trace.block_reason = Some("agent_loop_detected".to_string());
            trace.status = 429;
            trace.latency_us = trace_start.elapsed().as_micros() as u64;
            state.trace_store.record(trace).await;

            return Err(AppError::LoopDetected(format!(
                "Agent loop detected: the same request intent repeated {} times in this session. \
                 Request severed to prevent runaway cost. Vary the request or start a new session.",
                repeats
            )));
        }
    }

    // RiskChain evaluation
    let risk_alert = match &parsed {
        Some(v) => state.risk_chain.evaluate_value(&session_id, v),
        None => state.risk_chain.evaluate(&session_id, &req_bytes),
    };
    if let Some(alert) = risk_alert {
        tracing::error!(
            session_id = %alert.session_id,
            pattern = %alert.pattern,
            "RISK CHAIN ALERT"
        );
        state.metrics.risk_chain_alerts.fetch_add(1, Ordering::Relaxed);
        state.metrics.record_event("risk_alert", &tenant_id, &alert.pattern);
        trace.step(format!("risk_alert: {}", alert.pattern));

        // Fire webhook alert
        let state_clone = state.clone();
        let tid = tenant_id.clone();
        let pattern = alert.pattern.clone();
        tokio::spawn(async move {
            state_clone.send_alert(&tid, "risk_alert", &pattern).await;
        });
    }

    // AgentTrust: PII Redaction & Deobfuscation
    let mut body_mutated = false;
    let mut safefix_note: Option<String> = None;
    if method == axum::http::Method::POST {
        if let Ok(payload_str) = String::from_utf8(req_bytes.to_vec()) {
            use crate::engine::pii_redact::redact_pii;
            use crate::engine::deobfuscate::deobfuscate_shell;

            let deobfuscated = deobfuscate_shell(&payload_str);
            let mut final_str = deobfuscated;

            // Inspection-only: flag base64-encoded secret/credential exfiltration (e.g.
            // read `.env` → base64 → POST). Does NOT mutate the forwarded body.
            if let Some(snippet) = crate::engine::deobfuscate::detect_encoded_exfil(&payload_str) {
                tracing::warn!(tenant_id = %tenant_id, "Encoded exfiltration detected: {}", snippet);
                state.metrics.risk_chain_alerts.fetch_add(1, Ordering::Relaxed);
                state.metrics.record_event("encoded_exfil", &tenant_id, &format!("Base64-encoded sensitive content: {}", snippet));
                trace.step("encoded_exfil_detected");
                let state_clone = state.clone();
                let tid = tenant_id.clone();
                tokio::spawn(async move {
                    state_clone.send_alert(&tid, "encoded_exfil", "Base64-encoded sensitive content detected in request").await;
                });
            }

            if redact_pii(&mut final_str, &state.pii_vault, &tenant_id) {
                info!("AgentTrust: PII masked for tenant {}", tenant_id);
                state.metrics.pii_redactions.fetch_add(1, Ordering::Relaxed);
                state.metrics.record_event("pii_redaction", &tenant_id, "PII detected and masked (reversible)");
                trace.step("pii_redacted");
                req_bytes = Bytes::from(final_str.clone());
                body_mutated = true;
            } else if final_str != payload_str {
                info!("AgentTrust: Shell deobfuscation applied for tenant {}", tenant_id);
                state.metrics.record_event("deobfuscation", &tenant_id, "Shell hex decoded");
                trace.step("shell_deobfuscated");
                req_bytes = Bytes::from(final_str.clone());
                body_mutated = true;
            }

            // SafeFix: analyze for dangerous patterns and suggest alternatives
            let suggestions = crate::engine::safefix::analyze(&final_str);
            if !suggestions.is_empty() {
                for s in &suggestions {
                    info!("SafeFix [{}]: {} → {}", s.severity, s.original, s.suggested);
                }
                trace.step(format!("safefix: {} suggestion(s)", suggestions.len()));
                state.metrics.record_event("safefix", &tenant_id,
                    &format!("{} suggestion(s): {}", suggestions.len(), suggestions[0].reason));

                // Surface the top suggestion back to the calling agent via a response header
                // (header-safe ASCII). We advise rather than silently rewrite the request.
                let top = &suggestions[0];
                let raw = format!(
                    "{} suggestion(s); top[{}]: {} => {}",
                    suggestions.len(), top.severity, top.original, top.suggested
                );
                let clean: String = raw.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(200).collect();
                safefix_note = Some(clean);
            }
        }
    }

    // Redaction/deobfuscation rewrote the body — re-parse once so downstream analyzers
    // (prompt guard, token estimate, context window, cache hash) see the final bytes.
    if body_mutated {
        parsed = serde_json::from_slice::<serde_json::Value>(&req_bytes).ok();
    }

    // Prompt-injection & tool-poisoning defense (#6). Runs on the finalized body.
    if method == axum::http::Method::POST {
        use crate::engine::prompt_guard::GuardAction;
        let verdict = match &parsed {
            Some(v) => state.prompt_guard.analyze_value(v),
            None => state.prompt_guard.analyze(&req_bytes),
        };
        match verdict.action {
            GuardAction::Block => {
                tracing::warn!(tenant_id = %tenant_id, score = verdict.score, "PROMPT-INJECTION BLOCKED: {}", verdict.summary());
                state.metrics.injection_blocks.fetch_add(1, Ordering::Relaxed);
                state.metrics.record_event("prompt_injection", &tenant_id, &verdict.summary());
                let state_clone = state.clone();
                let tid = tenant_id.clone();
                let msg = verdict.summary();
                tokio::spawn(async move {
                    state_clone.send_alert(&tid, "prompt_injection", &msg).await;
                });

                trace.step(format!("prompt_injection_block: {}", verdict.summary()));
                trace.blocked = true;
                trace.block_reason = Some("prompt_injection_blocked".to_string());
                trace.status = 403;
                trace.latency_us = trace_start.elapsed().as_micros() as u64;
                state.trace_store.record(trace).await;

                return Err(AppError::InjectionBlocked(format!(
                    "Request blocked by prompt-injection defense (score {}): {}",
                    verdict.score, verdict.summary()
                )));
            }
            GuardAction::Alert => {
                tracing::warn!(tenant_id = %tenant_id, score = verdict.score, "prompt-injection signal: {}", verdict.summary());
                state.metrics.rule_alerts.fetch_add(1, Ordering::Relaxed);
                state.metrics.record_event("prompt_injection_alert", &tenant_id, &verdict.summary());
                trace.step(format!("prompt_injection_alert: {}", verdict.summary()));
            }
            GuardAction::Allow => {}
        }
    }

    // Declarative policy rules (#5): block/redact/alert/log per configured SecurityRules.
    if method == axum::http::Method::POST {
        use crate::engine::rules::RuleAction;
        let body_str = String::from_utf8_lossy(&req_bytes);
        let est_tokens = (req_bytes.len() / 4) as u32;
        let matches = state.rule_engine.evaluate(&body_str, &tenant_id, est_tokens);
        let mut block: Option<(String, String)> = None; // (rule_id, rule_name)
        for m in &matches {
            match &m.action {
                RuleAction::Block => {
                    block = Some((m.rule_id.clone(), m.rule_name.clone()));
                }
                RuleAction::Alert => {
                    state.metrics.rule_alerts.fetch_add(1, Ordering::Relaxed);
                    state.metrics.record_event("policy_alert", &tenant_id, &format!("Rule '{}' matched", m.rule_name));
                    trace.step(format!("policy_alert: {}", m.rule_id));
                    let state_clone = state.clone();
                    let tid = tenant_id.clone();
                    let msg = format!("Policy rule '{}' matched", m.rule_name);
                    tokio::spawn(async move {
                        state_clone.send_alert(&tid, "policy_alert", &msg).await;
                    });
                }
                RuleAction::Redact => {
                    state.metrics.record_event("policy_redact", &tenant_id, &format!("Rule '{}' flagged content for redaction", m.rule_name));
                    trace.step(format!("policy_redact: {}", m.rule_id));
                }
                RuleAction::Log => {
                    info!("Policy rule '{}' matched for tenant {}", m.rule_name, tenant_id);
                    trace.step(format!("policy_log: {}", m.rule_id));
                }
            }
        }
        if let Some((rule_id, rule_name)) = block {
            tracing::warn!(tenant_id = %tenant_id, rule = %rule_id, "POLICY BLOCK");
            state.metrics.policy_blocks.fetch_add(1, Ordering::Relaxed);
            state.metrics.record_event("policy_block", &tenant_id, &format!("Blocked by rule '{}'", rule_name));
            let state_clone = state.clone();
            let tid = tenant_id.clone();
            let msg = format!("Request blocked by policy rule '{}'", rule_name);
            tokio::spawn(async move {
                state_clone.send_alert(&tid, "policy_block", &msg).await;
            });

            trace.step(format!("policy_block: {}", rule_id));
            trace.blocked = true;
            trace.block_reason = Some(format!("policy_blocked:{}", rule_id));
            trace.status = 403;
            trace.latency_us = trace_start.elapsed().as_micros() as u64;
            state.trace_store.record(trace).await;

            return Err(AppError::PolicyBlocked(format!(
                "Request blocked by policy rule '{}' ({})", rule_name, rule_id
            )));
        }
    }

    // Semantic Caching
    let mut request_hash = None;
    let (tool_tokens_est, memory_tokens_est) = match &parsed {
        Some(v) => crate::tokens::estimate_token_layers_value(v),
        None => (0, 0),
    };

    // Context window overflow protection
    if let Some((estimated, model, limit)) = parsed.as_ref().and_then(crate::engine::context_window::check_context_overflow_value) {
        tracing::warn!("Context overflow: {} est. tokens > {} limit for model {}", estimated, limit, model);
        state.metrics.record_event("context_overflow", &tenant_id, &format!("Blocked: ~{} tokens > {} limit ({})", estimated, limit, model));
        trace.step(format!("context_overflow: ~{} > {} ({})", estimated, limit, model));
        trace.blocked = true;
        trace.block_reason = Some("context_overflow".to_string());
        trace.status = 500;
        trace.latency_us = trace_start.elapsed().as_micros() as u64;
        state.trace_store.record(trace).await;
        return Err(AppError::Internal(format!(
            "Request exceeds model context window: ~{} tokens estimated, {} max for {}",
            estimated, limit, model
        )));
    }
    if method == axum::http::Method::POST {
        if let Some(hash) = parsed.as_ref().and_then(|v| generate_hash_value(&tenant_id, v)) {
            if let Some(cached_res) = state.cache_manager.get(&hash).await {
                // Cache poisoning prevention: validate integrity
                if !cached_res.is_valid() {
                    tracing::warn!("Cache integrity check FAILED for hash: {} — evicting", hash);
                    state.metrics.record_event("cache_poisoning", &tenant_id, "Corrupted cache entry evicted");
                    state.cache_manager.insert(&hash, CachedResponse::new(Bytes::new(), String::new())).await;
                } else {
                    info!("Cache HIT for hash: {}", hash);
                    state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                    state.metrics.cache_savings_microdollars.fetch_add(4000, Ordering::Relaxed);
                    state.metrics.record_event("cache_hit", &tenant_id, "Semantic cache hit — saved LLM call");

                    trace.step("cache_hit");
                    trace.cache = "hit".to_string();
                    trace.status = 200;
                    trace.latency_us = trace_start.elapsed().as_micros() as u64;
                    state.trace_store.record(trace).await;

                    let response = axum::response::Response::builder()
                        .status(axum::http::StatusCode::OK)
                        .header("x-cache", "HIT")
                        .header("x-trace-id", &trace_id);
                    let response = match &safefix_note {
                        Some(note) => response.header("x-agent-safefix", note),
                        None => response,
                    };
                    let response = response
                        .header("content-type", cached_res.content_type)
                        .body(Body::from(cached_res.body))
                        .map_err(|e| AppError::Internal(e.to_string()))?;
                    return Ok(response);
                }
            }
            state.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
            trace.cache = "miss".to_string();
            request_hash = Some(hash);
        }
    }

    // Circuit breaker: check if primary provider is available
    let fallback_providers = [
        ("groq", "https://api.groq.com/openai"),
        ("openrouter", "https://openrouter.ai/api"),
        ("together", "https://api.together.xyz"),
        // Last resort: a locally hosted OpenAI-compatible model (e.g. Ollama) for
        // resilience / data-sovereignty when all cloud providers are unavailable.
        ("local", "http://localhost:11434"),
    ];

    let primary_provider = extract_provider_name(&upstream_base);
    let mut effective_uri = target_uri.clone();

    if !state.circuit_breaker.is_available(&primary_provider) {
        // Primary is down — find a fallback
        if let Some((name, base)) = fallback_providers.iter()
            .find(|(name, _)| *name != primary_provider && state.circuit_breaker.is_available(name))
        {
            tracing::warn!("Circuit open for {}, failing over to {}", primary_provider, name);
            effective_uri = if query.is_empty() {
                format!("{}{}", base, path)
            } else {
                format!("{}{}?{}", base, path, query)
            };
            state.metrics.record_event("failover", &tenant_id, &format!("Circuit open: {} → {}", primary_provider, name));
            trace.step(format!("failover: {} → {}", primary_provider, name));
        }
    }

    // Capture the (post-redaction) request snapshot for deterministic replay.
    trace.set_replay(method.as_str(), &effective_uri, &req_bytes);

    let res = state
        .client
        .request(method.clone(), &effective_uri)
        .headers(headers.clone())
        .body(req_bytes.clone())
        .send()
        .await
        .map_err(AppError::ProxyError)?;

    // Handle failures: retry once, then record failure for circuit breaker
    let res = if res.status().is_server_error() {
        state.circuit_breaker.record_failure(&primary_provider);
        tracing::warn!("Upstream 5xx from {}, attempting retry", effective_uri);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let retry_res = state.client
            .request(method, &effective_uri)
            .headers(headers)
            .body(req_bytes)
            .send()
            .await
            .map_err(AppError::ProxyError)?;
        if retry_res.status().is_server_error() {
            state.circuit_breaker.record_failure(&primary_provider);
        } else {
            state.circuit_breaker.record_success(&primary_provider);
        }
        retry_res
    } else {
        state.circuit_breaker.record_success(&primary_provider);
        res
    };

    let is_success = res.status().is_success();
    let content_type = res.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let is_streaming = content_type.contains("text/event-stream");

    let mut response_builder = axum::response::Response::builder().status(res.status());
    for (key, value) in res.headers() {
        response_builder = response_builder.header(key, value);
    }

    // For non-streaming responses, collect body upfront for reliable processing
    if !is_streaming {
        let status = res.status();
        let body_bytes = res.bytes().await.map_err(|e| AppError::Internal(e.to_string()))?;

        trace.status = status.as_u16();
        trace.step(format!("upstream_status={}", status.as_u16()));
        trace.latency_us = trace_start.elapsed().as_micros() as u64;
        state.trace_store.record(trace).await;

        // Process usage/caching in the same task (no race condition)
        if is_success {
            process_response_body(
                &body_bytes, &state, &tenant_id, &agent_id, api_key_id,
                request_hash, &content_type, &path, &protocol.to_string(),
                tool_tokens_est, memory_tokens_est, &trace_id,
            ).await;
        }

        let axum_res = axum::response::Response::builder()
            .status(status)
            .header("content-type", &content_type)
            .header("x-trace-id", &trace_id);
        let axum_res = match &safefix_note {
            Some(note) => axum_res.header("x-agent-safefix", note),
            None => axum_res,
        };
        let axum_res = axum_res
            .body(Body::from(body_bytes))
            .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(axum_res);
    }

    // Streaming responses (SSE) — use channel-based approach
    let stream_status = res.status().as_u16();
    let mut upstream_stream = res.bytes_stream();
    let (tx, rx) = mpsc::unbounded_channel::<StreamMessage>();

    let state_clone = state.clone();
    let tenant_id_clone = tenant_id.clone();
    let agent_id_clone = agent_id.clone();
    let cacheable_hash = if is_success { request_hash } else { None };
    let path_clone = path.clone();
    let protocol_str = protocol.to_string();
    let trace_id_clone = trace_id.clone();

    trace.status = stream_status;
    trace.step(format!("upstream_status={} (streaming)", stream_status));
    trace.latency_us = trace_start.elapsed().as_micros() as u64;
    state.trace_store.record(trace).await;

    tokio::spawn(async move {
        process_response_body_streaming(rx, state_clone, tenant_id_clone, agent_id_clone, api_key_id, cacheable_hash, content_type, path_clone, protocol_str, tool_tokens_est, memory_tokens_est, trace_id_clone).await;
    });

    let response_stream = async_stream::stream! {
        loop {
            match upstream_stream.next().await {
                Some(Ok(chunk)) => {
                    let _ = tx.send(StreamMessage::Chunk(chunk.clone()));
                    yield Ok::<Bytes, std::io::Error>(chunk);
                }
                Some(Err(_)) => {
                    let _ = tx.send(StreamMessage::Error);
                    yield Err(std::io::Error::other("Stream error"));
                    break;
                }
                None => {
                    let _ = tx.send(StreamMessage::Done);
                    break;
                }
            }
        }
    };

    let axum_res = response_builder
        .header("x-trace-id", &trace_id);
    let axum_res = match &safefix_note {
        Some(note) => axum_res.header("x-agent-safefix", note),
        None => axum_res,
    };
    let axum_res = axum_res
        .body(Body::from_stream(response_stream))
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(axum_res)
}

/// Process non-streaming response body inline (reliable — no race condition)
#[allow(clippy::too_many_arguments)]
async fn process_response_body<E: ProxyEnv>(
    body: &Bytes,
    state: &Arc<E>,
    tenant_id: &str,
    agent_id: &str,
    api_key_id: Option<uuid::Uuid>,
    request_hash: Option<String>,
    content_type: &str,
    path: &str,
    protocol: &str,
    tool_tokens_est: u32,
    memory_tokens_est: u32,
    trace_id: &str,
) {
    // Capture a response fingerprint for deterministic replay diffing.
    let response_hash = blake3::hash(body).to_hex().to_string();
    state.trace_store.enrich_usage(trace_id, 0, 0, Some(response_hash)).await;

    if let Some(hash) = request_hash {
        let cached_res = CachedResponse::new(body.clone(), content_type.to_string());
        state.cache_manager.insert(&hash, cached_res).await;
    }

    let body_str = String::from_utf8_lossy(body);
    if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&body_str) {
        if let Some(usage) = json_body.get("usage") {
            if let Some(token_usage) = parse_usage(usage) {
                if token_usage.total_tokens() > 0 {
                    let provider_usage = token_usage.as_provider_usage();
                    let attr = calculate_attribution(&provider_usage, tool_tokens_est, memory_tokens_est);

                    info!(
                        tenant_id = %tenant_id,
                        prompt = attr.prompt_tokens, tool = attr.tool_tokens,
                        memory = attr.memory_tokens, response = attr.response_tokens,
                        cached_read = token_usage.cached_read_tokens,
                        cache_write = token_usage.cache_write_tokens,
                        "4-Layer Token Attribution"
                    );

                    let model = json_body.get("model").and_then(|m| m.as_str()).unwrap_or("gpt-4o");
                    let total_tokens = token_usage.total_tokens();
                    state.metrics.total_tokens_used.fetch_add(total_tokens as u64, Ordering::Relaxed);

                    // Track per-agent usage (cache-aware cost)
                    let cost_micro = crate::tokens::calculate_cost_detailed(model, &token_usage);
                    state.agent_registry.record(tenant_id, agent_id, total_tokens, cost_micro);
                    state.trace_store.enrich_usage(trace_id, total_tokens, cost_micro, None).await;

                    // Billing, quotas, shared cross-instance counters and the usage log
                    // are cloud concerns — routed through the ProxyEnv hook so the OSS
                    // build needs no cost_tracker / quota_manager / redis / db.
                    state.record_usage(UsageEvent {
                        tenant_id: tenant_id.to_string(),
                        api_key_id,
                        model: model.to_string(),
                        usage: token_usage.clone(),
                        cost_micro,
                        total_tokens,
                        prompt_tokens: provider_usage.prompt_tokens,
                        completion_tokens: provider_usage.completion_tokens,
                        protocol: protocol.to_string(),
                        path: path.to_string(),
                    }).await;
                }
            }
        }
    }
}

/// Process streaming (SSE) response body via channel
#[allow(clippy::too_many_arguments)]
async fn process_response_body_streaming<E: ProxyEnv>(
    mut rx: mpsc::UnboundedReceiver<StreamMessage>,
    state: Arc<E>,
    tenant_id: String,
    agent_id: String,
    api_key_id: Option<uuid::Uuid>,
    request_hash: Option<String>,
    content_type: String,
    path: String,
    protocol: String,
    tool_tokens_est: u32,
    memory_tokens_est: u32,
    trace_id: String,
) {
    let mut full_body = Vec::new();
    let mut stream_success = false;

    while let Some(msg) = rx.recv().await {
        match msg {
            StreamMessage::Chunk(chunk) => full_body.extend_from_slice(&chunk),
            StreamMessage::Done => { stream_success = true; break; }
            StreamMessage::Error => break,
        }
    }

    if !stream_success { return; }

    // Capture a response fingerprint for deterministic replay diffing.
    let response_hash = blake3::hash(&full_body).to_hex().to_string();
    state.trace_store.enrich_usage(&trace_id, 0, 0, Some(response_hash)).await;

    if let Some(hash) = request_hash {
        let cached_res = CachedResponse::new(Bytes::from(full_body.clone()), content_type.clone());
        state.cache_manager.insert(&hash, cached_res).await;
    }

    let body_str = String::from_utf8_lossy(&full_body);
    let mut usage_value = None;

    if content_type.contains("text/event-stream") {
        for line in body_str.lines() {
            if line.starts_with("data: ") && line != "data: [DONE]" {
                if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&line[6..]) {
                    if let Some(usage) = json_body.get("usage") {
                        if !usage.is_null() { usage_value = Some(usage.clone()); break; }
                    }
                }
            }
        }
    } else if let Ok(json_body) = serde_json::from_str::<serde_json::Value>(&body_str) {
        usage_value = json_body.get("usage").cloned();
    }

    if let Some(usage) = usage_value {
        if let Some(token_usage) = parse_usage(&usage) {
            if token_usage.total_tokens() > 0 {
                let provider_usage = token_usage.as_provider_usage();
                let attr = calculate_attribution(&provider_usage, tool_tokens_est, memory_tokens_est);

                info!(
                    tenant_id = %tenant_id,
                    prompt = attr.prompt_tokens,
                    tool = attr.tool_tokens,
                    memory = attr.memory_tokens,
                    response = attr.response_tokens,
                    cached_read = token_usage.cached_read_tokens,
                    cache_write = token_usage.cache_write_tokens,
                    "4-Layer Token Attribution"
                );

                // Extract model name from response body
                let model = if content_type.contains("text/event-stream") {
                    body_str.lines()
                        .find(|l| l.starts_with("data: ") && *l != "data: [DONE]")
                        .and_then(|l| serde_json::from_str::<serde_json::Value>(&l[6..]).ok())
                        .and_then(|j| j.get("model").and_then(|m| m.as_str().map(String::from)))
                        .unwrap_or_else(|| "gpt-4o".to_string())
                } else {
                    serde_json::from_str::<serde_json::Value>(&body_str)
                        .ok()
                        .and_then(|j| j.get("model").and_then(|m| m.as_str().map(String::from)))
                        .unwrap_or_else(|| "gpt-4o".to_string())
                };

                let total_tokens = token_usage.total_tokens();
                state.metrics.total_tokens_used.fetch_add(total_tokens as u64, Ordering::Relaxed);

                // Track per-agent usage (cache-aware cost)
                let cost_micro = crate::tokens::calculate_cost_detailed(&model, &token_usage);
                state.agent_registry.record(&tenant_id, &agent_id, total_tokens, cost_micro);
                state.trace_store.enrich_usage(&trace_id, total_tokens, cost_micro, None).await;

                // Cloud accounting via the ProxyEnv hook (no-op in the OSS build).
                state.record_usage(UsageEvent {
                    tenant_id: tenant_id.clone(),
                    api_key_id,
                    model: model.clone(),
                    usage: token_usage.clone(),
                    cost_micro,
                    total_tokens,
                    prompt_tokens: provider_usage.prompt_tokens,
                    completion_tokens: provider_usage.completion_tokens,
                    protocol: protocol.clone(),
                    path: path.clone(),
                }).await;
            }
        }
    }
}

fn extract_provider_name(url: &str) -> String {
    if url.contains("groq.com") { "groq".into() }
    else if url.contains("openrouter.ai") { "openrouter".into() }
    else if url.contains("openai.com") { "openai".into() }
    else if url.contains("anthropic.com") { "anthropic".into() }
    else if url.contains("together.xyz") { "together".into() }
    else { url.split('/').nth(2).unwrap_or("unknown").to_string() }
}

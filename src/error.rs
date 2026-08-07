use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug)]
pub enum AppError {
    ProxyError(reqwest::Error),
    Internal(String),
    Unauthorized(String),
    RateLimited(String),
    LoopDetected(String),
    PolicyBlocked(String),
    InjectionBlocked(String),
    PayloadTooLarge,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            AppError::ProxyError(e) => (
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                format!("Failed to reach upstream provider: {}", e),
            ),
            AppError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", e),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg),
            AppError::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", msg),
            AppError::LoopDetected(msg) => {
                (StatusCode::TOO_MANY_REQUESTS, "agent_loop_detected", msg)
            }
            AppError::PolicyBlocked(msg) => (StatusCode::FORBIDDEN, "policy_blocked", msg),
            AppError::InjectionBlocked(msg) => {
                (StatusCode::FORBIDDEN, "prompt_injection_blocked", msg)
            }
            AppError::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "Request body exceeds maximum allowed size".to_string(),
            ),
        };

        let body = Json(json!({
            "error": {
                "code": code,
                "message": message,
                "type": "proxy_error",
            }
        }));

        (status, body).into_response()
    }
}

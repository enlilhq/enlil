use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use crate::usage::ProxyEnv;

pub async fn payload_size_middleware<E: ProxyEnv>(
    State(state): State<Arc<E>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(content_length) = req.headers().get("content-length") {
        if let Ok(len) = content_length.to_str().unwrap_or("0").parse::<usize>() {
            if len > state.config.max_payload_bytes {
                tracing::warn!(len, max = state.config.max_payload_bytes, "Payload too large");
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
        }
    }
    Ok(next.run(req).await)
}

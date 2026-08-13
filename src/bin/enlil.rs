//! `enlil` — the open-source agent control plane.
//!
//! Zero configuration required. Point your OpenAI-compatible client's `base_url`
//! at this process and every agent action is recorded, governed, and queryable:
//!
//! ```text
//! $ enlil
//! $ curl localhost:8080/api/traces
//! ```
//!
//! This binary links only the OSS core — no Postgres, Redis, DynamoDB,
//! multi-tenant auth, or billing. See `src/oss.rs`.

use enlil::config::ProxyConfig;
use enlil::server::build_oss_app;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Local trace/audit storage lives here. Overridable with DATA_DIR.
    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string());
    std::fs::create_dir_all(&data_dir).ok();

    let config = ProxyConfig::from_env_oss();
    let addr = format!("0.0.0.0:{}", config.port);

    tracing::info!(
        upstream = %config.upstream_url,
        "enlil — source-available control and audit plane for AI agent actions"
    );

    let app = build_oss_app(config).await;
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    tracing::info!("listening on http://{addr}  —  traces at /api/traces");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    tracing::info!("shutdown complete");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl+C, shutting down..."),
        _ = terminate => tracing::info!("received SIGTERM, shutting down..."),
    }
}

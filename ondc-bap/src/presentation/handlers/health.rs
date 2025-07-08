//! Health check handlers for ONDC BAP Server

use axum::{
    response::Json,
    http::StatusCode,
};
use serde::Serialize;
use tracing::info;

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
    pub uptime_seconds: u64,
}

/// Basic health check endpoint
pub async fn health_check() -> Json<HealthResponse> {
    info!("Health check requested");
    
    Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // TODO: Implement uptime tracking
    })
}

/// Readiness probe endpoint
pub async fn readiness_check() -> StatusCode {
    // TODO: Implement readiness checks (database, external services, etc.)
    StatusCode::OK
}

/// Liveness probe endpoint
pub async fn liveness_check() -> StatusCode {
    // TODO: Implement liveness checks
    StatusCode::OK
} 
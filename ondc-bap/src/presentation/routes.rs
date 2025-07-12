//! Route definitions for ONDC BAP Server

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use super::handlers::{
    admin_register, handle_on_subscribe, health_check, serve_site_verification, subscribe_to_registry, AppState,
};
use super::middleware::{
    cors_middleware, error_handling_middleware, logging_middleware, rate_limiting_middleware,
    security_headers_middleware,
};
use crate::{config::BAPConfig, services::RegistryClient};
use crate::services::KeyManagementService;

/// Create the main application router
pub fn create_router(config: Arc<BAPConfig>, key_manager: Arc<KeyManagementService>, registry_client: Arc<RegistryClient>) -> Router {
    // Create application state
    let app_state = AppState::new(config, key_manager, registry_client);

    // Create router with middleware stack
    Router::new()
        // Health and monitoring routes
        .route("/health", get(health_check))
        .route("/ready", get(super::handlers::health::readiness_check))
        .route("/live", get(super::handlers::health::liveness_check))
        .route("/metrics", get(metrics_handler))
        
        // ONDC protocol routes
        .route("/ondc-site-verification.html", get(serve_site_verification))
        .route("/on_subscribe", post(handle_on_subscribe))
        .route("/participant/info", get(super::handlers::ondc::get_participant_info))
        
        // Administrative routes
        .nest("/admin", admin_routes())
        
        // Apply middleware stack
        .layer(middleware::from_fn(logging_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(middleware::from_fn(error_handling_middleware))
        .layer(middleware::from_fn(rate_limiting_middleware))
        .layer(cors_middleware())
        .layer(TraceLayer::new_for_http())
        
        // Add application state
        .with_state(app_state)
}

/// Administrative routes
fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(admin_register))
        .route("/subscribe", post(subscribe_to_registry))
        .route("/config", post(super::handlers::admin::update_config))
        .route("/keys/rotate", post(super::handlers::admin::rotate_keys))
}

/// Metrics endpoint (Prometheus format)
async fn metrics_handler() -> String {
    // TODO: Implement actual metrics collection
    // For now, return basic Prometheus metrics

    r#"# HELP ondc_bap_requests_total Total number of requests
# TYPE ondc_bap_requests_total counter
ondc_bap_requests_total{endpoint="/health"} 0
ondc_bap_requests_total{endpoint="/ondc-site-verification.html"} 0
ondc_bap_requests_total{endpoint="/on_subscribe"} 0

# HELP ondc_bap_request_duration_seconds Request duration in seconds
# TYPE ondc_bap_request_duration_seconds histogram
ondc_bap_request_duration_seconds_bucket{le="0.1"} 0
ondc_bap_request_duration_seconds_bucket{le="0.5"} 0
ondc_bap_request_duration_seconds_bucket{le="1.0"} 0
ondc_bap_request_duration_seconds_bucket{le="+Inf"} 0

# HELP ondc_bap_up Server uptime status
# TYPE ondc_bap_up gauge
ondc_bap_up 1
"#
    .to_string()
}

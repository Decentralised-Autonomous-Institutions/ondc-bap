//! Logging middleware for ONDC BAP Server

use axum::{extract::Request, middleware::Next, response::Response};
use std::time::Instant;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Logging middleware for request/response logging
pub async fn logging_middleware(request: Request, next: Next) -> Response {
    let start = Instant::now();
    let request_id = Uuid::new_v4();

    // Log request details
    info!(
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri(),
        "Incoming request"
    );

    // Process request
    let response = next.run(request).await;

    // Calculate duration
    let duration = start.elapsed();

    // Log response details
    let status = response.status();
    let status_code = status.as_u16();

    match status_code {
        200..=299 => {
            info!(
                request_id = %request_id,
                status = %status_code,
                duration_ms = duration.as_millis(),
                "Request completed successfully"
            );
        }
        300..=399 => {
            debug!(
                request_id = %request_id,
                status = %status_code,
                duration_ms = duration.as_millis(),
                "Request redirected"
            );
        }
        400..=499 => {
            warn!(
                request_id = %request_id,
                status = %status_code,
                duration_ms = duration.as_millis(),
                "Client error"
            );
        }
        500..=599 => {
            error!(
                request_id = %request_id,
                status = %status_code,
                duration_ms = duration.as_millis(),
                "Server error"
            );
        }
        _ => {
            debug!(
                request_id = %request_id,
                status = %status_code,
                duration_ms = duration.as_millis(),
                "Request completed"
            );
        }
    }

    response
}

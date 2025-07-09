//! Error handling middleware for ONDC BAP Server

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{Json, Response},
};
use serde::Serialize;
use tracing::error;

/// Error response structure
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub status_code: u16,
}

/// Error handling middleware
pub async fn error_handling_middleware(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    // If the response is already an error, return it as is
    if response.status().is_client_error() || response.status().is_server_error() {
        return response;
    }

    response
}

/// Convert internal errors to HTTP responses
pub fn handle_error(
    err: Box<dyn std::error::Error + Send + Sync>,
) -> (StatusCode, Json<ErrorResponse>) {
    error!("Unhandled error: {}", err);

    let (status_code, message) = match err.downcast_ref::<crate::error::AppError>() {
        Some(app_error) => match app_error {
            crate::error::AppError::Config(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error")
            }
            crate::error::AppError::Crypto(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Cryptographic error")
            }
            crate::error::AppError::Validation(_) => (StatusCode::BAD_REQUEST, "Validation error"),
            crate::error::AppError::Registry(_) => (StatusCode::BAD_GATEWAY, "Registry error"),
            crate::error::AppError::Http(_) => (StatusCode::BAD_GATEWAY, "HTTP error"),
            crate::error::AppError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
            }
        },
        None => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
    };

    (
        status_code,
        Json(ErrorResponse {
            error: "server_error".to_string(),
            message: message.to_string(),
            status_code: status_code.as_u16(),
        }),
    )
}

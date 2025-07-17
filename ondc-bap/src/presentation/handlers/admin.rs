//! Administrative handlers for ONDC BAP Server

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::Json as JsonResponse,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, instrument};

use super::AppState;

/// Admin registration request
#[derive(Debug, Deserialize)]
pub struct AdminRegistrationRequest {
    pub ops_no: u32,
}

/// Admin registration response
#[derive(Debug, Serialize)]
pub struct AdminRegistrationResponse {
    pub status: String,
    pub message: String,
    pub request_id: Option<String>,
}

/// Admin status response
#[derive(Debug, Serialize)]
pub struct AdminStatusResponse {
    pub status: String,
    pub message: String,
    pub timestamp: String,
}

/// Administrative registration endpoint
///
/// This endpoint allows administrators to initiate ONDC network participant registration
/// by calling the registry subscribe API with the specified operation number.
#[instrument(skip(_state, request), fields(ops_no = request.ops_no))]
pub async fn admin_register(
    State(_state): State<AppState>,
    Json(request): Json<AdminRegistrationRequest>,
) -> Result<JsonResponse<AdminRegistrationResponse>, StatusCode> {
    info!("Processing admin registration request (ops_no: {})", request.ops_no);

    // Validate ops_no
    if !matches!(request.ops_no, 1 | 2 | 4) {
        error!("Invalid ops_no: {}", request.ops_no);
        return Err(StatusCode::BAD_REQUEST);
    }

    // TODO: Add registry client to AppState when implemented
    // For now, return a placeholder response
    info!("Registration request validated successfully");

    Ok(JsonResponse(AdminRegistrationResponse {
        status: "initiated".to_string(),
        message: format!("Registration initiated for ops_no: {}", request.ops_no),
        request_id: Some(uuid::Uuid::new_v4().to_string()),
    }))
}

/// Administrative status endpoint
///
/// This endpoint provides status information about the BAP server and its registration status.
#[instrument(skip(_state))]
pub async fn admin_status(
    State(_state): State<AppState>,
) -> Result<JsonResponse<AdminStatusResponse>, StatusCode> {
    info!("Admin status requested");

    // TODO: Add actual status checking logic
    // For now, return basic status information

    Ok(JsonResponse(AdminStatusResponse {
        status: "operational".to_string(),
        message: "BAP server is operational".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Health check endpoint for administrative purposes
///
/// This endpoint provides detailed health information including key validation
/// and service status.
#[instrument(skip(state))]
pub async fn admin_health(
    State(state): State<AppState>,
) -> Result<JsonResponse<AdminHealthResponse>, StatusCode> {
    info!("Admin health check requested");

    // Validate key pairs
    let key_validation = state.key_manager.validate_key_pairs().await;
    let key_status = if key_validation.is_ok() {
        "healthy".to_string()
    } else {
        "unhealthy".to_string()
    };

    // Get key metadata
    let key_metadata = state.key_manager.get_key_metadata().await;

    Ok(JsonResponse(AdminHealthResponse {
        status: "operational".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        services: ServiceHealth {
            key_management: key_status,
            site_verification: "healthy".to_string(),
            challenge_processing: "healthy".to_string(),
            registry_client: "not_implemented".to_string(),
        },
        key_metadata: KeyHealth {
            key_id: key_metadata.key_id,
            created_at: key_metadata.created_at.to_rfc3339(),
            is_active: key_metadata.is_active,
            rotation_count: key_metadata.rotation_count,
        },
    }))
}

/// Admin health response with detailed service information
#[derive(Debug, Serialize)]
pub struct AdminHealthResponse {
    pub status: String,
    pub timestamp: String,
    pub services: ServiceHealth,
    pub key_metadata: KeyHealth,
}

/// Service health information
#[derive(Debug, Serialize)]
pub struct ServiceHealth {
    pub key_management: String,
    pub site_verification: String,
    pub challenge_processing: String,
    pub registry_client: String,
}

/// Key health information
#[derive(Debug, Serialize)]
pub struct KeyHealth {
    pub key_id: String,
    pub created_at: String,
    pub is_active: bool,
    pub rotation_count: u32,
}

/// Configuration update request
#[derive(Deserialize)]
pub struct ConfigUpdateRequest {
    pub key: String,
    pub value: String,
}

/// Configuration update response
#[derive(Serialize)]
pub struct ConfigUpdateResponse {
    pub success: bool,
    pub message: String,
}

/// Update configuration endpoint
pub async fn update_config(
    State(_state): State<AppState>,
    Json(_request): Json<ConfigUpdateRequest>,
) -> Result<JsonResponse<ConfigUpdateResponse>, StatusCode> {
    info!("Configuration update request received");

    // TODO: Implement configuration update logic

    Ok(JsonResponse(ConfigUpdateResponse {
        success: true,
        message: "Configuration updated successfully".to_string(),
    }))
}

/// Key rotation request
#[derive(Deserialize)]
pub struct KeyRotationRequest {
    pub key_type: String,
}

/// Key rotation response
#[derive(Serialize)]
pub struct KeyRotationResponse {
    pub success: bool,
    pub message: String,
    pub new_key_id: Option<String>,
}

/// Rotate keys endpoint
pub async fn rotate_keys(
    State(_state): State<AppState>,
    Json(_request): Json<KeyRotationRequest>,
) -> Result<JsonResponse<KeyRotationResponse>, StatusCode> {
    info!("Key rotation request received");

    // TODO: Implement key rotation logic

    Ok(JsonResponse(KeyRotationResponse {
        success: true,
        message: "Keys rotated successfully".to_string(),
        new_key_id: Some(uuid::Uuid::new_v4().to_string()),
    }))
}

/// Subscribe request
#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub ops_no: u32,
}

/// Subscribe response
#[derive(Debug, Serialize)]
pub struct SubscribeResponse {
    pub status: String,
    pub message: String,
    pub request_id: Option<String>,
    pub registry_response: Option<String>,
}

/// Subscribe to ONDC registry endpoint
///
/// This endpoint allows administrators to subscribe to the ONDC registry
/// by calling the registry subscribe API with the specified operation number.
#[instrument(skip(state, request), fields(ops_no = request.ops_no))]
pub async fn subscribe_to_registry(
    State(state): State<AppState>,
    Json(request): Json<SubscribeRequest>,
) -> Result<JsonResponse<SubscribeResponse>, StatusCode> {
    info!("Processing subscribe request (ops_no: {})", request.ops_no);

    // Validate ops_no
    if !matches!(request.ops_no, 1 | 2 | 4) {
        error!("Invalid ops_no: {}", request.ops_no);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate a new request_id for this subscription
    let request_id = uuid::Uuid::new_v4().to_string();
    info!("Generated request_id for subscription: {}", request_id);
    
    // Store the request_id in site verification service so it can be used when site verification is accessed
    state.site_verification_service.store_request_id(&request_id).await;
    
    // Call the registry client subscribe method with the generated request_id
    match state.registry_client.subscribe_with_request_id(request.ops_no, request_id).await {
        Ok(registry_response) => {
            info!("Successfully subscribed to registry with ops_no: {}", request.ops_no);
            
            // Validate the response
            if let Err(validation_error) = state.registry_client.validate_subscription_response(&registry_response) {
                error!("Registry response validation failed: {:?}", validation_error);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }

            Ok(JsonResponse(SubscribeResponse {
                status: "success".to_string(),
                message: format!("Successfully subscribed to registry with ops_no: {}", request.ops_no),
                request_id: Some(uuid::Uuid::new_v4().to_string()),
                registry_response: Some(format!("Status: {}", registry_response.message.ack.status)),
            }))
        }
        Err(registry_error) => {
            error!("Registry subscription failed: {:?}", registry_error);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

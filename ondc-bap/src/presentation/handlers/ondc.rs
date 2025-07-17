//! ONDC protocol handlers for ONDC BAP Server

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::{Html, Json as JsonResponse},
};
use tracing::{error, info, instrument, warn};

use super::AppState;
use crate::services::{OnSubscribeRequest, OnSubscribeResponse};
use ondc_crypto_formats::decode_signature;

/// Site verification endpoint
#[instrument(skip(state))]
pub async fn serve_site_verification(
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    info!("Site verification page requested");

    // Get the stored request_id from the subscription call
    let stored_request_id = state.site_verification_service.get_current_request_id().await;
    
    match stored_request_id {
        Some(request_id) => {
            info!("Using stored request_id for site verification: {}", request_id);
            // Generate site verification with the stored request_id
            match state
                .site_verification_service
                .generate_site_verification_with_request_id(Some(&request_id))
                .await
            {
                Ok(html_content) => {
                    info!("Site verification page generated successfully with stored request_id");
                    Ok(Html(html_content))
                }
                Err(e) => {
                    error!("Failed to generate site verification: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        None => {
            warn!("No stored request_id found, generating new one");
            // Fallback to generating a new request_id
            match state
                .site_verification_service
                .generate_site_verification()
                .await
            {
                Ok(html_content) => {
                    info!("Site verification page generated successfully");
                    Ok(Html(html_content))
                }
                Err(e) => {
                    error!("Failed to generate site verification: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
    }
}

/// Handle on-subscribe challenge from ONDC registry
#[instrument(skip(state, request), fields(subscriber_id = %request.subscriber_id))]
pub async fn handle_on_subscribe(
    State(state): State<AppState>,
    Json(request): Json<OnSubscribeRequest>,
) -> Result<JsonResponse<OnSubscribeResponse>, StatusCode> {
    info!("On-subscribe challenge received");

    // Validate request
    if let Err(e) = validate_on_subscribe_request(&request) {
        error!("Invalid on_subscribe request: {}", e);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Process challenge
    match state.challenge_service.process_challenge(request).await {
        Ok(response) => {
            info!("Challenge processed successfully");
            Ok(JsonResponse(response))
        }
        Err(e) => {
            error!("Failed to process challenge: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Participant information response
#[derive(serde::Serialize)]
pub struct ParticipantInfo {
    pub subscriber_id: String,
    pub signing_public_key: String,
    pub encryption_public_key: String,
    pub unique_key_id: String,
    pub status: String,
}

/// Get participant information endpoint
pub async fn get_participant_info(
    State(_state): State<AppState>,
) -> Result<JsonResponse<ParticipantInfo>, StatusCode> {
    info!("Participant info requested");

    // TODO: Implement actual participant info retrieval
    // For now, return placeholder data

    Ok(JsonResponse(ParticipantInfo {
        subscriber_id: "placeholder.example.com".to_string(),
        signing_public_key: "placeholder_signing_public_key".to_string(),
        encryption_public_key: "placeholder_encryption_public_key".to_string(),
        unique_key_id: "placeholder_key_id".to_string(),
        status: "placeholder_status".to_string(),
    }))
}

/// Validate on_subscribe request
fn validate_on_subscribe_request(request: &OnSubscribeRequest) -> Result<(), String> {
    if request.subscriber_id.is_empty() {
        return Err("Subscriber ID cannot be empty".to_string());
    }

    if request.challenge.is_empty() {
        return Err("Challenge cannot be empty".to_string());
    }

    // Validate base64 format
    if let Err(_) = decode_signature(&request.challenge) {
        return Err("Challenge must be valid base64".to_string());
    }

    Ok(())
}

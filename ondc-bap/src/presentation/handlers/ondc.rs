//! ONDC protocol handlers for ONDC BAP Server

use axum::{
    extract::{State, Json},
    response::{Html, Json as JsonResponse},
    http::StatusCode,
};
use serde::{Serialize, Deserialize};
use tracing::info;

use super::AppState;

/// On-subscribe request from ONDC registry
#[derive(Deserialize)]
pub struct OnSubscribeRequest {
    pub subscriber_id: String,
    pub challenge: String,
}

/// On-subscribe response to ONDC registry
#[derive(Serialize)]
pub struct OnSubscribeResponse {
    pub answer: String,
}

/// Site verification endpoint
pub async fn serve_site_verification(
    State(_state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    info!("Site verification page requested");
    
    // TODO: Implement actual site verification logic
    // For now, return a placeholder HTML page
    
    let html_content = r#"<!--Contents of ondc-site-verification.html. -->
<!--Please replace SIGNED_UNIQUE_REQ_ID with an actual value-->
<html>
  <head>
    <meta
      name="ondc-site-verification"
      content="PLACEHOLDER_SIGNED_UNIQUE_REQ_ID"
    />
  </head>
  <body>
    ONDC Site Verification Page
  </body>
</html>"#;
    
    Ok(Html(html_content.to_string()))
}

/// Handle on-subscribe challenge from ONDC registry
pub async fn handle_on_subscribe(
    State(_state): State<AppState>,
    Json(_request): Json<OnSubscribeRequest>,
) -> Result<JsonResponse<OnSubscribeResponse>, StatusCode> {
    info!("On-subscribe challenge received");
    
    // TODO: Implement actual challenge processing logic
    // - Generate X25519 shared secret
    // - Decrypt challenge using AES-256-ECB
    // - Return decrypted answer
    
    Ok(JsonResponse(OnSubscribeResponse {
        answer: "placeholder_challenge_response".to_string(),
    }))
}

/// Participant information response
#[derive(Serialize)]
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
        status: "active".to_string(),
    }))
} 
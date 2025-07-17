//! Registry Client Service for ONDC BAP Server
//!
//! This service provides HTTP client capabilities for interacting with the ONDC registry APIs.
//! It handles subscription requests, participant lookups, and implements proper error handling
//! with retry logic and rate limiting compliance.

use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, instrument};

use crate::config::{ONDCConfig, ondc_config::ParticipantType};
use crate::services::KeyManagementService;

/// Registry client error types
#[derive(Debug, thiserror::Error)]
pub enum RegistryClientError {
    #[error("HTTP client creation failed: {0}")]
    ClientCreationFailed(String),

    #[error("HTTP request failed: {0}")]
    RequestFailed(String),

    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Subscription failed: {0}")]
    SubscriptionFailed(String),

    #[error("Lookup failed: {0}")]
    LookupFailed(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Key management error: {0}")]
    KeyManagerError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

/// ONDC subscribe request payload
#[derive(Debug, Serialize)]
pub struct SubscribeRequest {
    pub context: SubscribeContext,
    pub message: SubscribeMessage,
}

/// Subscribe context with operation details
#[derive(Debug, Serialize)]
pub struct SubscribeContext {
    pub operation: SubscribeOperation,
}

/// Subscribe operation details
#[derive(Debug, Serialize)]
pub struct SubscribeOperation {
    pub ops_no: u32,
}

/// Subscribe message containing entity and participant information
#[derive(Debug, Serialize)]
pub struct SubscribeMessage {
    pub request_id: String,
    pub timestamp: String,
    pub entity: SubscribeEntity,
    pub network_participant: Vec<NetworkParticipant>,
}

/// Subscribe entity with business and key information
#[derive(Debug, Serialize)]
pub struct SubscribeEntity {
    pub gst: GstInfo,
    pub pan: PanInfo,
    pub name_of_authorised_signatory: String,
    pub address_of_authorised_signatory: String,
    pub email_id: String,
    pub mobile_no: u64,
    pub country: String,
    pub subscriber_id: String,
    pub unique_key_id: String,
    pub callback_url: String,
    pub key_pair: KeyPairInfo,
}

/// GST information
#[derive(Debug, Serialize)]
pub struct GstInfo {
    pub legal_entity_name: String,
    pub business_address: String,
    pub city_code: Vec<String>,
    pub gst_no: Option<String>,
}

/// PAN information
#[derive(Debug, Serialize)]
pub struct PanInfo {
    pub name_as_per_pan: String,
    pub pan_no: String,
    pub date_of_incorporation: String,
}

/// Key pair information
#[derive(Debug, Serialize)]
pub struct KeyPairInfo {
    pub signing_public_key: String,
    pub encryption_public_key: String,
    pub valid_from: String,
    pub valid_until: String,
}

/// Network participant information
#[derive(Debug, Serialize)]
pub struct NetworkParticipant {
    pub subscriber_url: String,
    pub domain: String,
    #[serde(rename = "type")]
    pub participant_type: ParticipantType,
    pub msn: bool,
    pub city_code: Vec<String>,
}

/// ONDC subscribe response
#[derive(Debug, Deserialize)]
pub struct SubscribeResponse {
    pub message: SubscribeResponseMessage,
    pub error: SubscribeResponseError,
}

/// Subscribe response message
#[derive(Debug, Deserialize)]
pub struct SubscribeResponseMessage {
    pub ack: SubscribeAck,
}

/// Subscribe acknowledgment
#[derive(Debug, Deserialize)]
pub struct SubscribeAck {
    pub status: String,
}

/// Subscribe response error
#[derive(Debug, Deserialize)]
pub struct SubscribeResponseError {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub code: Option<String>,
    pub path: Option<String>,
    pub message: Option<String>,
}

/// Registry client for ONDC API interactions
pub struct RegistryClient {
    client: Client,
    base_url: String,
    key_manager: Arc<KeyManagementService>,
    config: ONDCConfig,
}

impl RegistryClient {
    /// Create a new registry client
    pub fn new(
        key_manager: Arc<KeyManagementService>,
        config: ONDCConfig,
    ) -> Result<Self, RegistryClientError> {
        info!("Initializing registry client for {}", config.registry_base_url);

        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .build()
            .map_err(|e| RegistryClientError::ClientCreationFailed(e.to_string()))?;

        Ok(Self {
            client,
            base_url: config.registry_base_url.clone(),
            key_manager,
            config,
        })
    }

    /// Subscribe to ONDC registry
    ///
    /// This method sends a subscription request to the ONDC registry with the provided
    /// operation number and generates all required fields from configuration.
    #[instrument(skip(self), fields(subscriber_id = %self.config.subscriber_id, ops_no = ops_no))]
    pub async fn subscribe(
        &self,
        ops_no: u32,
    ) -> Result<SubscribeResponse, RegistryClientError> {
        info!("Sending subscription request to registry (ops_no: {})", ops_no);

        // Generate request ID
        let request_id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string();
        
        // Set key validity period - valid for 1 week from now
        let now = Utc::now();
        // Format timestamps to match ONDC expected format (Z instead of +00:00, millisecond precision)
        let valid_from = now.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string();
        let valid_until = (now + chrono::Duration::weeks(1)).format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string();
        

        // Get public keys from key manager
        let signing_public_key = self.key_manager.get_signing_public_key().await
            .map_err(|e| RegistryClientError::KeyManagerError(e.to_string()))?;
        let encryption_public_key = self.key_manager.get_encryption_public_key().await
            .map_err(|e| RegistryClientError::KeyManagerError(e.to_string()))?;
        let unique_key_id = self.key_manager.get_unique_key_id().await;

        // Build the subscription request
        let request = SubscribeRequest {
            context: SubscribeContext {
                operation: SubscribeOperation { ops_no },
            },
            message: SubscribeMessage {
                request_id: request_id.clone(),
                timestamp: timestamp.clone(),
                entity: SubscribeEntity {
                    gst: GstInfo {
                        legal_entity_name: self.config.business_entity.gst.legal_entity_name.clone(),
                        business_address: self.config.business_entity.gst.business_address.clone(),
                        city_code: self.config.business_entity.gst.city_code.clone(),
                        gst_no: self.config.business_entity.gst.gst_no.clone(),
                    },
                    pan: PanInfo {
                        name_as_per_pan: self.config.business_entity.pan.name_as_per_pan.clone(),
                        pan_no: self.config.business_entity.pan.pan_no.clone(),
                        date_of_incorporation: self.config.business_entity.pan.date_of_incorporation.clone(),
                    },
                    name_of_authorised_signatory: self.config.business_entity.name_of_authorised_signatory.clone(),
                    address_of_authorised_signatory: self.config.business_entity.address_of_authorised_signatory.clone(),
                    email_id: self.config.business_entity.email_id.clone(),
                    mobile_no: self.config.business_entity.mobile_no,
                    country: self.config.business_entity.country.clone(),
                    subscriber_id: self.config.subscriber_id.clone(),
                    unique_key_id: unique_key_id.clone(),
                    callback_url: self.config.callback_url.clone(),
                    key_pair: KeyPairInfo {
                        signing_public_key,
                        encryption_public_key,
                        valid_from,
                        valid_until,
                    },
                },
                network_participant: vec![
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "nic2004:60232".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET10".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET11".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET12".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET13".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET14".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET15".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET16".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET18".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET1A".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET1B".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET1C".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:RET1D".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:AGR10".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:AGR11".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:SRV10".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:SRV11".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                    NetworkParticipant {
                        subscriber_url: "/".to_string(),
                        domain: "ONDC:SRV12".to_string(),
                        participant_type: ParticipantType::BuyerApp,
                        msn: false,
                        city_code: vec!["std:080".to_string()],
                    },
                ],
            },
        };

        // Send the request
        let url = format!("{}/subscribe", self.base_url);

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| RegistryClientError::RequestFailed(e.to_string()))?;

        info!("Registry response status: {}", response.status());

        if response.status().is_success() {
            let subscription_response: SubscribeResponse = response
                .json()
                .await
                .map_err(|e| RegistryClientError::DeserializationFailed(e.to_string()))?;

            info!("Subscription request successful for request_id: {}", request_id);
            Ok(subscription_response)
        } else if response.status() == 429 {
            warn!("Rate limit exceeded for subscription request");
            Err(RegistryClientError::RateLimitExceeded)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            error!("Subscription request failed: {}", error_text);
            Err(RegistryClientError::SubscriptionFailed(error_text))
        }
    }

    /// Subscribe with retry logic
    ///
    /// This method implements exponential backoff retry logic for subscription requests,
    /// specifically handling rate limiting (429) responses.
    #[instrument(skip(self), fields(subscriber_id = %self.config.subscriber_id, ops_no = ops_no))]
    pub async fn subscribe_with_retry(
        &self,
        ops_no: u32,
    ) -> Result<SubscribeResponse, RegistryClientError> {
        let mut attempts = 0;
        let max_attempts = self.config.max_retries;

        loop {
            match self.subscribe(ops_no).await {
                Ok(response) => return Ok(response),
                Err(RegistryClientError::RateLimitExceeded) if attempts < max_attempts => {
                    let delay = Duration::from_millis(1000 * 2_u64.pow(attempts as u32));
                    warn!("Rate limited, retrying in {:?} (attempt {}/{})", delay, attempts + 1, max_attempts);
                    tokio::time::sleep(delay).await;
                    attempts += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Validate subscription response
    ///
    /// This method validates that the subscription response indicates success.
    pub fn validate_subscription_response(
        &self,
        response: &SubscribeResponse,
    ) -> Result<(), RegistryClientError> {
        // Print response message
        if response.message.ack.status == "ACK" {
            if let (None, None, None, None) = (
                &response.error.error_type,
                &response.error.code,
                &response.error.path,
                &response.error.message,
            ) {
                Ok(())
            } else {
                Err(RegistryClientError::InvalidResponse(
                    "Subscription response contains error information".to_string(),
                ))
            }
        } else {
            error!("Subscription failed with error code: {:?}", response.error.code);
            error!("Subscription failed with error message: {:?}", response.error.message);
            Err(RegistryClientError::InvalidResponse(format!(
                "Subscription failed with status: {}",
                response.message.ack.status
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Environment;

    #[test]
    fn test_subscribe_request_serialization() {
        let request = SubscribeRequest {
            context: SubscribeContext {
                operation: SubscribeOperation { ops_no: 1 },
            },
            message: SubscribeMessage {
                request_id: "test-request-id".to_string(),
                timestamp: "2022-07-08T13:44:54.101Z".to_string(),
                entity: SubscribeEntity {
                    gst: GstInfo {
                        legal_entity_name: "Test Entity".to_string(),
                        business_address: "Test Address".to_string(),
                        city_code: vec!["std:080".to_string()],
                        gst_no: Some("00AAAAA0000A1Z5".to_string()),
                    },
                    pan: PanInfo {
                        name_as_per_pan: "Test Entity".to_string(),
                        pan_no: "AAAAA0000A".to_string(),
                        date_of_incorporation: "01/01/2020".to_string(),
                    },
                    name_of_authorised_signatory: "Test Signatory".to_string(),
                    address_of_authorised_signatory: "Test Address".to_string(),
                    email_id: "test@example.com".to_string(),
                    mobile_no: 9999999999,
                    country: "IND".to_string(),
                    subscriber_id: "test.example.com".to_string(),
                    unique_key_id: "test-key-1".to_string(),
                    callback_url: "/".to_string(),
                    key_pair: KeyPairInfo {
                        signing_public_key: "test-signing-key".to_string(),
                        encryption_public_key: "test-encryption-key".to_string(),
                        valid_from: "2022-07-08T13:44:54.101Z".to_string(),
                        valid_until: "2022-07-08T13:44:54.101Z".to_string(),
                    },
                },
                network_participant: vec![NetworkParticipant {
                    subscriber_url: "/bapl".to_string(),
                    domain: "nic2004:52110".to_string(),
                    participant_type: ParticipantType::BuyerApp,
                    msn: false,
                    city_code: vec!["std:080".to_string()],
                }],
            },
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-request-id"));
        assert!(json.contains("ops_no"));
        assert!(json.contains("buyerApp"));
    }
} 
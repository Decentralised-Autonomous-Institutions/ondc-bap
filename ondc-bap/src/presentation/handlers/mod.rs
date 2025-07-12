//! Request handlers for ONDC BAP Server

use std::sync::Arc;

use crate::config::BAPConfig;
use crate::services::{KeyManagementService, SiteVerificationService, ChallengeService, RegistryClient};

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<BAPConfig>,
    pub key_manager: Arc<KeyManagementService>,
    pub site_verification_service: Arc<SiteVerificationService>,
    pub challenge_service: Arc<ChallengeService>,
    pub registry_client: Arc<RegistryClient>,
    // TODO: Add other services as they are implemented
    // pub onboarding_service: Arc<OnboardingService>,
}

impl AppState {
    /// Create new application state
    pub fn new(
        config: Arc<BAPConfig>, 
        key_manager: Arc<KeyManagementService>,
        registry_client: Arc<RegistryClient>,
    ) -> Self {
        let site_verification_service = Arc::new(SiteVerificationService::new(
            key_manager.clone(),
            config.clone(),
        ));
        let challenge_service = Arc::new(ChallengeService::new(
            key_manager.clone(),
            config.clone(),
        ));

        Self {
            config,
            key_manager,
            site_verification_service,
            challenge_service,
            registry_client,
        }
    }
}

// Handler modules
pub mod admin;
pub mod health;
pub mod ondc;

// Re-export handler functions
pub use admin::{admin_register, admin_status, admin_health, subscribe_to_registry};
pub use health::health_check;
pub use ondc::{handle_on_subscribe, serve_site_verification};

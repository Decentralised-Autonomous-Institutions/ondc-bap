//! Request handlers for ONDC BAP Server

use std::sync::Arc;

use crate::config::BAPConfig;
use crate::services::{KeyManagementService, SiteVerificationService};

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<BAPConfig>,
    pub key_manager: Arc<KeyManagementService>,
    pub site_verification_service: Arc<SiteVerificationService>,
    // TODO: Add other services as they are implemented
    // pub onboarding_service: Arc<OnboardingService>,
    // pub registry_client: Arc<RegistryClient>,
    // pub challenge_service: Arc<ChallengeService>,
}

impl AppState {
    /// Create new application state
    pub fn new(config: Arc<BAPConfig>, key_manager: Arc<KeyManagementService>) -> Self {
        let site_verification_service = Arc::new(SiteVerificationService::new(
            key_manager.clone(),
            config.clone(),
        ));

        Self {
            config,
            key_manager,
            site_verification_service,
        }
    }
}

// Handler modules
pub mod admin;
pub mod health;
pub mod ondc;

// Re-export handler functions
pub use admin::admin_register;
pub use health::health_check;
pub use ondc::{handle_on_subscribe, serve_site_verification};

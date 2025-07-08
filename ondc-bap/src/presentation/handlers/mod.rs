//! Request handlers for ONDC BAP Server

use std::sync::Arc;

use crate::config::BAPConfig;
use crate::services::KeyManagementService;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<BAPConfig>,
    pub key_manager: Arc<KeyManagementService>,
    // TODO: Add other services as they are implemented
    // pub onboarding_service: Arc<OnboardingService>,
    // pub registry_client: Arc<RegistryClient>,
    // pub challenge_service: Arc<ChallengeService>,
}

impl AppState {
    /// Create new application state
    pub fn new(
        config: Arc<BAPConfig>,
        key_manager: Arc<KeyManagementService>,
    ) -> Self {
        Self {
            config,
            key_manager,
        }
    }
}

// Handler modules
pub mod health;
pub mod admin;
pub mod ondc;

// Re-export handler functions
pub use health::health_check;
pub use admin::admin_register;
pub use ondc::{serve_site_verification, handle_on_subscribe}; 
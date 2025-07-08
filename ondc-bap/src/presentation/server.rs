//! Main server implementation for ONDC BAP

use std::sync::Arc;
use axum::Router;
use tracing::{info, error};
use crate::{Result, BAPConfig};

/// Main BAP server implementation
pub struct BAPServer {
    config: Arc<BAPConfig>,
}

impl BAPServer {
    /// Create a new BAP server instance
    pub async fn new() -> Result<Self> {
        let config = Arc::new(crate::config::load_config()?);
        info!("BAP Server configuration loaded successfully");
        
        Ok(Self { config })
    }
    
    /// Run the server
    pub async fn run(&self) -> Result<()> {
        info!("Starting BAP Server on {}:{}", self.config.server.host, self.config.server.port);
        
        // TODO: Implement router creation and server startup
        // This will be implemented in subsequent tasks
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        // This test will need proper configuration setup
        // For now, just verify the struct can be created
        let _server = BAPServer {
            config: Arc::new(crate::config::environment::create_test_config()),
        };
    }
} 
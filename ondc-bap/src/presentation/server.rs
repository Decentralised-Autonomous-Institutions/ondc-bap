//! Main server implementation for ONDC BAP

use std::sync::Arc;
use std::net::SocketAddr;
use tokio::signal;
use tracing::{info, error};

use crate::{Result, BAPConfig};
use crate::config::load_config;
use crate::services::KeyManagementService;
use super::routes::create_router;

/// Main BAP server implementation
pub struct BAPServer {
    config: Arc<BAPConfig>,
    key_manager: Arc<KeyManagementService>,
}

impl BAPServer {
    /// Create a new BAP server instance
    pub async fn new() -> Result<Self> {
        let config = Arc::new(load_config()?);
        info!("BAP Server configuration loaded successfully");
        
        let key_manager = Arc::new(KeyManagementService::new(config.keys.clone()).await
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?);
        info!("Key management service initialized successfully");
        
        Ok(Self { 
            config,
            key_manager,
        })
    }
    
    /// Run the server
    pub async fn run(&self) -> Result<()> {
        let addr = SocketAddr::from((
            self.config.server.host.parse::<std::net::IpAddr>().unwrap_or_else(|_| [0, 0, 0, 0].into()),
            self.config.server.port,
        ));
        
        info!("Starting BAP Server on {}", addr);
        
        // Create router
        let app = create_router(self.config.clone(), self.key_manager.clone());
        
        // Start server with graceful shutdown
        let listener = tokio::net::TcpListener::bind(addr).await
            .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
        
        info!("Server listening on {}", addr);
        
        // Handle graceful shutdown
        let graceful = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal());
        
        if let Err(e) = graceful.await {
            error!("Server error: {}", e);
            return Err(crate::error::AppError::Internal(e.to_string()));
        }
        
        info!("Server shutdown complete");
        Ok(())
    }
    
    /// Get server configuration
    pub fn config(&self) -> &BAPConfig {
        &self.config
    }
    
    /// Get key manager
    pub fn key_manager(&self) -> &KeyManagementService {
        &self.key_manager
    }
}

/// Handle graceful shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down gracefully");
        },
        _ = terminate => {
            info!("Received SIGTERM, shutting down gracefully");
        },
    }
    
    info!("Shutdown signal received, starting graceful shutdown");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        // This test will need proper configuration setup
        // For now, just verify the struct can be created with test config
        let test_config = crate::config::environment::create_test_config();
        let key_manager = KeyManagementService::new(test_config.keys.clone()).await.unwrap();
        
        let _server = BAPServer {
            config: Arc::new(test_config),
            key_manager: Arc::new(key_manager),
        };
    }
} 
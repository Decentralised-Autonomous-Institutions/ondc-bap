//! ONDC BAP Server - Main Binary
//!
//! This is the main entry point for the ONDC BAP server application.

use ondc_bap::{BAPServer, Result};
use tracing::{error, info, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ondc_bap=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting ONDC BAP Server v{}", ondc_bap::VERSION);

    // Create and run the server
    match BAPServer::new().await {
        Ok(server) => {
            info!("BAP Server initialized successfully");
            server.run().await
        }
        Err(e) => {
            error!("Failed to initialize BAP Server: {}", e);
            Err(e)
        }
    }
}

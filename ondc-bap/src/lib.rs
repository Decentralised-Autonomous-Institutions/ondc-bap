//! ONDC BAP (Beckn Application Platform) Server
//!
//! A production-ready ONDC BAP server implementation in Rust that handles
//! ONDC network participant onboarding and provides required endpoints for
//! registry integration.
//!
//! ## Features
//!
//! - **ONDC Protocol Compliance**: Full implementation of ONDC registry APIs
//! - **Cryptographic Security**: Built on secure crypto foundation
//! - **Production Ready**: Comprehensive logging, monitoring, and error handling
//! - **Layered Architecture**: Clean separation of concerns with Axum web framework
//!
//! ## Quick Start
//!
//! ```rust
//! use ondc_bap::BAPServer;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let server = BAPServer::new().await?;
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod error;
pub mod infrastructure;
pub mod presentation;
pub mod services;

// Re-export main types for convenience
pub use config::BAPConfig;
pub use error::AppError;
pub use presentation::BAPServer;

/// Result type for BAP operations
pub type Result<T> = std::result::Result<T, error::AppError>;

/// Application version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration file path
pub const DEFAULT_CONFIG_PATH: &str = "config/";

/// Default server port
pub const DEFAULT_PORT: u16 = 8080;

/// Default server host
pub const DEFAULT_HOST: &str = "0.0.0.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constant() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_PORT, 8080);
        assert_eq!(DEFAULT_HOST, "0.0.0.0");
        assert!(!DEFAULT_CONFIG_PATH.is_empty());
    }
}

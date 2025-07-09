//! Presentation layer for ONDC BAP Server
//!
//! This module contains the HTTP layer implementation using Axum framework,
//! including routers, handlers, middleware, and application state management.

pub mod handlers;
pub mod middleware;
pub mod routes;
pub mod server;

// Re-export main types
pub use handlers::AppState;
pub use routes::create_router;
pub use server::BAPServer;

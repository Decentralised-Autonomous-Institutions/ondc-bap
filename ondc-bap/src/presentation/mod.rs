//! Presentation layer for ONDC BAP Server
//! 
//! This module contains the HTTP layer implementation using Axum framework,
//! including routers, handlers, middleware, and application state management.

pub mod server;
pub mod routes;
pub mod handlers;
pub mod middleware;

// Re-export main types
pub use server::BAPServer;
pub use routes::create_router;
pub use handlers::AppState; 
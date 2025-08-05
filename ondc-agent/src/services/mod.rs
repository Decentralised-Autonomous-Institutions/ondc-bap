//! Service layer for the ONDC Agent.
//!
//! This module contains the service layer implementations that orchestrate
//! business logic, manage LLM operations, and coordinate between different
//! components of the agent system.

pub mod llm_service;

pub use llm_service::LLMService;
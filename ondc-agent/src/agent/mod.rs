//! Core agent functionality for ONDC natural language processing.
//!
//! This module contains the main `ONDCAgent` struct and its implementation,
//! which orchestrates the process of converting natural language queries
//! into ONDC/Beckn protocol requests.

pub use ondc_agent::ONDCAgent;

pub mod ondc_agent;
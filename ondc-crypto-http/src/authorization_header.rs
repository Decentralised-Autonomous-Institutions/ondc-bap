//! Authorization header generation and parsing.

use ondc_crypto_traits::ONDCCryptoError;

/// Create authorization header for ONDC requests.
pub fn create_authorization_header(
    _body: &[u8],
    _private_key: &[u8],
    _subscriber_id: &str,
    _unique_key_id: &str,
    _expires: Option<u64>,
    _created: Option<u64>,
) -> Result<String, ONDCCryptoError> {
    // TODO: Implement authorization header creation
    todo!("Authorization header creation implementation")
}

/// Parse authorization header from string.
pub fn parse_authorization_header(_header: &str) -> Result<ParsedHeader, ONDCCryptoError> {
    // TODO: Implement authorization header parsing
    todo!("Authorization header parsing implementation")
}

/// Parsed authorization header structure.
#[derive(Debug, Clone)]
pub struct ParsedHeader {
    pub key_id: String,
    pub algorithm: String,
    pub created: u64,
    pub expires: u64,
    pub headers: Vec<String>,
    pub signature: Vec<u8>,
} 
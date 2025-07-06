//! ONDC signing string generation.

use ondc_crypto_traits::ONDCCryptoError;

/// ONDC signing string structure.
#[derive(Debug, Clone)]
pub struct ONDCSigningString {
    pub created: u64,
    pub expires: u64,
    pub digest: String,
}

impl ONDCSigningString {
    /// Create a new ONDC signing string.
    pub fn new(
        _body: &[u8],
        _created: Option<u64>,
        _expires: Option<u64>,
    ) -> Result<Self, ONDCCryptoError> {
        // TODO: Implement ONDC signing string creation
        todo!("ONDC signing string implementation")
    }

    /// Convert to string format.
    pub fn to_string(&self) -> String {
        // TODO: Implement string conversion
        todo!("String conversion implementation")
    }
} 
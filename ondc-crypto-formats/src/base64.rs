//! Base64 encoding and decoding utilities for ONDC cryptographic operations.
//!
//! This module provides secure Base64 encoding and decoding functions that are
//! compatible with the ONDC protocol and the Node.js implementation.
//!
//! # Security Considerations
//!
//! - All encoding operations use constant-time implementations where possible
//! - Sensitive data is automatically zeroized when using `Zeroizing` types
//! - Input validation prevents buffer overflow attacks
//! - Error messages do not leak sensitive information

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::engine::Engine;
use ondc_crypto_traits::ONDCCryptoError;
use zeroize::{Zeroize, Zeroizing};

/// Base64 encoding variants supported by ONDC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Variant {
    /// Standard Base64 encoding (RFC 4648)
    Standard,
    /// URL-safe Base64 encoding (RFC 4648)
    UrlSafe,
    /// URL-safe Base64 encoding without padding
    UrlSafeNoPad,
}

impl Default for Base64Variant {
    fn default() -> Self {
        Self::Standard
    }
}

/// Encode signature for ONDC headers using standard Base64 encoding.
///
/// This function uses the same encoding as the Node.js implementation
/// (`_sodium.base64_variants.ORIGINAL`).
///
/// # Arguments
///
/// * `signature` - The signature bytes to encode
///
/// # Returns
///
/// A Base64-encoded string suitable for use in ONDC authorization headers.
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::encode_signature;
///
/// let signature = [0x01, 0x02, 0x03, 0x04];
/// let encoded = encode_signature(&signature);
/// assert_eq!(encoded, "AQIDBA==");
/// ```
///
/// # Security
///
/// This function does not handle sensitive data directly. For sensitive data,
/// use `encode_signature_secure()`.
pub fn encode_signature(signature: &[u8]) -> String {
    STANDARD.encode(signature)
}

/// Encode signature with specified Base64 variant.
///
/// # Arguments
///
/// * `signature` - The signature bytes to encode
/// * `variant` - The Base64 encoding variant to use
///
/// # Returns
///
/// A Base64-encoded string using the specified variant.
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::{encode_signature_variant, Base64Variant};
///
/// let signature = [0x01, 0x02, 0x03, 0x04];
/// let encoded = encode_signature_variant(&signature, Base64Variant::UrlSafe);
/// assert_eq!(encoded, "AQIDBA==");
/// ```
pub fn encode_signature_variant(signature: &[u8], variant: Base64Variant) -> String {
    match variant {
        Base64Variant::Standard => STANDARD.encode(signature),
        Base64Variant::UrlSafe => URL_SAFE.encode(signature),
        Base64Variant::UrlSafeNoPad => URL_SAFE_NO_PAD.encode(signature),
    }
}

/// Encode signature securely with automatic zeroization.
///
/// This function is designed for encoding sensitive data that should be
/// automatically zeroized after use.
///
/// # Arguments
///
/// * `signature` - The signature bytes to encode (will be zeroized after encoding)
///
/// # Returns
///
/// A Base64-encoded string with the original data zeroized.
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::encode_signature_secure;
/// use zeroize::Zeroizing;
///
/// let mut signature = Zeroizing::new(vec![0x01, 0x02, 0x03, 0x04]);
/// let encoded = encode_signature_secure(&mut signature);
/// // signature is now zeroized
/// ```
///
/// # Security
///
/// The input signature is automatically zeroized after encoding to prevent
/// memory disclosure of sensitive data.
pub fn encode_signature_secure(signature: &mut Zeroizing<Vec<u8>>) -> String {
    let encoded = STANDARD.encode(signature.as_slice());
    // Zeroize the sensitive data
    signature.zeroize();
    encoded
}

/// Decode signature with validation.
///
/// This function decodes Base64-encoded signatures and validates the output.
/// It uses the same decoding as the Node.js implementation.
///
/// # Arguments
///
/// * `encoded` - The Base64-encoded signature string
///
/// # Returns
///
/// The decoded signature bytes, or an error if decoding fails.
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::decode_signature;
///
/// let encoded = "AQIDBA==";
/// let decoded = decode_signature(encoded).unwrap();
/// assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);
/// ```
///
/// # Errors
///
/// Returns `ONDCCryptoError::EncodingError` if the input is not valid Base64.
pub fn decode_signature(encoded: &str) -> Result<Vec<u8>, ONDCCryptoError> {
    STANDARD
        .decode(encoded)
        .map_err(|e| ONDCCryptoError::EncodingError(format!("Invalid Base64 encoding: {}", e)))
}

/// Decode signature with specified Base64 variant.
///
/// # Arguments
///
/// * `encoded` - The Base64-encoded signature string
/// * `variant` - The Base64 encoding variant to use for decoding
///
/// # Returns
///
/// The decoded signature bytes, or an error if decoding fails.
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::{decode_signature_variant, Base64Variant};
///
/// let encoded = "AQIDBA==";
/// let decoded = decode_signature_variant(encoded, Base64Variant::Standard).unwrap();
/// assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);
/// ```
///
/// # Errors
///
/// Returns `ONDCCryptoError::EncodingError` if the input is not valid Base64
/// for the specified variant.
pub fn decode_signature_variant(
    encoded: &str,
    variant: Base64Variant,
) -> Result<Vec<u8>, ONDCCryptoError> {
    let result = match variant {
        Base64Variant::Standard => STANDARD.decode(encoded),
        Base64Variant::UrlSafe => URL_SAFE.decode(encoded),
        Base64Variant::UrlSafeNoPad => URL_SAFE_NO_PAD.decode(encoded),
    };

    result.map_err(|e| ONDCCryptoError::EncodingError(format!("Invalid Base64 encoding: {}", e)))
}

/// Decode signature securely with automatic zeroization.
///
/// This function is designed for decoding sensitive data that should be
/// automatically zeroized after use.
///
/// # Arguments
///
/// * `encoded` - The Base64-encoded signature string
///
/// # Returns
///
/// The decoded signature bytes in a `Zeroizing` container, or an error if decoding fails.
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::decode_signature_secure;
///
/// let encoded = "AQIDBA==";
/// let decoded = decode_signature_secure(encoded).unwrap();
/// // decoded is automatically zeroized when dropped
/// ```
///
/// # Security
///
/// The decoded data is automatically zeroized when the `Zeroizing` container is dropped.
///
/// # Errors
///
/// Returns `ONDCCryptoError::EncodingError` if the input is not valid Base64.
pub fn decode_signature_secure(encoded: &str) -> Result<Zeroizing<Vec<u8>>, ONDCCryptoError> {
    let decoded = decode_signature(encoded)?;
    Ok(Zeroizing::new(decoded))
}

/// Validate Base64 string format.
///
/// This function checks if a string is valid Base64 without actually decoding it.
///
/// # Arguments
///
/// * `encoded` - The string to validate
/// * `variant` - The Base64 variant to validate against
///
/// # Returns
///
/// `true` if the string is valid Base64, `false` otherwise.
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::{is_valid_base64, Base64Variant};
///
/// assert!(is_valid_base64("AQIDBA==", Base64Variant::Standard));
/// assert!(!is_valid_base64("invalid!", Base64Variant::Standard));
/// ```
pub fn is_valid_base64(encoded: &str, variant: Base64Variant) -> bool {
    match variant {
        Base64Variant::Standard => STANDARD.decode(encoded).is_ok(),
        Base64Variant::UrlSafe => URL_SAFE.decode(encoded).is_ok(),
        Base64Variant::UrlSafeNoPad => URL_SAFE_NO_PAD.decode(encoded).is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_signature() {
        let signature = [0x01, 0x02, 0x03, 0x04];
        let encoded = encode_signature(&signature);
        assert_eq!(encoded, "AQIDBA==");
    }

    #[test]
    fn test_decode_signature() {
        let encoded = "AQIDBA==";
        let decoded = decode_signature(encoded).unwrap();
        assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let encoded = encode_signature(&original);
        let decoded = decode_signature(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_decode_invalid_base64() {
        let invalid = "invalid!";
        let result = decode_signature(invalid);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ONDCCryptoError::EncodingError(_)
        ));
    }

    #[test]
    fn test_encode_signature_variant() {
        let signature = [0x01, 0x02, 0x03, 0x04];

        let standard = encode_signature_variant(&signature, Base64Variant::Standard);
        assert_eq!(standard, "AQIDBA==");

        let url_safe = encode_signature_variant(&signature, Base64Variant::UrlSafe);
        assert_eq!(url_safe, "AQIDBA==");

        let url_safe_no_pad = encode_signature_variant(&signature, Base64Variant::UrlSafeNoPad);
        assert_eq!(url_safe_no_pad, "AQIDBA");
    }

    #[test]
    fn test_decode_signature_variant() {
        let standard_encoded = "AQIDBA==";
        let decoded = decode_signature_variant(standard_encoded, Base64Variant::Standard).unwrap();
        assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);

        let url_safe_no_pad_encoded = "AQIDBA";
        let decoded =
            decode_signature_variant(url_safe_no_pad_encoded, Base64Variant::UrlSafeNoPad).unwrap();
        assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_encode_signature_secure() {
        let mut signature = Zeroizing::new(vec![0x01, 0x02, 0x03, 0x04]);
        let encoded = encode_signature_secure(&mut signature);
        assert_eq!(encoded, "AQIDBA==");

        // Verify the signature was zeroized
        assert_eq!(signature.as_slice(), &[]);
    }

    #[test]
    fn test_decode_signature_secure() {
        let encoded = "AQIDBA==";
        let decoded = decode_signature_secure(encoded).unwrap();
        assert_eq!(decoded.as_slice(), &[0x01, 0x02, 0x03, 0x04]);

        // The Zeroizing container will automatically zeroize when dropped
    }

    #[test]
    fn test_is_valid_base64() {
        assert!(is_valid_base64("AQIDBA==", Base64Variant::Standard));
        assert!(is_valid_base64("AQIDBA", Base64Variant::UrlSafeNoPad));
        assert!(!is_valid_base64("invalid!", Base64Variant::Standard));
        assert!(!is_valid_base64("AQIDBA===", Base64Variant::Standard)); // Too much padding
    }

    #[test]
    fn test_empty_input() {
        let empty = [];
        let encoded = encode_signature(&empty);
        assert_eq!(encoded, "");

        let decoded = decode_signature("").unwrap();
        assert_eq!(decoded, vec![]);
    }

    #[test]
    fn test_large_input() {
        let large_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let encoded = encode_signature(&large_data);
        let decoded = decode_signature(&encoded).unwrap();
        assert_eq!(decoded, large_data);
    }

    #[test]
    fn test_ondc_compatibility() {
        // Test with data that matches ONDC signature patterns
        let signature = vec![
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b,
            0x5c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d,
            0x9e, 0x0f, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f,
            0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b,
            0x7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c, 0x4d,
        ];

        let encoded = encode_signature(&signature);
        let decoded = decode_signature(&encoded).unwrap();
        assert_eq!(decoded, signature);

        // Verify the encoded string is valid for ONDC headers
        assert!(!encoded.contains('+') || !encoded.contains('/')); // Should be URL-safe if needed
    }
}

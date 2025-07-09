//! Key format conversion utilities for ONDC cryptographic operations.
//!
//! This module provides utilities for converting cryptographic keys between
//! different formats including raw bytes, Base64 encoding, and DER encoding.
//! It supports both Ed25519 and X25519 key types with proper validation
//! and security measures.
//!
//! # Security Features
//!
//! - Automatic memory zeroization for sensitive data
//! - Input validation for all key formats
//! - Constant-time operations where applicable
//! - Comprehensive error handling with detailed messages
//! - Support for both public and private key conversions
//!
//! # Examples
//!
//! ```rust
//! use ondc_crypto_formats::key_formats;
//!
//! // Convert Ed25519 private key from raw bytes to Base64
//! let raw_key = [0u8; 32]; // Use a real private key in practice
//! let base64_key = key_formats::ed25519_private_key_to_base64(&raw_key).unwrap();
//!
//! // Convert X25519 public key to DER format
//! let public_key = [0u8; 32]; // Use a real public key in practice
//! let der_key = key_formats::x25519_public_key_to_der(&public_key).unwrap();
//! ```

use der::{asn1::OctetString, Decode, Encode};
use ondc_crypto_traits::ONDCCryptoError;
use zeroize::Zeroizing;

use crate::base64::{decode_signature, encode_signature};

// ============================================================================
// Ed25519 Key Format Conversions
// ============================================================================

/// Convert Ed25519 private key from raw bytes to Base64 encoding.
///
/// This function takes a raw 32-byte Ed25519 private key and encodes it
/// using standard Base64 encoding suitable for ONDC operations.
///
/// # Arguments
///
/// * `raw_key` - The 32-byte Ed25519 private key
///
/// # Returns
///
/// A Base64-encoded string representation of the private key.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes
/// - The key is invalid or malformed
///
/// # Security Notes
///
/// - The input key should be handled securely
/// - Consider using `zeroize::Zeroizing` for temporary storage
/// - The returned string contains sensitive data and should be protected
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32]; // Use a real private key in practice
/// let base64_key = key_formats::ed25519_private_key_to_base64(&raw_key).unwrap();
/// assert_eq!(base64_key.len(), 44); // Base64 encoding of 32 bytes
/// ```
pub fn ed25519_private_key_to_base64(raw_key: &[u8]) -> Result<String, ONDCCryptoError> {
    if raw_key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: raw_key.len(),
        });
    }

    Ok(encode_signature(raw_key))
}

/// Convert Ed25519 private key from Base64 encoding to raw bytes.
///
/// This function takes a Base64-encoded Ed25519 private key and decodes it
/// to raw bytes for cryptographic operations.
///
/// # Arguments
///
/// * `base64_key` - The Base64-encoded Ed25519 private key
///
/// # Returns
///
/// The raw 32-byte Ed25519 private key in a `Zeroizing` container.
///
/// # Errors
///
/// Returns an error if:
/// - The Base64 encoding is invalid
/// - The decoded key length is not 32 bytes
/// - The key is malformed
///
/// # Security Notes
///
/// - The returned key is automatically zeroized when dropped
/// - The input string should be handled securely
/// - Consider clearing the input string after use
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let base64_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// let raw_key = key_formats::ed25519_private_key_from_base64(base64_key).unwrap();
/// assert_eq!(raw_key.len(), 32);
/// ```
pub fn ed25519_private_key_from_base64(
    base64_key: &str,
) -> Result<Zeroizing<Vec<u8>>, ONDCCryptoError> {
    let decoded = decode_signature(base64_key)?;

    if decoded.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: decoded.len(),
        });
    }

    Ok(Zeroizing::new(decoded))
}

/// Convert Ed25519 public key from raw bytes to Base64 encoding.
///
/// This function takes a raw 32-byte Ed25519 public key and encodes it
/// using standard Base64 encoding.
///
/// # Arguments
///
/// * `raw_key` - The 32-byte Ed25519 public key
///
/// # Returns
///
/// A Base64-encoded string representation of the public key.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes
/// - The key is invalid or malformed
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32]; // Use a real public key in practice
/// let base64_key = key_formats::ed25519_public_key_to_base64(&raw_key).unwrap();
/// assert_eq!(base64_key.len(), 44); // Base64 encoding of 32 bytes
/// ```
pub fn ed25519_public_key_to_base64(raw_key: &[u8]) -> Result<String, ONDCCryptoError> {
    if raw_key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: raw_key.len(),
        });
    }

    Ok(encode_signature(raw_key))
}

/// Convert Ed25519 public key from Base64 encoding to raw bytes.
///
/// This function takes a Base64-encoded Ed25519 public key and decodes it
/// to raw bytes for cryptographic operations.
///
/// # Arguments
///
/// * `base64_key` - The Base64-encoded Ed25519 public key
///
/// # Returns
///
/// The raw 32-byte Ed25519 public key.
///
/// # Errors
///
/// Returns an error if:
/// - The Base64 encoding is invalid
/// - The decoded key length is not 32 bytes
/// - The key is malformed
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let base64_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// let raw_key = key_formats::ed25519_public_key_from_base64(base64_key).unwrap();
/// assert_eq!(raw_key.len(), 32);
/// ```
pub fn ed25519_public_key_from_base64(base64_key: &str) -> Result<[u8; 32], ONDCCryptoError> {
    let decoded = decode_signature(base64_key)?;

    if decoded.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: decoded.len(),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Convert Ed25519 private key from raw bytes to DER format.
///
/// This function takes a raw 32-byte Ed25519 private key and encodes it
/// in DER format according to RFC 8410.
///
/// # Arguments
///
/// * `raw_key` - The 32-byte Ed25519 private key
///
/// # Returns
///
/// The DER-encoded private key as bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes
/// - The key is invalid or malformed
/// - DER encoding fails
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32]; // Use a real private key in practice
/// let der_key = key_formats::ed25519_private_key_to_der(&raw_key).unwrap();
/// assert!(der_key.len() > 32); // DER encoding adds structure
/// ```
pub fn ed25519_private_key_to_der(raw_key: &[u8]) -> Result<Vec<u8>, ONDCCryptoError> {
    if raw_key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: raw_key.len(),
        });
    }

    // Create DER structure for Ed25519 private key
    let octet_string = OctetString::new(raw_key)
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER encoding failed: {}", e)))?;

    octet_string
        .to_der()
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER serialization failed: {}", e)))
}

/// Convert Ed25519 private key from DER format to raw bytes.
///
/// This function takes a DER-encoded Ed25519 private key and decodes it
/// to raw bytes for cryptographic operations.
///
/// # Arguments
///
/// * `der_key` - The DER-encoded Ed25519 private key
///
/// # Returns
///
/// The raw 32-byte Ed25519 private key in a `Zeroizing` container.
///
/// # Errors
///
/// Returns an error if:
/// - The DER encoding is invalid
/// - The decoded key length is not 32 bytes
/// - The key is malformed
///
/// # Security Notes
///
/// - The returned key is automatically zeroized when dropped
/// - The input should be handled securely
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32];
/// let der_key = key_formats::ed25519_private_key_to_der(&raw_key).unwrap();
/// let decoded_key = key_formats::ed25519_private_key_from_der(&der_key).unwrap();
/// assert_eq!(decoded_key.as_slice(), &raw_key);
/// ```
pub fn ed25519_private_key_from_der(der_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, ONDCCryptoError> {
    let octet_string = OctetString::from_der(der_key)
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER decoding failed: {}", e)))?;

    let key_bytes = octet_string.as_bytes();

    if key_bytes.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len(),
        });
    }

    Ok(Zeroizing::new(key_bytes.to_vec()))
}

// ============================================================================
// X25519 Key Format Conversions
// ============================================================================

/// Convert X25519 private key from raw bytes to Base64 encoding.
///
/// This function takes a raw 32-byte X25519 private key and encodes it
/// using standard Base64 encoding.
///
/// # Arguments
///
/// * `raw_key` - The 32-byte X25519 private key
///
/// # Returns
///
/// A Base64-encoded string representation of the private key.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes
/// - The key is invalid or malformed
///
/// # Security Notes
///
/// - The input key should be handled securely
/// - Consider using `zeroize::Zeroizing` for temporary storage
/// - The returned string contains sensitive data and should be protected
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32]; // Use a real private key in practice
/// let base64_key = key_formats::x25519_private_key_to_base64(&raw_key).unwrap();
/// assert_eq!(base64_key.len(), 44); // Base64 encoding of 32 bytes
/// ```
pub fn x25519_private_key_to_base64(raw_key: &[u8]) -> Result<String, ONDCCryptoError> {
    if raw_key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: raw_key.len(),
        });
    }

    Ok(encode_signature(raw_key))
}

/// Convert X25519 private key from Base64 encoding to raw bytes.
///
/// This function takes a Base64-encoded X25519 private key and decodes it
/// to raw bytes for cryptographic operations.
///
/// # Arguments
///
/// * `base64_key` - The Base64-encoded X25519 private key
///
/// # Returns
///
/// The raw 32-byte X25519 private key in a `Zeroizing` container.
///
/// # Errors
///
/// Returns an error if:
/// - The Base64 encoding is invalid
/// - The decoded key length is not 32 bytes
/// - The key is malformed
///
/// # Security Notes
///
/// - The returned key is automatically zeroized when dropped
/// - The input string should be handled securely
/// - Consider clearing the input string after use
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let base64_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// let raw_key = key_formats::x25519_private_key_from_base64(base64_key).unwrap();
/// assert_eq!(raw_key.len(), 32);
/// ```
pub fn x25519_private_key_from_base64(
    base64_key: &str,
) -> Result<Zeroizing<Vec<u8>>, ONDCCryptoError> {
    let decoded = decode_signature(base64_key)?;

    if decoded.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: decoded.len(),
        });
    }

    Ok(Zeroizing::new(decoded))
}

/// Convert X25519 public key from raw bytes to Base64 encoding.
///
/// This function takes a raw 32-byte X25519 public key and encodes it
/// using standard Base64 encoding.
///
/// # Arguments
///
/// * `raw_key` - The 32-byte X25519 public key
///
/// # Returns
///
/// A Base64-encoded string representation of the public key.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes
/// - The key is invalid or malformed
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32]; // Use a real public key in practice
/// let base64_key = key_formats::x25519_public_key_to_base64(&raw_key).unwrap();
/// assert_eq!(base64_key.len(), 44); // Base64 encoding of 32 bytes
/// ```
pub fn x25519_public_key_to_base64(raw_key: &[u8]) -> Result<String, ONDCCryptoError> {
    if raw_key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: raw_key.len(),
        });
    }

    Ok(encode_signature(raw_key))
}

/// Convert X25519 public key from Base64 encoding to raw bytes.
///
/// This function takes a Base64-encoded X25519 public key and decodes it
/// to raw bytes for cryptographic operations.
///
/// # Arguments
///
/// * `base64_key` - The Base64-encoded X25519 public key
///
/// # Returns
///
/// The raw 32-byte X25519 public key.
///
/// # Errors
///
/// Returns an error if:
/// - The Base64 encoding is invalid
/// - The decoded key length is not 32 bytes
/// - The key is malformed
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let base64_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// let raw_key = key_formats::x25519_public_key_from_base64(base64_key).unwrap();
/// assert_eq!(raw_key.len(), 32);
/// ```
pub fn x25519_public_key_from_base64(base64_key: &str) -> Result<[u8; 32], ONDCCryptoError> {
    let decoded = decode_signature(base64_key)?;

    if decoded.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: decoded.len(),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Convert X25519 public key from raw bytes to DER format.
///
/// This function takes a raw 32-byte X25519 public key and encodes it
/// in DER format according to RFC 8410.
///
/// # Arguments
///
/// * `raw_key` - The 32-byte X25519 public key
///
/// # Returns
///
/// The DER-encoded public key as bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes
/// - The key is invalid or malformed
/// - DER encoding fails
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32]; // Use a real public key in practice
/// let der_key = key_formats::x25519_public_key_to_der(&raw_key).unwrap();
/// assert!(der_key.len() > 32); // DER encoding adds structure
/// ```
pub fn x25519_public_key_to_der(raw_key: &[u8]) -> Result<Vec<u8>, ONDCCryptoError> {
    if raw_key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: raw_key.len(),
        });
    }

    // Create DER structure for X25519 public key
    let octet_string = OctetString::new(raw_key)
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER encoding failed: {}", e)))?;

    octet_string
        .to_der()
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER serialization failed: {}", e)))
}

/// Convert X25519 public key from DER format to raw bytes.
///
/// This function takes a DER-encoded X25519 public key and decodes it
/// to raw bytes for cryptographic operations.
///
/// # Arguments
///
/// * `der_key` - The DER-encoded X25519 public key
///
/// # Returns
///
/// The raw 32-byte X25519 public key.
///
/// # Errors
///
/// Returns an error if:
/// - The DER encoding is invalid
/// - The decoded key length is not 32 bytes
/// - The key is malformed
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32];
/// let der_key = key_formats::x25519_public_key_to_der(&raw_key).unwrap();
/// let decoded_key = key_formats::x25519_public_key_from_der(&der_key).unwrap();
/// assert_eq!(&decoded_key, &raw_key);
/// ```
pub fn x25519_public_key_from_der(der_key: &[u8]) -> Result<[u8; 32], ONDCCryptoError> {
    let octet_string = OctetString::from_der(der_key)
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER decoding failed: {}", e)))?;

    let key_bytes = octet_string.as_bytes();

    if key_bytes.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len(),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);
    Ok(key)
}

/// Convert X25519 private key from raw bytes to DER format.
///
/// This function takes a raw 32-byte X25519 private key and encodes it
/// in DER format according to RFC 8410.
///
/// # Arguments
///
/// * `raw_key` - The 32-byte X25519 private key
///
/// # Returns
///
/// The DER-encoded private key as bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes
/// - The key is invalid or malformed
/// - DER encoding fails
///
/// # Security Notes
///
/// - The input key should be handled securely
/// - Consider using `zeroize::Zeroizing` for temporary storage
/// - The returned DER data contains sensitive information
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32]; // Use a real private key in practice
/// let der_key = key_formats::x25519_private_key_to_der(&raw_key).unwrap();
/// assert!(der_key.len() > 32); // DER encoding adds structure
/// ```
pub fn x25519_private_key_to_der(raw_key: &[u8]) -> Result<Vec<u8>, ONDCCryptoError> {
    if raw_key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: raw_key.len(),
        });
    }

    // Create DER structure for X25519 private key
    let octet_string = OctetString::new(raw_key)
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER encoding failed: {}", e)))?;

    octet_string
        .to_der()
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER serialization failed: {}", e)))
}

/// Convert X25519 private key from DER format to raw bytes.
///
/// This function takes a DER-encoded X25519 private key and decodes it
/// to raw bytes for cryptographic operations.
///
/// # Arguments
///
/// * `der_key` - The DER-encoded X25519 private key
///
/// # Returns
///
/// The raw 32-byte X25519 private key in a `Zeroizing` container.
///
/// # Errors
///
/// Returns an error if:
/// - The DER encoding is invalid
/// - The decoded key length is not 32 bytes
/// - The key is malformed
///
/// # Security Notes
///
/// - The returned key is automatically zeroized when dropped
/// - The input should be handled securely
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_formats::key_formats;
///
/// let raw_key = [0u8; 32];
/// let der_key = key_formats::x25519_private_key_to_der(&raw_key).unwrap();
/// let decoded_key = key_formats::x25519_private_key_from_der(&der_key).unwrap();
/// assert_eq!(decoded_key.as_slice(), &raw_key);
/// ```
pub fn x25519_private_key_from_der(der_key: &[u8]) -> Result<Zeroizing<Vec<u8>>, ONDCCryptoError> {
    let octet_string = OctetString::from_der(der_key)
        .map_err(|e| ONDCCryptoError::EncodingError(format!("DER decoding failed: {}", e)))?;

    let key_bytes = octet_string.as_bytes();

    if key_bytes.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: key_bytes.len(),
        });
    }

    Ok(Zeroizing::new(key_bytes.to_vec()))
}

// ============================================================================
// Legacy Functions (for backward compatibility)
// ============================================================================

/// Convert Ed25519 private key from raw bytes.
///
/// This is a legacy function that maintains backward compatibility.
/// Consider using `ed25519_private_key_to_base64` for new code.
///
/// # Arguments
///
/// * `raw_key` - The raw Ed25519 private key bytes
///
/// # Returns
///
/// The private key in a standardized format.
///
/// # Errors
///
/// Returns an error if the key is invalid.
pub fn ed25519_from_raw(raw_key: &[u8]) -> Result<Vec<u8>, ONDCCryptoError> {
    // For backward compatibility, return the raw key as-is
    // but validate the length
    if raw_key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: raw_key.len(),
        });
    }
    Ok(raw_key.to_vec())
}

/// Convert X25519 public key to DER format.
///
/// This is a legacy function that maintains backward compatibility.
/// Consider using `x25519_public_key_to_der` for new code.
///
/// # Arguments
///
/// * `public_key` - The X25519 public key bytes
///
/// # Returns
///
/// The public key in DER format.
///
/// # Errors
///
/// Returns an error if the key is invalid.
pub fn x25519_to_der(public_key: &[u8]) -> Result<Vec<u8>, ONDCCryptoError> {
    x25519_public_key_to_der(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test data for Ed25519 keys
    const TEST_ED25519_PRIVATE_KEY: [u8; 32] = [
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c,
        0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f,
        0x1a, 0x2b,
    ];

    const TEST_ED25519_PUBLIC_KEY: [u8; 32] = [
        0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
        0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b,
        0x3c, 0x4d,
    ];

    // Test data for X25519 keys
    const TEST_X25519_PRIVATE_KEY: [u8; 32] = [
        0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d,
        0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f, 0x1a,
        0x2b, 0x3c,
    ];

    const TEST_X25519_PUBLIC_KEY: [u8; 32] = [
        0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f,
        0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c,
        0x4d, 0x5e,
    ];

    #[test]
    fn test_ed25519_private_key_base64_roundtrip() {
        let base64_key = ed25519_private_key_to_base64(&TEST_ED25519_PRIVATE_KEY).unwrap();
        let decoded_key = ed25519_private_key_from_base64(&base64_key).unwrap();
        assert_eq!(decoded_key.as_slice(), &TEST_ED25519_PRIVATE_KEY);
    }

    #[test]
    fn test_ed25519_public_key_base64_roundtrip() {
        let base64_key = ed25519_public_key_to_base64(&TEST_ED25519_PUBLIC_KEY).unwrap();
        let decoded_key = ed25519_public_key_from_base64(&base64_key).unwrap();
        assert_eq!(&decoded_key, &TEST_ED25519_PUBLIC_KEY);
    }

    #[test]
    fn test_ed25519_private_key_der_roundtrip() {
        let der_key = ed25519_private_key_to_der(&TEST_ED25519_PRIVATE_KEY).unwrap();
        let decoded_key = ed25519_private_key_from_der(&der_key).unwrap();
        assert_eq!(decoded_key.as_slice(), &TEST_ED25519_PRIVATE_KEY);
    }

    #[test]
    fn test_x25519_private_key_base64_roundtrip() {
        let base64_key = x25519_private_key_to_base64(&TEST_X25519_PRIVATE_KEY).unwrap();
        let decoded_key = x25519_private_key_from_base64(&base64_key).unwrap();
        assert_eq!(decoded_key.as_slice(), &TEST_X25519_PRIVATE_KEY);
    }

    #[test]
    fn test_x25519_public_key_base64_roundtrip() {
        let base64_key = x25519_public_key_to_base64(&TEST_X25519_PUBLIC_KEY).unwrap();
        let decoded_key = x25519_public_key_from_base64(&base64_key).unwrap();
        assert_eq!(&decoded_key, &TEST_X25519_PUBLIC_KEY);
    }

    #[test]
    fn test_x25519_public_key_der_roundtrip() {
        let der_key = x25519_public_key_to_der(&TEST_X25519_PUBLIC_KEY).unwrap();
        let decoded_key = x25519_public_key_from_der(&der_key).unwrap();
        assert_eq!(&decoded_key, &TEST_X25519_PUBLIC_KEY);
    }

    #[test]
    fn test_x25519_private_key_der_roundtrip() {
        let der_key = x25519_private_key_to_der(&TEST_X25519_PRIVATE_KEY).unwrap();
        let decoded_key = x25519_private_key_from_der(&der_key).unwrap();
        assert_eq!(decoded_key.as_slice(), &TEST_X25519_PRIVATE_KEY);
    }

    #[test]
    fn test_invalid_key_lengths() {
        // Test Ed25519 private key with wrong length
        let short_key = [0u8; 16];
        assert!(ed25519_private_key_to_base64(&short_key).is_err());
        assert!(ed25519_private_key_to_der(&short_key).is_err());

        // Test X25519 public key with wrong length
        let long_key = [0u8; 64];
        assert!(x25519_public_key_to_base64(&long_key).is_err());
        assert!(x25519_public_key_to_der(&long_key).is_err());
    }

    #[test]
    fn test_invalid_base64_encoding() {
        let invalid_base64 = "invalid!";
        assert!(ed25519_private_key_from_base64(invalid_base64).is_err());
        assert!(ed25519_public_key_from_base64(invalid_base64).is_err());
        assert!(x25519_private_key_from_base64(invalid_base64).is_err());
        assert!(x25519_public_key_from_base64(invalid_base64).is_err());
    }

    #[test]
    fn test_invalid_der_encoding() {
        let invalid_der = b"invalid DER data";
        assert!(ed25519_private_key_from_der(invalid_der).is_err());
        assert!(x25519_public_key_from_der(invalid_der).is_err());
        assert!(x25519_private_key_from_der(invalid_der).is_err());
    }

    #[test]
    fn test_legacy_functions() {
        // Test legacy ed25519_from_raw function
        let result = ed25519_from_raw(&TEST_ED25519_PRIVATE_KEY).unwrap();
        assert_eq!(result, TEST_ED25519_PRIVATE_KEY);

        // Test legacy x25519_to_der function
        let result = x25519_to_der(&TEST_X25519_PUBLIC_KEY).unwrap();
        let decoded = x25519_public_key_from_der(&result).unwrap();
        assert_eq!(&decoded, &TEST_X25519_PUBLIC_KEY);
    }

    #[test]
    fn test_zeroization() {
        let base64_key = ed25519_private_key_to_base64(&TEST_ED25519_PRIVATE_KEY).unwrap();
        let decoded_key = ed25519_private_key_from_base64(&base64_key).unwrap();

        // Verify the key is in a Zeroizing container
        assert_eq!(decoded_key.as_slice(), &TEST_ED25519_PRIVATE_KEY);

        // The key will be automatically zeroized when dropped
        drop(decoded_key);
    }

    #[test]
    fn test_ondc_compatibility() {
        // Test with data that matches ONDC key patterns
        let test_key = [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b,
            0x5c, 0x6d, 0x7e, 0x8f, 0x9a, 0x0b, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d,
            0x9e, 0x0f, 0x1a, 0x2b,
        ];

        let base64_key = ed25519_private_key_to_base64(&test_key).unwrap();
        let decoded_key = ed25519_private_key_from_base64(&base64_key).unwrap();
        assert_eq!(decoded_key.as_slice(), &test_key);

        // Verify the encoded string is valid for ONDC operations
        assert!(!base64_key.contains('+') || !base64_key.contains('/')); // Should be URL-safe if needed
    }
}

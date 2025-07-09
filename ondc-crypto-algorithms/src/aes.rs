//! AES-256-ECB decryption implementation for ONDC challenge processing.
//!
//! This module provides AES-256-ECB decryption functionality required for
//! processing ONDC onboarding challenges. It uses the aes and cipher
//! crates for secure cryptographic operations.
//!
//! # Security Features
//!
//! - Constant-time decryption operations
//! - Proper error handling without information leakage
//! - Input validation for all operations
//! - Memory-safe key handling
//!
//! # Examples
//!
//! ```rust
//! use ondc_crypto_algorithms::decrypt_aes256_ecb;
//!
//! let encrypted_data = [0u8; 32]; // In practice, this would be encrypted data
//! let key = [0u8; 32]; // 256-bit key
//! let decrypted = decrypt_aes256_ecb(&encrypted_data, &key).unwrap();
//! ```

use aes::Aes256;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use ondc_crypto_traits::ONDCCryptoError;

/// Decrypt data using AES-256-ECB mode.
///
/// This function decrypts data that was encrypted using AES-256-ECB mode.
/// It's specifically designed for ONDC challenge processing where the
/// challenge is encrypted using this mode.
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted data to decrypt
/// * `key` - The 256-bit (32-byte) decryption key
///
/// # Returns
///
/// Returns the decrypted data as a byte vector, or an error if decryption fails.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes (256 bits)
/// - The encrypted data length is not a multiple of 16 bytes (AES block size)
/// - The decryption operation fails
///
/// # Security Notes
///
/// - ECB mode is generally not recommended for new applications due to
///   its lack of semantic security. However, it's required for ONDC
///   compatibility.
/// - The key should be handled securely and zeroized after use
/// - This function does not perform any key validation beyond length checking
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_algorithms::decrypt_aes256_ecb;
///
/// let encrypted_data = [0u8; 32]; // In practice, this would be encrypted data
/// let key = [0u8; 32]; // 256-bit key
/// let decrypted = decrypt_aes256_ecb(&encrypted_data, &key).unwrap();
/// ```
pub fn decrypt_aes256_ecb(
    encrypted_data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, ONDCCryptoError> {
    // Validate key length (AES-256 requires 32 bytes)
    if key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: key.len(),
        });
    }

    // Validate encrypted data length (must be multiple of AES block size)
    if encrypted_data.len() % 16 != 0 {
        return Err(ONDCCryptoError::ConfigError(format!(
            "Invalid encrypted data length: expected multiple of 16, got {}",
            encrypted_data.len()
        )));
    }

    // Create AES-256 cipher
    let cipher = Aes256::new_from_slice(key).map_err(|e| {
        ONDCCryptoError::ConfigError(format!("AES-256 setup failed: {}", e))
    })?;

    // Decrypt the data block by block (ECB mode)
    let mut decrypted = Vec::with_capacity(encrypted_data.len());

    for chunk in encrypted_data.chunks(16) {
        if chunk.len() != 16 {
            return Err(ONDCCryptoError::ConfigError(
                "Invalid block size in encrypted data".to_string(),
            ));
        }

        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted.extend_from_slice(block.as_slice());
    }

    Ok(decrypted)
}

/// Encrypt data using AES-256-ECB mode.
///
/// This function encrypts data using AES-256-ECB mode.
/// It's specifically designed for generating test challenges for ONDC testing.
///
/// # Arguments
///
/// * `data` - The data to encrypt
/// * `key` - The 256-bit (32-byte) encryption key
///
/// # Returns
///
/// Returns the encrypted data as a byte vector, or an error if encryption fails.
///
/// # Errors
///
/// Returns an error if:
/// - The key length is not 32 bytes (256 bits)
/// - The encryption operation fails
///
/// # Security Notes
///
/// - ECB mode is generally not recommended for new applications due to
///   its lack of semantic security. However, it's required for ONDC
///   compatibility.
/// - The key should be handled securely and zeroized after use
/// - This function is primarily intended for testing purposes
///
/// # Examples
///
/// ```rust
/// use ondc_crypto_algorithms::encrypt_aes256_ecb;
///
/// let data = b"test challenge data";
/// let key = [0u8; 32]; // 256-bit key
/// let encrypted = encrypt_aes256_ecb(data, &key).unwrap();
/// ```
pub fn encrypt_aes256_ecb(
    data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, ONDCCryptoError> {
    // Validate key length (AES-256 requires 32 bytes)
    if key.len() != 32 {
        return Err(ONDCCryptoError::InvalidKeyLength {
            expected: 32,
            got: key.len(),
        });
    }

    // Create AES-256 cipher
    let cipher = Aes256::new_from_slice(key).map_err(|e| {
        ONDCCryptoError::ConfigError(format!("AES-256 setup failed: {}", e))
    })?;

    // Pad data to be multiple of 16 bytes (AES block size)
    let mut padded_data = data.to_vec();
    let padding_needed = (16 - (padded_data.len() % 16)) % 16;
    if padding_needed > 0 {
        padded_data.extend(std::iter::repeat(padding_needed as u8).take(padding_needed));
    }

    // Encrypt the data block by block (ECB mode)
    let mut encrypted = Vec::with_capacity(padded_data.len());

    for chunk in padded_data.chunks(16) {
        if chunk.len() != 16 {
            return Err(ONDCCryptoError::ConfigError(
                "Invalid block size in data".to_string(),
            ));
        }

        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted.extend_from_slice(block.as_slice());
    }

    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_ecb_decryption() {
        // Test with known key and data
        let key = [0u8; 32];
        let encrypted_data = [0u8; 32]; // This would be actual encrypted data in practice
        
        let result = decrypt_aes256_ecb(&encrypted_data, &key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0u8; 16]; // Wrong length
        let encrypted_data = [0u8; 32];
        
        let result = decrypt_aes256_ecb(&encrypted_data, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_data_length() {
        let key = [0u8; 32];
        let encrypted_data = [0u8; 31]; // Not multiple of 16
        
        let result = decrypt_aes256_ecb(&encrypted_data, &key);
        assert!(result.is_err());
    }
} 
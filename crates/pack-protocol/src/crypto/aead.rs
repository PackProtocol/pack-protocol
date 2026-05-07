// Implements: AES-256-GCM authenticated encryption with associated data
// Source: NIST SP 800-38D

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};

use crate::errors::{Result, PackError};

const NONCE_SIZE: usize = 12;

/// Encrypt plaintext using AES-256-GCM.
///
/// - `key`: 32-byte AES-256 key
/// - `nonce`: 12-byte nonce (must be unique per key)
/// - `plaintext`: data to encrypt
/// - `ad`: associated data authenticated but not encrypted
///
/// Returns ciphertext with appended 16-byte authentication tag.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| PackError::Crypto(format!("AES-GCM key init failed: {e}")))?;

    let gcm_nonce = Nonce::<Aes256Gcm>::from_slice(nonce);

    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad: ad,
    };

    cipher
        .encrypt(gcm_nonce, payload)
        .map_err(|e| PackError::Crypto(format!("AES-GCM encrypt failed: {e}")))
}

/// Decrypt ciphertext using AES-256-GCM.
///
/// - `key`: 32-byte AES-256 key
/// - `nonce`: 12-byte nonce (same as used for encryption)
/// - `ciphertext`: data to decrypt (includes appended 16-byte authentication tag)
/// - `ad`: associated data (must match what was used during encryption)
///
/// Returns plaintext on success, or error if authentication fails.
pub fn decrypt(key: &[u8; 32], nonce: &[u8; NONCE_SIZE], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| PackError::Crypto(format!("AES-GCM key init failed: {e}")))?;

    let gcm_nonce = Nonce::<Aes256Gcm>::from_slice(nonce);

    let payload = aes_gcm::aead::Payload {
        msg: ciphertext,
        aad: ad,
    };

    cipher
        .decrypt(gcm_nonce, payload)
        .map_err(|_| PackError::InvalidMac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"hello, world!";
        let ad = b"associated data";

        let ciphertext = encrypt(&key, &nonce, plaintext, ad).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        let decrypted = decrypt(&key, &nonce, &ciphertext, ad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0x01u8; 12];

        let ciphertext = encrypt(&key, &nonce, b"secret", b"").unwrap();
        assert!(decrypt(&wrong_key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_wrong_ad_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];

        let ciphertext = encrypt(&key, &nonce, b"secret", b"correct ad").unwrap();
        assert!(decrypt(&key, &nonce, &ciphertext, b"wrong ad").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];

        let mut ciphertext = encrypt(&key, &nonce, b"secret", b"").unwrap();
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt(&key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];

        let ciphertext = encrypt(&key, &nonce, b"", b"only ad").unwrap();
        // Ciphertext should be just the 16-byte tag
        assert_eq!(ciphertext.len(), 16);

        let decrypted = decrypt(&key, &nonce, &ciphertext, b"only ad").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_empty_ad() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];

        let ciphertext = encrypt(&key, &nonce, b"data", b"").unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext, b"").unwrap();
        assert_eq!(decrypted, b"data");
    }

}

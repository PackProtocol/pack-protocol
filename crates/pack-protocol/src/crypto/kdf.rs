// Implements: HKDF-SHA256 per RFC 5869 Sections 2.2-2.3
// Extract: PRK = HMAC-SHA256(salt, IKM)
// Expand: iterate HMAC-SHA256(PRK, T(i-1) || info || i) to produce output keying material

use hkdf::Hkdf;
use sha2::Sha256;

use crate::errors::{Result, PackError};

/// Derive output keying material using HKDF-SHA256.
///
/// Parameters match RFC 5869:
/// - `ikm`: input keying material
/// - `salt`: optional salt (use &[] for no salt, HKDF will use a zero-filled salt)
/// - `info`: context and application specific information
/// - `output_len`: desired length of output keying material in bytes
pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|e| PackError::Crypto(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}

/// Derive exactly 64 bytes of output keying material, returning as two 32-byte arrays.
/// Used by KDF_RK in the Double Ratchet (spec §2.2) to split into (new_root_key, new_chain_key).
pub fn hkdf_derive_pair(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let output = hkdf_derive(ikm, salt, info, 64)?;
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&output[..32]);
    second.copy_from_slice(&output[32..64]);
    Ok((first, second))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 Appendix A - Test Case 1
    #[test]
    fn test_rfc5869_case1() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        ).unwrap();

        let okm = hkdf_derive(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    // RFC 5869 Appendix A - Test Case 2
    #[test]
    fn test_rfc5869_case2() {
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f"
        ).unwrap();
        let salt = hex::decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        ).unwrap();
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ).unwrap();
        let expected_okm = hex::decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
        ).unwrap();

        let okm = hkdf_derive(&ikm, &salt, &info, 82).unwrap();
        assert_eq!(okm, expected_okm);
    }

    // RFC 5869 Appendix A - Test Case 3
    #[test]
    fn test_rfc5869_case3() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = b"";
        let info = b"";
        let expected_okm = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8"
        ).unwrap();

        let okm = hkdf_derive(&ikm, salt, info, 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_derive_pair() {
        let ikm = b"some key material";
        let salt = b"some salt";
        let info = b"some info";

        let (first, second) = hkdf_derive_pair(ikm, salt, info).unwrap();
        let full = hkdf_derive(ikm, salt, info, 64).unwrap();

        assert_eq!(&first, &full[..32]);
        assert_eq!(&second, &full[32..64]);
    }

}

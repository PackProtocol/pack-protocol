// Implements: HMAC-SHA256 per RFC 2104
// Used by the Double Ratchet for chain key derivation (KDF_CK)

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256(key, data).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify an HMAC-SHA256 tag in constant time.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    let computed = hmac_sha256(key, data);
    use subtle::ConstantTimeEq;
    computed.ct_eq(expected).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_deterministic() {
        let key = b"my secret key";
        let data = b"message to authenticate";

        let tag1 = hmac_sha256(key, data);
        let tag2 = hmac_sha256(key, data);

        assert_eq!(tag1, tag2);
    }

    #[test]
    fn test_hmac_different_keys() {
        let data = b"same message";
        let tag1 = hmac_sha256(b"key1", data);
        let tag2 = hmac_sha256(b"key2", data);

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_hmac_different_messages() {
        let key = b"same key";
        let tag1 = hmac_sha256(key, b"message1");
        let tag2 = hmac_sha256(key, b"message2");

        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_hmac_verify_correct() {
        let key = b"verify key";
        let data = b"verify data";
        let tag = hmac_sha256(key, data);

        assert!(hmac_sha256_verify(key, data, &tag));
    }

    #[test]
    fn test_hmac_verify_wrong_tag() {
        let key = b"verify key";
        let data = b"verify data";
        let mut tag = hmac_sha256(key, data);
        tag[0] ^= 0xFF;

        assert!(!hmac_sha256_verify(key, data, &tag));
    }

    // RFC 4231 Test Case 1 (HMAC-SHA256)
    #[test]
    fn test_rfc4231_case1() {
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let expected = hex::decode(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        ).unwrap();

        let tag = hmac_sha256(&key, data);
        assert_eq!(&tag[..], &expected[..]);
    }

    // RFC 4231 Test Case 2 (HMAC-SHA256)
    #[test]
    fn test_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex::decode(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        ).unwrap();

        let tag = hmac_sha256(key, data);
        assert_eq!(&tag[..], &expected[..]);
    }
}

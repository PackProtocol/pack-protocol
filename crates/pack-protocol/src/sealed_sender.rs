// Implements: Sealed Sender envelope encryption using a Noise NK handshake
// Source: noiseprotocol.org/noise.html (Section 7.4, pattern NK)
// The NK pattern hides the sender from the server while binding the envelope
// to the recipient's static key via the Noise handshake hash chain.

use sha2::{Sha256, Digest};

use zeroize::Zeroizing;

use crate::crypto::curve::{self, KeyPair, PublicKey};
use crate::crypto::{aead, kdf};
use crate::errors::{Result, PackError};
use crate::keys::{IdentityKey, IdentityKeyPair};

/// Server-signed certificate binding a sender to their identity key.
#[derive(Clone)]
pub struct SenderCertificate {
    pub sender_uuid: String,
    pub sender_device_id: u32,
    pub sender_identity: IdentityKey,
    pub expiration: u64,
    pub server_certificate: ServerCertificate,
    pub signature: Vec<u8>,
}

impl SenderCertificate {
    pub fn serialize_content(&self) -> Vec<u8> {
        let uuid_bytes = self.sender_uuid.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&(uuid_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(uuid_bytes);
        out.extend_from_slice(&self.sender_device_id.to_be_bytes());
        out.extend_from_slice(self.sender_identity.as_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out
    }

    pub fn serialize(&self) -> Vec<u8> {
        let content = self.serialize_content();
        let server_cert = self.server_certificate.serialize();
        let mut out = Vec::new();
        out.extend_from_slice(&(content.len() as u32).to_be_bytes());
        out.extend_from_slice(&content);
        out.extend_from_slice(&(server_cert.len() as u32).to_be_bytes());
        out.extend_from_slice(&server_cert);
        out.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        let content_len = read_u32(data, &mut offset)? as usize;
        if data.len() < offset + content_len {
            return Err(PackError::InvalidCertificate);
        }
        let content = &data[offset..offset + content_len];
        offset += content_len;

        // Parse content
        let mut co = 0;
        let uuid_len = read_u32(content, &mut co)? as usize;
        if content.len() < co + uuid_len {
            return Err(PackError::InvalidCertificate);
        }
        let sender_uuid = String::from_utf8(content[co..co + uuid_len].to_vec())
            .map_err(|_| PackError::InvalidCertificate)?;
        co += uuid_len;

        let sender_device_id = read_u32(content, &mut co)?;

        if content.len() < co + 32 {
            return Err(PackError::InvalidCertificate);
        }
        let mut ik_bytes = [0u8; 32];
        ik_bytes.copy_from_slice(&content[co..co + 32]);
        co += 32;

        let expiration = read_u64(content, &mut co)?;

        let server_cert_len = read_u32(data, &mut offset)? as usize;
        if data.len() < offset + server_cert_len {
            return Err(PackError::InvalidCertificate);
        }
        let server_certificate = ServerCertificate::deserialize(&data[offset..offset + server_cert_len])?;
        offset += server_cert_len;

        let sig_len = read_u32(data, &mut offset)? as usize;
        if data.len() < offset + sig_len {
            return Err(PackError::InvalidCertificate);
        }
        let signature = data[offset..offset + sig_len].to_vec();

        Ok(Self {
            sender_uuid,
            sender_device_id,
            sender_identity: IdentityKey::from_bytes(ik_bytes)?,
            expiration,
            server_certificate,
            signature,
        })
    }
}

/// The server's signing certificate.
#[derive(Clone)]
pub struct ServerCertificate {
    pub key: PublicKey,
    pub id: u32,
}

impl ServerCertificate {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(36);
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 36 {
            return Err(PackError::InvalidCertificate);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[..32]);
        let id = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        Ok(Self {
            key: PublicKey::from_bytes_validated(key_bytes)?,
            id,
        })
    }
}

/// The encrypted sealed sender envelope.
pub struct SealedSenderMessage {
    pub version: u8,
    pub ephemeral_public: PublicKey,
    pub encrypted_content: Vec<u8>,
}

/// Result of decrypting a sealed sender message.
pub struct SealedSenderResult {
    pub sender_uuid: String,
    pub sender_device_id: u32,
    pub plaintext: Vec<u8>,
}

/// Noise NK protocol name — determines the initial handshake hash.
const NOISE_NK_PROTOCOL: &[u8] = b"Noise_NK_25519_AESGCM_SHA256";

fn mix_hash(h: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(h);
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn mix_key(ck: &[u8; 32], ikm: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    kdf::hkdf_derive_pair(ikm, ck, b"")
}

fn noise_nk_init(responder_static: &PublicKey) -> ([u8; 32], [u8; 32]) {
    let protocol_hash = {
        let mut hasher = Sha256::new();
        hasher.update(NOISE_NK_PROTOCOL);
        let mut h = [0u8; 32];
        h.copy_from_slice(&hasher.finalize());
        h
    };
    let ck = protocol_hash;
    let h = mix_hash(&protocol_hash, responder_static.as_bytes());
    (h, ck)
}

/// Encrypt a message into a Sealed Sender envelope using a Noise NK handshake.
///
/// Noise NK pattern (noiseprotocol.org/noise.html §7.4):
///   <- s                (recipient's static key is known)
///   -> e, es            (sender sends ephemeral, DH with recipient's static)
///
/// 1. Initialize handshake hash with protocol name and recipient's public key
/// 2. Generate ephemeral key pair, MixHash the ephemeral public key
/// 3. MixKey with DH(ephemeral, recipient_static) to derive encryption key
/// 4. EncryptAndHash the payload with AES-256-GCM
/// 5. Sender signs the final handshake hash with their identity key (identity binding)
/// 6. Output: version || ephemeral_public || ciphertext
///
/// Payload format: cert_len || cert || identity_signature (64 bytes) || inner_message
/// The identity_signature proves the sender holds the private key for cert.sender_identity.
pub fn sealed_sender_encrypt(
    sender_identity: &IdentityKeyPair,
    sender_certificate: &SenderCertificate,
    recipient_identity: &IdentityKey,
    inner_message: &[u8],
    current_time: u64,
) -> Result<Vec<u8>> {
    if sender_certificate.expiration < current_time {
        return Err(PackError::ExpiredCertificate);
    }

    // Noise NK init: h = SHA-256(protocol_name), h = MixHash(h, rs)
    let (mut h, ck) = noise_nk_init(recipient_identity.public_key());

    // -> e: generate ephemeral, MixHash
    let ephemeral = KeyPair::generate();
    h = mix_hash(&h, ephemeral.public.as_bytes());

    // -> es: DH(e, rs), MixKey
    let dh_result = Zeroizing::new(curve::dh(&ephemeral.private, recipient_identity.public_key())?);
    let (_ck, k) = mix_key(&ck, &*dh_result)?;

    // Sender signs the handshake hash to prove identity key ownership
    let identity_signature = sender_identity.sign(&h);

    // Build plaintext payload: cert_len || cert || identity_signature || inner_message
    let cert_bytes = sender_certificate.serialize();
    let mut payload = Vec::with_capacity(4 + cert_bytes.len() + 64 + inner_message.len());
    payload.extend_from_slice(&(cert_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&cert_bytes);
    payload.extend_from_slice(&identity_signature);
    payload.extend_from_slice(inner_message);

    // EncryptAndHash: AEAD(k, nonce=0, payload, ad=h)
    let nonce = [0u8; 12];
    let encrypted = aead::encrypt(&k, &nonce, &payload, &h)?;

    // Complete Noise handshake transcript
    h = mix_hash(&h, &encrypted);
    let _ = h;

    let msg = SealedSenderMessage {
        version: 2,
        ephemeral_public: ephemeral.public.clone(),
        encrypted_content: encrypted,
    };

    Ok(serialize_sealed_sender(&msg))
}

/// Decrypt a Sealed Sender envelope using the Noise NK handshake.
///
/// Mirrors the encrypt side:
/// 1. Initialize handshake hash with protocol name and our public key
/// 2. MixHash the received ephemeral public key
/// 3. MixKey with DH(our_static, ephemeral) to derive decryption key
/// 4. DecryptAndHash the ciphertext using the handshake hash as AD
/// 5. Parse and validate the sender certificate
/// 6. Verify the sender's identity signature over the handshake hash (identity binding)
pub fn sealed_sender_decrypt(
    our_identity: &IdentityKeyPair,
    ciphertext: &[u8],
    trust_root: &PublicKey,
    current_time: u64,
) -> Result<SealedSenderResult> {
    let msg = deserialize_sealed_sender(ciphertext)?;

    // Noise NK init: same as encrypt side, using our public key as rs
    let (mut h, ck) = noise_nk_init(our_identity.public.public_key());

    // -> e: MixHash the received ephemeral
    h = mix_hash(&h, msg.ephemeral_public.as_bytes());

    // -> es: DH(s, e), MixKey
    let dh_result = Zeroizing::new(curve::dh(our_identity.private_key(), &msg.ephemeral_public)?);
    let (_ck, k) = mix_key(&ck, &*dh_result)?;

    // DecryptAndHash: AEAD_decrypt(k, nonce=0, ciphertext, ad=h)
    let nonce = [0u8; 12];
    let h_at_sign = h;
    let payload = aead::decrypt(&k, &nonce, &msg.encrypted_content, &h_at_sign)?;

    // Complete Noise handshake transcript
    let _h = mix_hash(&h_at_sign, &msg.encrypted_content);

    // Parse payload: cert_len || cert || identity_signature (64 bytes) || inner_message
    if payload.len() < 4 {
        return Err(PackError::InvalidMessage("sealed sender payload too short".into()));
    }
    let mut offset = 0;
    let cert_len = read_u32(&payload, &mut offset)? as usize;
    if payload.len() < offset + cert_len {
        return Err(PackError::InvalidMessage("sealed sender certificate truncated".into()));
    }
    let cert = SenderCertificate::deserialize(&payload[offset..offset + cert_len])?;
    offset += cert_len;

    // Extract identity signature (64 bytes)
    if payload.len() < offset + 64 {
        return Err(PackError::InvalidMessage("sealed sender identity signature missing".into()));
    }
    let mut identity_sig = [0u8; 64];
    identity_sig.copy_from_slice(&payload[offset..offset + 64]);
    offset += 64;

    let inner_message = payload[offset..].to_vec();

    // Validate certificate
    if cert.expiration < current_time {
        return Err(PackError::ExpiredCertificate);
    }

    let cert_content = cert.serialize_content();
    if cert.signature.len() != 64 {
        return Err(PackError::InvalidCertificate);
    }
    let mut server_sig = [0u8; 64];
    server_sig.copy_from_slice(&cert.signature);
    curve::xeddsa_verify(trust_root, &cert_content, &server_sig)?;

    // Verify sender identity binding: the sender signed the handshake hash h
    // (captured before EncryptAndHash completed the transcript) with their identity key.
    curve::xeddsa_verify(cert.sender_identity.public_key(), &h_at_sign, &identity_sig)?;

    Ok(SealedSenderResult {
        sender_uuid: cert.sender_uuid,
        sender_device_id: cert.sender_device_id,
        plaintext: inner_message,
    })
}

fn serialize_sealed_sender(msg: &SealedSenderMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + msg.encrypted_content.len());
    out.push(msg.version);
    out.extend_from_slice(msg.ephemeral_public.as_bytes());
    out.extend_from_slice(&msg.encrypted_content);
    out
}

fn deserialize_sealed_sender(data: &[u8]) -> Result<SealedSenderMessage> {
    if data.len() < 33 {
        return Err(PackError::InvalidMessage("sealed sender too short".into()));
    }
    let version = data[0];
    let mut eph_bytes = [0u8; 32];
    eph_bytes.copy_from_slice(&data[1..33]);
    let encrypted_content = data[33..].to_vec();
    Ok(SealedSenderMessage {
        version,
        ephemeral_public: PublicKey::from_bytes_validated(eph_bytes)?,
        encrypted_content,
    })
}

fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32> {
    if data.len() < *offset + 4 {
        return Err(PackError::InvalidMessage("unexpected end of data".into()));
    }
    let val = u32::from_be_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]);
    *offset += 4;
    Ok(val)
}

fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64> {
    if data.len() < *offset + 8 {
        return Err(PackError::InvalidMessage("unexpected end of data".into()));
    }
    let val = u64::from_be_bytes([
        data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3],
        data[*offset + 4], data[*offset + 5], data[*offset + 6], data[*offset + 7],
    ]);
    *offset += 8;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_certificate(
        sender_identity: &IdentityKeyPair,
        server_key: &crate::crypto::curve::PrivateKey,
        expiration: u64,
    ) -> SenderCertificate {
        let server_cert = ServerCertificate {
            key: {
                // Derive the server's public key from its private key via DH with basepoint
                // We just need any public key for the server
                let kp = KeyPair::generate();
                kp.public.clone()
            },
            id: 1,
        };

        let mut cert = SenderCertificate {
            sender_uuid: "alice-uuid".to_string(),
            sender_device_id: 1,
            sender_identity: sender_identity.public.clone(),
            expiration,
            server_certificate: server_cert,
            signature: Vec::new(),
        };

        // Sign the certificate content with the server's key
        let content = cert.serialize_content();
        let sig = curve::xeddsa_sign(server_key, &content);
        cert.signature = sig.to_vec();

        cert
    }

    fn create_server_keypair() -> KeyPair {
        KeyPair::generate()
    }

    #[test]
    fn test_sealed_sender_roundtrip() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = create_server_keypair();

        let cert = create_test_certificate(&alice_identity, &server_kp.private, 2000);
        let inner_message = b"hello bob, this is a secret message";

        let encrypted = sealed_sender_encrypt(
            &alice_identity,
            &cert,
            &bob_identity.public,
            inner_message,
            1000,
        ).unwrap();

        let result = sealed_sender_decrypt(
            &bob_identity,
            &encrypted,
            &server_kp.public,
            1000,
        ).unwrap();

        assert_eq!(result.sender_uuid, "alice-uuid");
        assert_eq!(result.sender_device_id, 1);
        assert_eq!(result.plaintext, inner_message);
    }

    #[test]
    fn test_sealed_sender_expired_certificate_encrypt() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = create_server_keypair();

        let cert = create_test_certificate(&alice_identity, &server_kp.private, 500);

        let result = sealed_sender_encrypt(
            &alice_identity,
            &cert,
            &bob_identity.public,
            b"test",
            1000, // current time > expiration
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_sealed_sender_expired_certificate_decrypt() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = create_server_keypair();

        let cert = create_test_certificate(&alice_identity, &server_kp.private, 1500);

        let encrypted = sealed_sender_encrypt(
            &alice_identity,
            &cert,
            &bob_identity.public,
            b"test",
            1000,
        ).unwrap();

        // Decrypt with a time after expiration
        let result = sealed_sender_decrypt(
            &bob_identity,
            &encrypted,
            &server_kp.public,
            2000,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_sealed_sender_wrong_recipient_fails() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let charlie_identity = IdentityKeyPair::generate();
        let server_kp = create_server_keypair();

        let cert = create_test_certificate(&alice_identity, &server_kp.private, 2000);

        let encrypted = sealed_sender_encrypt(
            &alice_identity,
            &cert,
            &bob_identity.public,
            b"for bob only",
            1000,
        ).unwrap();

        // Charlie tries to decrypt — should fail
        let result = sealed_sender_decrypt(
            &charlie_identity,
            &encrypted,
            &server_kp.public,
            1000,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_sealed_sender_wrong_trust_root_fails() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = create_server_keypair();
        let wrong_server_kp = create_server_keypair();

        let cert = create_test_certificate(&alice_identity, &server_kp.private, 2000);

        let encrypted = sealed_sender_encrypt(
            &alice_identity,
            &cert,
            &bob_identity.public,
            b"test",
            1000,
        ).unwrap();

        // Decrypt with wrong trust root
        let result = sealed_sender_decrypt(
            &bob_identity,
            &encrypted,
            &wrong_server_kp.public,
            1000,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_sealed_sender_tampered_fails() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = create_server_keypair();

        let cert = create_test_certificate(&alice_identity, &server_kp.private, 2000);

        let mut encrypted = sealed_sender_encrypt(
            &alice_identity,
            &cert,
            &bob_identity.public,
            b"test",
            1000,
        ).unwrap();

        // Tamper with encrypted content
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }

        let result = sealed_sender_decrypt(
            &bob_identity,
            &encrypted,
            &server_kp.public,
            1000,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_server_certificate_roundtrip() {
        let kp = KeyPair::generate();
        let cert = ServerCertificate {
            key: kp.public.clone(),
            id: 42,
        };

        let bytes = cert.serialize();
        let decoded = ServerCertificate::deserialize(&bytes).unwrap();
        assert_eq!(decoded.id, 42);
    }

    #[test]
    fn test_sender_certificate_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let server_kp = create_server_keypair();
        let cert = create_test_certificate(&identity, &server_kp.private, 5000);

        let bytes = cert.serialize();
        let decoded = SenderCertificate::deserialize(&bytes).unwrap();

        assert_eq!(decoded.sender_uuid, "alice-uuid");
        assert_eq!(decoded.sender_device_id, 1);
        assert_eq!(decoded.expiration, 5000);
    }

    #[test]
    fn test_sealed_sender_forged_identity_rejected() {
        let alice_identity = IdentityKeyPair::generate();
        let eve_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = create_server_keypair();

        let alice_cert = create_test_certificate(&alice_identity, &server_kp.private, 2000);

        // Eve uses her own identity key but alice's certificate
        let result = sealed_sender_encrypt(
            &eve_identity,
            &alice_cert,
            &bob_identity.public,
            b"pretending to be alice",
            1000,
        ).unwrap();

        // Bob decrypts — identity signature won't verify because eve signed
        // with her key but the cert says alice's identity
        let decrypt_result = sealed_sender_decrypt(
            &bob_identity,
            &result,
            &server_kp.public,
            1000,
        );

        assert!(decrypt_result.is_err(), "forged sender identity must be rejected");
    }

}

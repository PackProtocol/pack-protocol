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
        let server_cert_bytes = self.server_certificate.serialize();
        let mut out = Vec::new();
        out.extend_from_slice(&(uuid_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(uuid_bytes);
        out.extend_from_slice(&self.sender_device_id.to_be_bytes());
        out.extend_from_slice(self.sender_identity.as_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out.extend_from_slice(&(server_cert_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&server_cert_bytes);
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
    // Noise spec §5.2: if len(protocol_name) <= HASHLEN, zero-pad to HASHLEN
    let mut protocol_hash = [0u8; 32];
    protocol_hash[..NOISE_NK_PROTOCOL.len()].copy_from_slice(NOISE_NK_PROTOCOL);
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
    if version != 2 {
        return Err(PackError::InvalidMessage(
            format!("unsupported sealed sender version: {version}"),
        ));
    }
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

// ── Protobuf cert support ──
// Server sends sender certificates in protobuf format. The inner cert bytes
// (which the server signed) differ from the Rust binary serialize_content().
// These functions handle raw protobuf certs end-to-end so the signature
// over the original bytes is preserved.

struct ProtobufSenderCert {
    inner_cert_bytes: Vec<u8>,
    signature: Vec<u8>,
    sender_uuid: String,
    sender_device_id: u32,
    sender_identity: IdentityKey,
    expiration: u64,
}

fn read_protobuf_varint(data: &[u8], offset: usize) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut pos = offset;
    loop {
        if pos >= data.len() { return Err(PackError::InvalidCertificate); }
        let byte = data[pos];
        pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 { break; }
        shift += 7;
        if shift >= 64 { return Err(PackError::InvalidCertificate); }
    }
    Ok((result, pos))
}

fn parse_protobuf_sender_cert(data: &[u8]) -> Result<ProtobufSenderCert> {
    let mut inner_cert_bytes: Option<Vec<u8>> = None;
    let mut signature: Option<Vec<u8>> = None;
    let mut offset = 0;

    while offset < data.len() {
        let tag = data[offset];
        offset += 1;
        let field_number = (tag >> 3) as usize;
        let wire_type = (tag & 0x07) as usize;
        match wire_type {
            0 => { let (_, o) = read_protobuf_varint(data, offset)?; offset = o; }
            1 => { offset += 8; if offset > data.len() { return Err(PackError::InvalidCertificate); } }
            2 => {
                let (len, o) = read_protobuf_varint(data, offset)?;
                offset = o;
                let end = offset + len as usize;
                if end > data.len() { return Err(PackError::InvalidCertificate); }
                match field_number {
                    1 => inner_cert_bytes = Some(data[offset..end].to_vec()),
                    2 => signature = Some(data[offset..end].to_vec()),
                    _ => {}
                }
                offset = end;
            }
            5 => { offset += 4; if offset > data.len() { return Err(PackError::InvalidCertificate); } }
            _ => return Err(PackError::InvalidCertificate),
        }
    }

    let inner = inner_cert_bytes.ok_or(PackError::InvalidCertificate)?;
    let sig = signature.ok_or(PackError::InvalidCertificate)?;

    let mut uuid: Option<String> = None;
    let mut device_id: u32 = 0;
    let mut expiration: u64 = 0;
    let mut identity_key_bytes: Option<Vec<u8>> = None;
    offset = 0;

    while offset < inner.len() {
        let tag = inner[offset];
        offset += 1;
        let field_number = (tag >> 3) as usize;
        let wire_type = (tag & 0x07) as usize;
        match wire_type {
            0 => {
                let (val, o) = read_protobuf_varint(&inner, offset)?;
                offset = o;
                match field_number {
                    2 | 3 => device_id = val as u32,
                    4 => expiration = val,
                    _ => {}
                }
            }
            1 => {
                if offset + 8 > inner.len() { return Err(PackError::InvalidCertificate); }
                if field_number == 3 || field_number == 4 {
                    expiration = u64::from_le_bytes(inner[offset..offset + 8].try_into().unwrap());
                }
                offset += 8;
            }
            2 => {
                let (len, o) = read_protobuf_varint(&inner, offset)?;
                offset = o;
                let end = offset + len as usize;
                if end > inner.len() { return Err(PackError::InvalidCertificate); }
                match field_number {
                    1 | 6 => {
                        let bytes = &inner[offset..end];
                        if let Ok(s) = String::from_utf8(bytes.to_vec()) {
                            if !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b > 0x1F) {
                                uuid = Some(s);
                            }
                        }
                    }
                    4 | 5 => {
                        let len = end - offset;
                        if len == 32 || len == 33 {
                            identity_key_bytes = Some(inner[offset..end].to_vec());
                        }
                    }
                    _ => {}
                }
                offset = end;
            }
            5 => { offset += 4; if offset > inner.len() { return Err(PackError::InvalidCertificate); } }
            _ => return Err(PackError::InvalidCertificate),
        }
    }

    let ik_raw = identity_key_bytes.ok_or(PackError::InvalidCertificate)?;
    let ik_slice = if ik_raw.len() == 33 && ik_raw[0] == 0x05 { &ik_raw[1..] } else { &ik_raw };
    let ik_arr: [u8; 32] = ik_slice.try_into().map_err(|_| PackError::InvalidCertificate)?;

    Ok(ProtobufSenderCert {
        inner_cert_bytes: inner,
        signature: sig,
        sender_uuid: uuid.ok_or(PackError::InvalidCertificate)?,
        sender_device_id: device_id,
        sender_identity: IdentityKey::from_bytes(ik_arr)?,
        expiration,
    })
}

pub fn sealed_sender_encrypt_raw_cert(
    sender_identity: &IdentityKeyPair,
    raw_cert_blob: &[u8],
    recipient_identity: &IdentityKey,
    inner_message: &[u8],
    current_time: u64,
) -> Result<Vec<u8>> {
    let cert = parse_protobuf_sender_cert(raw_cert_blob)?;
    if cert.expiration < current_time {
        return Err(PackError::ExpiredCertificate);
    }

    let (mut h, ck) = noise_nk_init(recipient_identity.public_key());
    let ephemeral = KeyPair::generate();
    h = mix_hash(&h, ephemeral.public.as_bytes());
    let dh_result = Zeroizing::new(curve::dh(&ephemeral.private, recipient_identity.public_key())?);
    let (_ck, k) = mix_key(&ck, &*dh_result)?;
    let identity_signature = sender_identity.sign(&h);

    let mut payload = Vec::with_capacity(4 + raw_cert_blob.len() + 64 + inner_message.len());
    payload.extend_from_slice(&(raw_cert_blob.len() as u32).to_be_bytes());
    payload.extend_from_slice(raw_cert_blob);
    payload.extend_from_slice(&identity_signature);
    payload.extend_from_slice(inner_message);

    let nonce = [0u8; 12];
    let encrypted = aead::encrypt(&k, &nonce, &payload, &h)?;
    h = mix_hash(&h, &encrypted);
    let _ = h;

    Ok(serialize_sealed_sender(&SealedSenderMessage {
        version: 2,
        ephemeral_public: ephemeral.public.clone(),
        encrypted_content: encrypted,
    }))
}

pub fn sealed_sender_decrypt_raw_cert(
    our_identity: &IdentityKeyPair,
    ciphertext: &[u8],
    trust_root: &PublicKey,
    current_time: u64,
) -> Result<SealedSenderResult> {
    let msg = deserialize_sealed_sender(ciphertext)?;

    let (mut h, ck) = noise_nk_init(our_identity.public.public_key());
    h = mix_hash(&h, msg.ephemeral_public.as_bytes());
    let dh_result = Zeroizing::new(curve::dh(our_identity.private_key(), &msg.ephemeral_public)?);
    let (_ck, k) = mix_key(&ck, &*dh_result)?;

    let nonce = [0u8; 12];
    let h_at_sign = h;
    let payload = aead::decrypt(&k, &nonce, &msg.encrypted_content, &h_at_sign)?;
    let _h = mix_hash(&h_at_sign, &msg.encrypted_content);

    if payload.len() < 4 {
        return Err(PackError::InvalidMessage("sealed sender payload too short".into()));
    }
    let mut offset = 0;
    let cert_len = read_u32(&payload, &mut offset)? as usize;
    if payload.len() < offset + cert_len {
        return Err(PackError::InvalidMessage("sealed sender certificate truncated".into()));
    }
    let cert = parse_protobuf_sender_cert(&payload[offset..offset + cert_len])?;
    offset += cert_len;

    if payload.len() < offset + 64 {
        return Err(PackError::InvalidMessage("sealed sender identity signature missing".into()));
    }
    let mut identity_sig = [0u8; 64];
    identity_sig.copy_from_slice(&payload[offset..offset + 64]);
    offset += 64;
    let inner_message = payload[offset..].to_vec();

    if cert.expiration < current_time {
        return Err(PackError::ExpiredCertificate);
    }

    if cert.signature.len() != 64 {
        return Err(PackError::InvalidCertificate);
    }
    let mut server_sig = [0u8; 64];
    server_sig.copy_from_slice(&cert.signature);
    let server_sig_ok = curve::xeddsa_verify(trust_root, &cert.inner_cert_bytes, &server_sig).is_ok()
        || curve::ed25519_verify_raw(trust_root.as_bytes(), &cert.inner_cert_bytes, &server_sig).is_ok();
    if !server_sig_ok {
        return Err(PackError::InvalidSignature);
    }
    let identity_sig_ok = curve::xeddsa_verify(cert.sender_identity.public_key(), &h_at_sign, &identity_sig).is_ok()
        || curve::ed25519_verify_raw(cert.sender_identity.public_key().as_bytes(), &h_at_sign, &identity_sig).is_ok();
    if !identity_sig_ok {
        return Err(PackError::InvalidSignature);
    }

    Ok(SealedSenderResult {
        sender_uuid: cert.sender_uuid,
        sender_device_id: cert.sender_device_id,
        plaintext: inner_message,
    })
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

    #[test]
    fn test_parse_protobuf_sender_cert_real_format() {
        // Simulates the exact protobuf encoding the real server produces:
        // Outer: field 1 (bytes) = inner cert, field 2 (bytes) = signature
        // Inner: field 1 (string) = UUID, field 3 (varint/uint32) = device_id,
        //        field 4 (fixed64) = expires, field 5 (bytes) = identity_key,
        //        field 6 (message) = signer (ServerCertificate)
        let identity = IdentityKeyPair::generate();
        let ik_bytes = identity.public.as_bytes();

        // Build inner cert protobuf manually
        let mut inner = Vec::new();
        // field 1, wire type 2 (LDS): sender_uuid
        let uuid = "test-user-uuid-1234";
        inner.push((1 << 3) | 2); // tag: field 1, wire type 2
        inner.push(uuid.len() as u8); // length
        inner.extend_from_slice(uuid.as_bytes());
        // field 3, wire type 0 (varint): sender_device_id = 42
        inner.push((3 << 3) | 0); // tag: field 3, wire type 0
        inner.push(42); // varint value 42
        // field 4, wire type 1 (fixed64): expires
        let expires: u64 = 9999999999000;
        inner.push((4 << 3) | 1); // tag: field 4, wire type 1
        inner.extend_from_slice(&expires.to_le_bytes());
        // field 5, wire type 2 (LDS): identity_key
        inner.push((5 << 3) | 2); // tag: field 5, wire type 2
        inner.push(32); // 32 bytes
        inner.extend_from_slice(ik_bytes);
        // field 6, wire type 2 (LDS): signer (ServerCertificate message — realistic size)
        // Real ServerCertificate has: field 1 (bytes, ~70 bytes cert) + field 2 (bytes, 64 bytes sig) ≈ 140 bytes
        let fake_signer = vec![0u8; 140];
        inner.push((6 << 3) | 2); // tag: field 6, wire type 2
        // varint encode signer length (140 > 127, needs 2 bytes)
        let mut signer_len = fake_signer.len();
        while signer_len >= 0x80 { inner.push((signer_len as u8) | 0x80); signer_len >>= 7; }
        inner.push(signer_len as u8);
        inner.extend_from_slice(&fake_signer);

        // Build outer cert protobuf
        let server_kp = KeyPair::generate();
        let sig = curve::xeddsa_sign(&server_kp.private, &inner);

        let mut outer = Vec::new();
        // field 1: certificate (inner cert bytes)
        outer.push((1 << 3) | 2);
        let inner_len = inner.len();
        // varint encode length
        let mut len_val = inner_len;
        while len_val >= 0x80 { outer.push((len_val as u8) | 0x80); len_val >>= 7; }
        outer.push(len_val as u8);
        outer.extend_from_slice(&inner);
        // field 2: signature (64 bytes)
        outer.push((2 << 3) | 2);
        outer.push(64);
        outer.extend_from_slice(&sig);

        let cert = parse_protobuf_sender_cert(&outer).expect("should parse real protobuf format");
        assert_eq!(cert.sender_uuid, uuid);
        assert_eq!(cert.sender_device_id, 42);
        assert_eq!(cert.expiration, expires);
        assert_eq!(cert.sender_identity.as_bytes(), ik_bytes);
        assert_eq!(cert.signature, sig.to_vec());
        assert_eq!(cert.inner_cert_bytes, inner);
    }

    #[test]
    fn test_parse_protobuf_sender_cert_legacy_format() {
        // Legacy field numbering: field 2=device, 3=expires, 4=identity, 5=signer, 6=uuid
        let identity = IdentityKeyPair::generate();
        let ik_bytes = identity.public.as_bytes();

        let mut inner = Vec::new();
        // field 2, wire type 0: device_id = 66
        inner.push((2 << 3) | 0);
        inner.push(66);
        // field 3, wire type 1: expires (fixed64)
        let expires: u64 = 1778971556772;
        inner.push((3 << 3) | 1);
        inner.extend_from_slice(&expires.to_le_bytes());
        // field 4, wire type 2: identity_key (32 bytes)
        inner.push((4 << 3) | 2);
        inner.push(32);
        inner.extend_from_slice(ik_bytes);
        // field 5, wire type 2: signer (nested message, 105 bytes of junk)
        let signer_data = vec![0x0Au8; 105];
        inner.push((5 << 3) | 2);
        inner.push(105);
        inner.extend_from_slice(&signer_data);
        // field 6, wire type 2: uuid (36 chars)
        let uuid = "97ACDAE5-1404-4960-959F-C139E79CF436";
        inner.push((6 << 3) | 2);
        inner.push(uuid.len() as u8);
        inner.extend_from_slice(uuid.as_bytes());

        let server_kp = KeyPair::generate();
        let sig = curve::xeddsa_sign(&server_kp.private, &inner);

        let mut outer = Vec::new();
        outer.push((1 << 3) | 2);
        let mut len_val = inner.len();
        while len_val >= 0x80 { outer.push((len_val as u8) | 0x80); len_val >>= 7; }
        outer.push(len_val as u8);
        outer.extend_from_slice(&inner);
        outer.push((2 << 3) | 2);
        outer.push(64);
        outer.extend_from_slice(&sig);

        let cert = parse_protobuf_sender_cert(&outer).expect("should parse legacy-format cert");
        assert_eq!(cert.sender_uuid, uuid);
        assert_eq!(cert.sender_device_id, 66);
        assert_eq!(cert.expiration, expires);
        assert_eq!(cert.sender_identity.as_bytes(), ik_bytes);
    }
}

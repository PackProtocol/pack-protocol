// Implements: Wire format types for protocol messages
// Source: Derived from X3DH and Double Ratchet protocol specifications

use crate::crypto::curve::PublicKey;
use crate::keys::IdentityKey;
use crate::ratchet::MessageHeader;
use crate::errors::{Result, PackError};

/// A regular encrypted message (after session is established).
/// Contains: version + header + ciphertext
#[derive(Clone)]
pub struct PackMessage {
    pub version: u8,
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

impl PackMessage {
    pub fn new(header: MessageHeader, ciphertext: Vec<u8>) -> Self {
        Self {
            version: 1,
            header,
            ciphertext,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let mut out = Vec::with_capacity(1 + 4 + header_bytes.len() + self.ciphertext.len());
        out.push(self.version);
        out.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(PackError::InvalidMessage("message too short".into()));
        }
        let version = data[0];
        if version != 1 {
            return Err(PackError::InvalidMessage(
                format!("unsupported message version: {version}"),
            ));
        }
        let header_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data.len() < 5 + header_len {
            return Err(PackError::InvalidMessage("message truncated".into()));
        }
        let header = MessageHeader::from_bytes(&data[5..5 + header_len])?;
        let ciphertext = data[5 + header_len..].to_vec();
        Ok(Self { version, header, ciphertext })
    }
}

/// Initial message that includes pre-key information for X3DH session establishment.
#[derive(Clone)]
pub struct PreKeyPackMessage {
    pub version: u8,
    pub signed_pre_key_id: u32,
    pub pre_key_id: Option<u32>,
    pub base_key: PublicKey,
    pub identity_key: IdentityKey,
    pub message: PackMessage,
    pub pq_pre_key_id: Option<u32>,
    pub kem_ciphertext: Option<Vec<u8>>,
}

impl PreKeyPackMessage {
    pub fn new(
        signed_pre_key_id: u32,
        pre_key_id: Option<u32>,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: PackMessage,
    ) -> Self {
        Self {
            version: 1,
            signed_pre_key_id,
            pre_key_id,
            base_key,
            identity_key,
            message,
            pq_pre_key_id: None,
            kem_ciphertext: None,
        }
    }

    pub fn new_pqxdh(
        signed_pre_key_id: u32,
        pre_key_id: Option<u32>,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: PackMessage,
        pq_pre_key_id: u32,
        kem_ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            version: 2,
            signed_pre_key_id,
            pre_key_id,
            base_key,
            identity_key,
            message,
            pq_pre_key_id: Some(pq_pre_key_id),
            kem_ciphertext: Some(kem_ciphertext),
        }
    }

    pub fn is_pqxdh(&self) -> bool {
        self.version == 2
    }

    pub fn serialize(&self) -> Vec<u8> {
        let inner = self.message.serialize();
        let has_pre_key: u8 = if self.pre_key_id.is_some() { 1 } else { 0 };

        let mut out = Vec::with_capacity(1 + 4 + 1 + 4 + 32 + 32 + 4 + inner.len());
        out.push(self.version);
        out.extend_from_slice(&self.signed_pre_key_id.to_be_bytes());
        out.push(has_pre_key);
        if let Some(pk_id) = self.pre_key_id {
            out.extend_from_slice(&pk_id.to_be_bytes());
        }
        out.extend_from_slice(self.base_key.as_bytes());
        out.extend_from_slice(self.identity_key.as_bytes());
        out.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        out.extend_from_slice(&inner);

        if self.version >= 2 {
            if let (Some(pq_id), Some(ref kem_ct)) = (self.pq_pre_key_id, &self.kem_ciphertext) {
                out.extend_from_slice(&pq_id.to_be_bytes());
                out.extend_from_slice(&(kem_ct.len() as u32).to_be_bytes());
                out.extend_from_slice(kem_ct);
            }
        }
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.len() < 1 + 4 + 1 {
            return Err(PackError::InvalidMessage("pre-key message too short".into()));
        }
        let version = data[0];
        if version < 1 || version > 2 {
            return Err(PackError::InvalidMessage(
                format!("unsupported pre-key message version: {version}"),
            ));
        }
        let signed_pre_key_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let has_pre_key = data[5];

        let mut offset = 6;
        let pre_key_id = if has_pre_key == 1 {
            if data.len() < offset + 4 {
                return Err(PackError::InvalidMessage("pre-key message truncated".into()));
            }
            let id = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
            offset += 4;
            Some(id)
        } else {
            None
        };

        if data.len() < offset + 32 + 32 + 4 {
            return Err(PackError::InvalidMessage("pre-key message truncated".into()));
        }
        let mut base_key_bytes = [0u8; 32];
        base_key_bytes.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut identity_key_bytes = [0u8; 32];
        identity_key_bytes.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let inner_len = u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if data.len() < offset + inner_len {
            return Err(PackError::InvalidMessage("pre-key message inner truncated".into()));
        }
        let message = PackMessage::deserialize(&data[offset..offset + inner_len])?;
        offset += inner_len;

        let (pq_pre_key_id, kem_ciphertext) = if version >= 2 && data.len() > offset {
            if data.len() < offset + 4 + 4 {
                return Err(PackError::InvalidMessage("pqxdh fields truncated".into()));
            }
            let pq_id = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
            offset += 4;
            let kem_len = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
            offset += 4;
            if data.len() < offset + kem_len {
                return Err(PackError::InvalidMessage("kem ciphertext truncated".into()));
            }
            (Some(pq_id), Some(data[offset..offset+kem_len].to_vec()))
        } else {
            (None, None)
        };

        Ok(Self {
            version,
            signed_pre_key_id,
            pre_key_id,
            base_key: PublicKey::from_bytes_validated(base_key_bytes)?,
            identity_key: IdentityKey::from_bytes(identity_key_bytes)?,
            message,
            pq_pre_key_id,
            kem_ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::KeyPair;
    use crate::keys::IdentityKeyPair;

    #[test]
    fn test_pack_message_roundtrip() {
        let kp = KeyPair::generate();
        let header = MessageHeader {
            ratchet_key: kp.public,
            prev_chain_length: 5,
            message_number: 12,
        };
        let msg = PackMessage::new(header, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let serialized = msg.serialize();
        let deserialized = PackMessage::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.version, 1);
        assert_eq!(deserialized.header.prev_chain_length, 5);
        assert_eq!(deserialized.header.message_number, 12);
        assert_eq!(deserialized.ciphertext, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_prekey_pack_message_roundtrip() {
        let kp = KeyPair::generate();
        let identity = IdentityKeyPair::generate();
        let header = MessageHeader {
            ratchet_key: kp.public.clone(),
            prev_chain_length: 0,
            message_number: 0,
        };
        let inner = PackMessage::new(header, vec![0xCA, 0xFE]);

        let msg = PreKeyPackMessage::new(1, Some(42), kp.public, identity.public, inner);
        let serialized = msg.serialize();
        let deserialized = PreKeyPackMessage::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.signed_pre_key_id, 1);
        assert_eq!(deserialized.pre_key_id, Some(42));
        assert_eq!(deserialized.message.ciphertext, vec![0xCA, 0xFE]);
    }

    #[test]
    fn test_prekey_pack_message_no_opk() {
        let kp = KeyPair::generate();
        let identity = IdentityKeyPair::generate();
        let header = MessageHeader {
            ratchet_key: kp.public.clone(),
            prev_chain_length: 0,
            message_number: 0,
        };
        let inner = PackMessage::new(header, vec![]);

        let msg = PreKeyPackMessage::new(1, None, kp.public, identity.public, inner);
        let serialized = msg.serialize();
        let deserialized = PreKeyPackMessage::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.pre_key_id, None);
    }

}

// Implements: Sender Keys for group messaging
// Source: Public Sender Keys documentation
//
// Each group member maintains their own sender key chain. When a member wants to
// send to the group, they first distribute a SenderKeyDistributionMessage to all
// members via 1:1 encrypted sessions. Then they can encrypt to the group using
// their sender key chain, which ratchets forward with each message.

use std::collections::HashMap;

use crate::chain::{ChainKey, MessageKey, kdf_ck};
use crate::crypto::aead;
use crate::crypto::curve::{self, KeyPair, PublicKey};
use crate::crypto::hmac;
use crate::errors::{Result, PackError};

const MAX_SENDER_KEY_STATES: usize = 5;
const MAX_MESSAGE_KEYS: usize = 2000;

/// A sender key distribution message sent to group members to establish
/// or update the sender's key chain. Distributed via 1:1 encrypted sessions.
pub struct SenderKeyDistributionMessage {
    pub distribution_id: String,
    pub chain_id: u32,
    pub iteration: u32,
    pub chain_key: [u8; 32],
    pub signing_key: PublicKey,
}

impl SenderKeyDistributionMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let dist_bytes = self.distribution_id.as_bytes();
        let mut buf = Vec::with_capacity(4 + dist_bytes.len() + 4 + 4 + 32 + 32);
        buf.extend_from_slice(&(dist_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(dist_bytes);
        buf.extend_from_slice(&self.chain_id.to_be_bytes());
        buf.extend_from_slice(&self.iteration.to_be_bytes());
        buf.extend_from_slice(&self.chain_key);
        buf.extend_from_slice(self.signing_key.as_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(PackError::InvalidMessage("sender key dist message too short".into()));
        }
        let dist_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let offset = 4 + dist_len;
        if data.len() < offset + 4 + 4 + 32 + 32 {
            return Err(PackError::InvalidMessage("sender key dist message too short".into()));
        }
        let distribution_id = String::from_utf8(data[4..offset].to_vec())
            .map_err(|_| PackError::InvalidMessage("invalid utf8 in distribution id".into()))?;
        let chain_id = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        let iteration = u32::from_be_bytes([data[offset+4], data[offset+5], data[offset+6], data[offset+7]]);
        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(&data[offset+8..offset+40]);
        let mut signing_bytes = [0u8; 32];
        signing_bytes.copy_from_slice(&data[offset+40..offset+72]);
        let signing_key = PublicKey::from_bytes_validated(signing_bytes)?;
        Ok(Self { distribution_id, chain_id, iteration, chain_key, signing_key })
    }
}

/// A single sender key chain state.
pub struct SenderKeyState {
    pub chain_id: u32,
    pub iteration: u32,
    pub chain_key: ChainKey,
    pub signing_key: PublicKey,
    pub signing_private: Option<crate::crypto::curve::PrivateKey>,
    skipped_keys: HashMap<u32, MessageKey>,
}

impl SenderKeyState {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.iteration.to_be_bytes());
        out.extend_from_slice(self.chain_key.as_bytes());
        out.extend_from_slice(self.signing_key.as_bytes());
        match &self.signing_private {
            Some(k) => { out.push(1); out.extend_from_slice(k.as_bytes()); }
            None => { out.push(0); }
        }
        out.extend_from_slice(&(self.skipped_keys.len() as u32).to_be_bytes());
        for (&seq, mk) in &self.skipped_keys {
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(mk.as_bytes());
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 + 4 + 32 + 32 + 1 {
            return Err(PackError::InvalidMessage("sender key state too short".into()));
        }
        let mut pos = 0;
        let chain_id = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        pos += 4;
        let iteration = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        pos += 4;
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&data[pos..pos+32]);
        pos += 32;
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&data[pos..pos+32]);
        pos += 32;
        let has_private = data[pos];
        pos += 1;
        let signing_private = if has_private == 1 {
            if data.len() < pos + 32 {
                return Err(PackError::InvalidMessage("sender key state truncated".into()));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&data[pos..pos+32]);
            pos += 32;
            Some(curve::PrivateKey::from_bytes(pk))
        } else {
            None
        };
        let mut skipped_keys = HashMap::new();
        if data.len() >= pos + 4 {
            let count = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            for _ in 0..count {
                if data.len() < pos + 4 + 32 {
                    return Err(PackError::InvalidMessage("sender key state truncated".into()));
                }
                let seq = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
                pos += 4;
                let mut mk = [0u8; 32];
                mk.copy_from_slice(&data[pos..pos+32]);
                pos += 32;
                skipped_keys.insert(seq, MessageKey::from_bytes(mk));
            }
        }
        Ok(Self {
            chain_id,
            iteration,
            chain_key: ChainKey::from_bytes(ck),
            signing_key: PublicKey::from_bytes(sk),
            signing_private,
            skipped_keys,
        })
    }
}

/// Stored sender key record for a group member. May hold multiple states
/// to handle re-keying transitions.
pub struct SenderKeyRecord {
    pub states: Vec<SenderKeyState>,
}

impl SenderKeyRecord {
    pub fn new() -> Self {
        Self { states: Vec::new() }
    }

    pub fn add_state(&mut self, state: SenderKeyState) {
        self.states.retain(|s| s.chain_id != state.chain_id);
        self.states.insert(0, state);
        self.states.truncate(MAX_SENDER_KEY_STATES);
    }

    fn state_for_chain_id(&self, chain_id: u32) -> Option<usize> {
        self.states.iter().position(|s| s.chain_id == chain_id)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.states.len() as u32).to_be_bytes());
        for state in &self.states {
/*
            out.extend_from_slice(&state.chain_id.to_be_bytes());
            out.extend_from_slice(&state.iteration.to_be_bytes());
            out.extend_from_slice(state.chain_key.as_bytes());
            out.extend_from_slice(state.signing_key.as_bytes());
            match &state.signing_private {
                Some(pk) => { out.push(1); out.extend_from_slice(pk.as_bytes()); }
                None => { out.push(0); }
            }
            out.extend_from_slice(&(state.skipped_keys.len() as u32).to_be_bytes());
            for (&iter, mk) in &state.skipped_keys {
                out.extend_from_slice(&iter.to_be_bytes());
                out.extend_from_slice(mk.as_bytes());
            }
*/
            let sb = state.to_bytes();
            out.extend_from_slice(&(sb.len() as u32).to_be_bytes());
            out.extend_from_slice(&sb);
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {

        if data.len() < 4 {
            return Err(PackError::InvalidMessage("sender key record too short".into()));
        }
        let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut pos = 4;
        let mut states = Vec::with_capacity(count);
        for _ in 0..count {
            if data.len() < pos + 4 {
                return Err(PackError::InvalidMessage("sender key record truncated".into()));
            }
            let len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            if data.len() < pos + len {
                return Err(PackError::InvalidMessage("sender key record truncated".into()));
            }
            states.push(SenderKeyState::from_bytes(&data[pos..pos+len])?);
            pos += len;
        }
        Ok(Self { states })
    }

    pub fn to_bytes_encrypted(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>> {
        let plaintext = self.to_bytes();
        let nonce: [u8; 12] = rand::random();
        let ciphertext = aead::encrypt(storage_key, &nonce, &plaintext, b"sender-key-record")?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn from_bytes_encrypted(data: &[u8], storage_key: &[u8; 32]) -> Result<Self> {
        if data.len() < 12 {
            return Err(PackError::InvalidMessage("encrypted sender key record too short".into()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[..12]);
        let plaintext = aead::decrypt(storage_key, &nonce, &data[12..], b"sender-key-record")?;
        Self::from_bytes(&plaintext)
    }
}

/// Create a new sender key distribution message for a group.
/// The caller is the sender establishing their chain for this group.
pub fn create_sender_key_distribution_message(
    distribution_id: &str,
    record: &mut SenderKeyRecord,
) -> Result<SenderKeyDistributionMessage> {
    let signing_pair = KeyPair::generate();
    let chain_key_bytes: [u8; 32] = rand::random();
    let chain_id: u32 = rand::random();

    let state = SenderKeyState {
        chain_id,
        iteration: 0,
        chain_key: ChainKey::from_bytes(chain_key_bytes),
        signing_key: signing_pair.public.clone(),
        signing_private: Some(signing_pair.private.clone()),
        skipped_keys: HashMap::new(),
    };

    record.add_state(state);

    Ok(SenderKeyDistributionMessage {
        distribution_id: distribution_id.to_string(),
        chain_id,
        iteration: 0,
        chain_key: chain_key_bytes,
        signing_key: signing_pair.public.clone(),
    })
}

/// Process a received sender key distribution message.
/// Stores the sender's chain so we can decrypt their future group messages.
pub fn process_sender_key_distribution_message(
    record: &mut SenderKeyRecord,
    message: &SenderKeyDistributionMessage,
) {
    let state = SenderKeyState {
        chain_id: message.chain_id,
        iteration: message.iteration,
        chain_key: ChainKey::from_bytes(message.chain_key),
        signing_key: message.signing_key.clone(),
        signing_private: None,
        skipped_keys: HashMap::new(),
    };
    record.add_state(state);
}

/// Encrypted group message format.
pub struct SenderKeyMessage {
    pub chain_id: u32,
    pub iteration: u32,
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
}

impl SenderKeyMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 4 + 4 + self.ciphertext.len() + 64);
        buf.extend_from_slice(&self.chain_id.to_be_bytes());
        buf.extend_from_slice(&self.iteration.to_be_bytes());
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        buf.extend_from_slice(&self.signature);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 12 + 64 {
            return Err(PackError::InvalidMessage("sender key message too short".into()));
        }
        let chain_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let iteration = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ct_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        if data.len() < 12 + ct_len + 64 {
            return Err(PackError::InvalidMessage("sender key message too short".into()));
        }
        let ciphertext = data[12..12+ct_len].to_vec();
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[12+ct_len..12+ct_len+64]);
        Ok(Self { chain_id, iteration, ciphertext, signature })
    }
}

/// Encrypt a message using the sender's key chain for a group.
pub(crate) fn group_encrypt(
    record: &mut SenderKeyRecord,
    plaintext: &[u8],
) -> Result<SenderKeyMessage> {
    let state = record.states.first_mut()
        .ok_or(PackError::InvalidMessage("no sender key state".into()))?;

    let signing_private = state.signing_private.as_ref()
        .ok_or(PackError::InvalidMessage("not the sender for this chain".into()))?;

    // Derive message key from chain key
    let (new_chain_key, message_key) = kdf_ck(&state.chain_key);
    let iteration = state.iteration;

    // Derive nonce from message key + iteration
    let nonce = derive_group_nonce(message_key.as_bytes(), iteration);

    // Encrypt with chain_id as associated data to bind ciphertext to this chain
    let ad = state.chain_id.to_be_bytes();
    let ciphertext = aead::encrypt(message_key.as_bytes(), &nonce, plaintext, &ad)?;

    // Update chain state
    state.chain_key = new_chain_key;
    state.iteration = state.iteration.checked_add(1)
        .ok_or(PackError::InvalidMessage("group iteration counter overflow".into()))?;

    // Sign the message content (chain_id || iteration || ciphertext)
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&state.chain_id.to_be_bytes());
    sign_data.extend_from_slice(&iteration.to_be_bytes());
    sign_data.extend_from_slice(&ciphertext);
    let signature = curve::xeddsa_sign(signing_private, &sign_data);

    Ok(SenderKeyMessage {
        chain_id: state.chain_id,
        iteration,
        ciphertext,
        signature,
    })
}

/// Decrypt a group message using the stored sender key for the sender.
pub(crate) fn group_decrypt(
    record: &mut SenderKeyRecord,
    message: &SenderKeyMessage,
) -> Result<Vec<u8>> {
    let state_idx = record.state_for_chain_id(message.chain_id)
        .ok_or(PackError::InvalidMessage("unknown sender key chain".into()))?;

    let state = &record.states[state_idx];

    // Verify signature
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&message.chain_id.to_be_bytes());
    sign_data.extend_from_slice(&message.iteration.to_be_bytes());
    sign_data.extend_from_slice(&message.ciphertext);
    curve::xeddsa_verify(&state.signing_key, &sign_data, &message.signature)?;

    // Check skipped keys cache first (for out-of-order messages)
    let state = &mut record.states[state_idx];

    let ad = message.chain_id.to_be_bytes();

    if message.iteration < state.iteration {
        if let Some(mk) = state.skipped_keys.remove(&message.iteration) {
            let nonce = derive_group_nonce(mk.as_bytes(), message.iteration);
            return aead::decrypt(mk.as_bytes(), &nonce, &message.ciphertext, &ad);
        }
        return Err(PackError::DuplicateMessage);
    }

    let skip_count = message.iteration - state.iteration;
    if skip_count > MAX_MESSAGE_KEYS as u32 {
        return Err(PackError::TooManySkippedMessages);
    }

    let new_iteration = message.iteration.checked_add(1)
        .ok_or(PackError::InvalidMessage("iteration counter overflow".into()))?;

    // Derive keys into temporaries — state is not mutated until AEAD succeeds
    let mut current_chain = ChainKey::from_bytes(*state.chain_key.as_bytes());
    let mut target_mk: Option<MessageKey> = None;
    let mut pending_skipped: Vec<(u32, MessageKey)> = Vec::new();

    for i in 0..=skip_count {
        let (next_chain, mk) = kdf_ck(&current_chain);
        if i == skip_count {
            target_mk = Some(mk);
        } else {
            pending_skipped.push((state.iteration + i, mk));
        }
        current_chain = next_chain;
    }

    let message_key = target_mk.unwrap();
    let nonce = derive_group_nonce(message_key.as_bytes(), message.iteration);

    let plaintext = aead::decrypt(message_key.as_bytes(), &nonce, &message.ciphertext, &ad)?;

    // AEAD succeeded — commit skipped keys and advance state
    for (iter, mk) in pending_skipped {
        state.skipped_keys.insert(iter, mk);
        if state.skipped_keys.len() > MAX_MESSAGE_KEYS {
            let oldest = *state.skipped_keys.keys().min().unwrap();
            state.skipped_keys.remove(&oldest);
        }
    }
    state.chain_key = current_chain;
    state.iteration = new_iteration;

    Ok(plaintext)
}

fn derive_group_nonce(mk: &[u8; 32], iteration: u32) -> [u8; 12] {
    let iter_bytes = iteration.to_be_bytes();
    let hash = hmac::hmac_sha256(mk, &iter_bytes);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_key_distribution_roundtrip() {
        let mut record = SenderKeyRecord::new();
        let msg = create_sender_key_distribution_message("group-1", &mut record).unwrap();

        let bytes = msg.to_bytes();
        let parsed = SenderKeyDistributionMessage::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.distribution_id, "group-1");
        assert_eq!(parsed.chain_id, msg.chain_id);
        assert_eq!(parsed.iteration, 0);
        assert_eq!(parsed.chain_key, msg.chain_key);
    }

    #[test]
    fn test_sender_key_message_roundtrip() {
        let msg = SenderKeyMessage {
            chain_id: 42,
            iteration: 7,
            ciphertext: vec![1, 2, 3, 4, 5],
            signature: [0xAB; 64],
        };
        let bytes = msg.to_bytes();
        let parsed = SenderKeyMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.chain_id, 42);
        assert_eq!(parsed.iteration, 7);
        assert_eq!(parsed.ciphertext, vec![1, 2, 3, 4, 5]);
        assert_eq!(parsed.signature, [0xAB; 64]);
    }

    #[test]
    fn test_group_encrypt_decrypt_roundtrip() {
        let mut sender_record = SenderKeyRecord::new();
        let dist_msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        // Receiver processes the distribution message
        let mut receiver_record = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut receiver_record, &dist_msg);

        // Sender encrypts
        let plaintext = b"hello group!";
        let encrypted = group_encrypt(&mut sender_record, plaintext).unwrap();

        // Receiver decrypts
        let decrypted = group_decrypt(&mut receiver_record, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_group_multiple_messages() {
        let mut sender_record = SenderKeyRecord::new();
        let dist_msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        let mut receiver_record = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut receiver_record, &dist_msg);

        for i in 0..10 {
            let msg = format!("message {}", i);
            let encrypted = group_encrypt(&mut sender_record, msg.as_bytes()).unwrap();
            let decrypted = group_decrypt(&mut receiver_record, &encrypted).unwrap();
            assert_eq!(decrypted, msg.as_bytes());
        }
    }

    #[test]
    fn test_group_out_of_order() {
        let mut sender_record = SenderKeyRecord::new();
        let dist_msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        let mut receiver_record = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut receiver_record, &dist_msg);

        // Send 3 messages
        let e1 = group_encrypt(&mut sender_record, b"msg1").unwrap();
        let e2 = group_encrypt(&mut sender_record, b"msg2").unwrap();
        let e3 = group_encrypt(&mut sender_record, b"msg3").unwrap();

        // Receive out of order: 3, 1, 2
        // Message 3 first — skips forward, caching keys for 1 and 2
        let d3 = group_decrypt(&mut receiver_record, &e3).unwrap();
        assert_eq!(d3, b"msg3");

        // Messages 1 and 2 decrypted from the skipped key cache
        let d1 = group_decrypt(&mut receiver_record, &e1).unwrap();
        assert_eq!(d1, b"msg1");
        let d2 = group_decrypt(&mut receiver_record, &e2).unwrap();
        assert_eq!(d2, b"msg2");

        // Replaying message 1 again should fail (key consumed)
        assert!(group_decrypt(&mut receiver_record, &e1).is_err());
    }

    #[test]
    fn test_group_wrong_chain_fails() {
        let mut sender_record = SenderKeyRecord::new();
        let _dist_msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        let encrypted = group_encrypt(&mut sender_record, b"secret").unwrap();

        // Receiver has no sender key for this chain
        let mut empty_record = SenderKeyRecord::new();
        assert!(group_decrypt(&mut empty_record, &encrypted).is_err());
    }

    #[test]
    fn test_group_tampered_ciphertext_fails() {
        let mut sender_record = SenderKeyRecord::new();
        let dist_msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        let mut receiver_record = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut receiver_record, &dist_msg);

        let mut encrypted = group_encrypt(&mut sender_record, b"hello").unwrap();
        // Tamper with ciphertext — signature verification should fail
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }
        assert!(group_decrypt(&mut receiver_record, &encrypted).is_err());
    }

    #[test]
    fn test_group_multiple_receivers() {
        let mut sender_record = SenderKeyRecord::new();
        let dist_msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        let mut receiver1 = SenderKeyRecord::new();
        let mut receiver2 = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut receiver1, &dist_msg);
        process_sender_key_distribution_message(&mut receiver2, &dist_msg);

        let encrypted = group_encrypt(&mut sender_record, b"to all").unwrap();

        let d1 = group_decrypt(&mut receiver1, &encrypted).unwrap();
        let d2 = group_decrypt(&mut receiver2, &encrypted).unwrap();
        assert_eq!(d1, b"to all");
        assert_eq!(d2, b"to all");
    }

    #[test]
    fn test_group_chain_ratchet_advances() {
        let mut sender_record = SenderKeyRecord::new();
        let dist_msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        let initial_chain = *sender_record.states[0].chain_key.as_bytes();

        let _e1 = group_encrypt(&mut sender_record, b"msg1").unwrap();
        let after_one = *sender_record.states[0].chain_key.as_bytes();
        assert_ne!(initial_chain, after_one);

        let _e2 = group_encrypt(&mut sender_record, b"msg2").unwrap();
        let after_two = *sender_record.states[0].chain_key.as_bytes();
        assert_ne!(after_one, after_two);

        assert_eq!(sender_record.states[0].iteration, 2);
        let _ = dist_msg; // used above
    }

    #[test]
    fn test_sender_key_record_serialization_roundtrip() {
        let mut sender_record = SenderKeyRecord::new();
        let dist_msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        let mut receiver_record = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut receiver_record, &dist_msg);

        // Send some messages to advance the chain
        let e1 = group_encrypt(&mut sender_record, b"msg1").unwrap();
        let e2 = group_encrypt(&mut sender_record, b"msg2").unwrap();
        let e3 = group_encrypt(&mut sender_record, b"msg3").unwrap();

        // Receive out of order to populate skipped keys
        group_decrypt(&mut receiver_record, &e3).unwrap();

        // Serialize and restore the receiver
        let bytes = receiver_record.to_bytes();
        let mut restored = SenderKeyRecord::from_bytes(&bytes).unwrap();

        // Skipped keys should still work
        let d1 = group_decrypt(&mut restored, &e1).unwrap();
        assert_eq!(d1, b"msg1");
        let d2 = group_decrypt(&mut restored, &e2).unwrap();
        assert_eq!(d2, b"msg2");

        // New messages should also work
        let e4 = group_encrypt(&mut sender_record, b"msg4").unwrap();
        let d4 = group_decrypt(&mut restored, &e4).unwrap();
        assert_eq!(d4, b"msg4");

        // Also test sender-side round-trip
        let sender_bytes = sender_record.to_bytes();
        let mut sender_restored = SenderKeyRecord::from_bytes(&sender_bytes).unwrap();
        let e5 = group_encrypt(&mut sender_restored, b"msg5").unwrap();
        let d5 = group_decrypt(&mut restored, &e5).unwrap();
        assert_eq!(d5, b"msg5");
    }

    #[test]
    fn test_max_sender_key_states_truncation() {
        let mut sender_record = SenderKeyRecord::new();

        let mut dist_msgs = Vec::new();
        for _ in 0..MAX_SENDER_KEY_STATES + 1 {
            let msg = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();
            dist_msgs.push(msg);
        }

        assert_eq!(sender_record.states.len(), MAX_SENDER_KEY_STATES);

        // The oldest chain (dist_msgs[0]) should have been truncated
        let oldest_chain_id = dist_msgs[0].chain_id;
        assert!(sender_record.state_for_chain_id(oldest_chain_id).is_none());

        // The newest chain should be at position 0
        let newest_chain_id = dist_msgs[MAX_SENDER_KEY_STATES].chain_id;
        assert_eq!(sender_record.state_for_chain_id(newest_chain_id), Some(0));

        // A receiver with only the oldest SKDM cannot decrypt new messages
        let mut stale_receiver = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut stale_receiver, &dist_msgs[0]);

        let encrypted = group_encrypt(&mut sender_record, b"new message").unwrap();
        assert!(group_decrypt(&mut stale_receiver, &encrypted).is_err());

        // A receiver with the newest SKDM can decrypt
        let mut fresh_receiver = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut fresh_receiver, &dist_msgs[MAX_SENDER_KEY_STATES]);

        let encrypted2 = group_encrypt(&mut sender_record, b"another message").unwrap();
        let decrypted = group_decrypt(&mut fresh_receiver, &encrypted2).unwrap();
        assert_eq!(decrypted, b"another message");
    }

    #[test]
    fn test_chain_rotation_breaks_stale_receiver() {
        let mut sender_record = SenderKeyRecord::new();

        // Create initial chain and distribute to two receivers
        let dist_msg1 = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();
        let mut receiver_a = SenderKeyRecord::new();
        let mut receiver_b = SenderKeyRecord::new();
        process_sender_key_distribution_message(&mut receiver_a, &dist_msg1);
        process_sender_key_distribution_message(&mut receiver_b, &dist_msg1);

        // Both can decrypt
        let e1 = group_encrypt(&mut sender_record, b"before rotation").unwrap();
        assert_eq!(group_decrypt(&mut receiver_a, &e1).unwrap(), b"before rotation");
        assert_eq!(group_decrypt(&mut receiver_b, &e1).unwrap(), b"before rotation");

        // Sender rotates chain (simulates redistribute_skdms creating new chain)
        let dist_msg2 = create_sender_key_distribution_message("group-1", &mut sender_record).unwrap();

        // Only receiver_a gets the new SKDM (simulates delta sending to new member only)
        process_sender_key_distribution_message(&mut receiver_a, &dist_msg2);

        // Sender encrypts with new chain (position 0)
        let e2 = group_encrypt(&mut sender_record, b"after rotation").unwrap();

        // receiver_a can decrypt (has new chain)
        assert_eq!(group_decrypt(&mut receiver_a, &e2).unwrap(), b"after rotation");

        // receiver_b CANNOT decrypt (only has old chain, not the new one)
        assert!(group_decrypt(&mut receiver_b, &e2).is_err());

        // receiver_b gets the new SKDM (simulates receiving it later)
        process_sender_key_distribution_message(&mut receiver_b, &dist_msg2);

        // Now receiver_b can decrypt new messages
        let e3 = group_encrypt(&mut sender_record, b"after update").unwrap();
        assert_eq!(group_decrypt(&mut receiver_b, &e3).unwrap(), b"after update");
    }
}

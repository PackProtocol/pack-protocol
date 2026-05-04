// Implements: Double Ratchet Algorithm, Sections 3.1-3.5
// Source: https://signal.org/docs/specifications/doubleratchet/

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::chain::{self, RootKey, ChainKey, MessageKey};
use crate::crypto::curve::{self, KeyPair, PublicKey};
use crate::crypto::aead;
use crate::errors::{Result, PackError};

const MAX_SKIP: u32 = 1000;
const MAX_TOTAL_SKIPPED: usize = 5000;

/// Message header sent with each encrypted message (spec §3.1).
#[derive(Clone)]
pub struct MessageHeader {
    /// The sender's current DH ratchet public key
    pub ratchet_key: PublicKey,
    /// Number of messages in previous sending chain (PN)
    pub prev_chain_length: u32,
    /// Message number in current sending chain (Ns or Nr)
    pub message_number: u32,
}

impl MessageHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(self.ratchet_key.as_bytes());
        out.extend_from_slice(&self.prev_chain_length.to_be_bytes());
        out.extend_from_slice(&self.message_number.to_be_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 40 {
            return Err(PackError::InvalidMessage("header too short".into()));
        }
        let mut rk_bytes = [0u8; 32];
        rk_bytes.copy_from_slice(&data[..32]);
        let prev_chain_length = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
        let message_number = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);
        Ok(Self {
            ratchet_key: PublicKey::from_bytes_validated(rk_bytes)?,
            prev_chain_length,
            message_number,
        })
    }
}

/// Key for looking up skipped message keys: (ratchet public key bytes, message number).
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord)]
struct SkippedKeyId {
    ratchet_key: [u8; 32],
    message_number: u32,
}

/// The full Double Ratchet state for one side of a session (spec §3.1).
#[derive(Clone)]
pub struct RatchetState {
    /// Our current DH ratchet key pair (DHs)
    dh_self: KeyPair,
    /// Their current DH ratchet public key (DHr)
    dh_remote: Option<PublicKey>,
    /// Root key (RK)
    root_key: RootKey,
    /// Sending chain key (CKs) and counter (Ns)
    sending_chain: Option<ChainKey>,
    send_count: u32,
    /// Receiving chain key (CKr) and counter (Nr)
    receiving_chain: Option<ChainKey>,
    recv_count: u32,
    /// Number of messages in previous sending chain (PN)
    prev_send_count: u32,
    /// Skipped message keys (MKSKIPPED) with insertion sequence for LRU eviction
    skipped_keys: BTreeMap<SkippedKeyId, (MessageKey, u64)>,
    /// Monotonic counter for skipped-key insertion order
    skipped_seq: u64,
}

impl RatchetState {
    /// Serialize the ratchet state to bytes for persistent storage.
    ///
    /// # Security
    /// The output contains private keys, root keys, chain keys, and message keys
    /// in plaintext. Callers MUST encrypt this data before writing to disk or any
    /// storage backend accessible to other processes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);

        // dh_self (32 pub + 32 priv)
        out.extend_from_slice(self.dh_self.public.as_bytes());
        out.extend_from_slice(self.dh_self.private.as_bytes());

        // dh_remote (1 flag + optional 32)
        match &self.dh_remote {
            Some(pk) => { out.push(1); out.extend_from_slice(pk.as_bytes()); }
            None => { out.push(0); }
        }

        // root_key (32)
        out.extend_from_slice(self.root_key.as_bytes());

        // sending_chain (1 flag + optional 32)
        match &self.sending_chain {
            Some(ck) => { out.push(1); out.extend_from_slice(ck.as_bytes()); }
            None => { out.push(0); }
        }

        out.extend_from_slice(&self.send_count.to_be_bytes());

        // receiving_chain (1 flag + optional 32)
        match &self.receiving_chain {
            Some(ck) => { out.push(1); out.extend_from_slice(ck.as_bytes()); }
            None => { out.push(0); }
        }

        out.extend_from_slice(&self.recv_count.to_be_bytes());
        out.extend_from_slice(&self.prev_send_count.to_be_bytes());

        // skipped_keys: count + entries (each: 32 ratchet_key + 4 msg_num + 32 mk + 8 seq)
        out.extend_from_slice(&(self.skipped_keys.len() as u32).to_be_bytes());
        for (id, (mk, seq)) in &self.skipped_keys {
            out.extend_from_slice(&id.ratchet_key);
            out.extend_from_slice(&id.message_number.to_be_bytes());
            out.extend_from_slice(mk.as_bytes());
            out.extend_from_slice(&seq.to_be_bytes());
        }

        // skipped_seq counter
        out.extend_from_slice(&self.skipped_seq.to_be_bytes());

        out
    }

    /// Deserialize ratchet state from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut pos = 0;

        let read = |pos: &mut usize, len: usize| -> Result<&[u8]> {
            if *pos + len > data.len() {
                return Err(PackError::InvalidMessage("ratchet state truncated".into()));
            }
            let slice = &data[*pos..*pos + len];
            *pos += len;
            Ok(slice)
        };

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(read(&mut pos, 32)?);
        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(read(&mut pos, 32)?);
        let dh_self = KeyPair {
            public: PublicKey::from_bytes_validated(pub_bytes)?,
            private: curve::PrivateKey::from_bytes(priv_bytes),
        };

        let has_remote = read(&mut pos, 1)?[0];
        let dh_remote = if has_remote == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(read(&mut pos, 32)?);
            Some(PublicKey::from_bytes_validated(b)?)
        } else { None };

        let mut rk = [0u8; 32];
        rk.copy_from_slice(read(&mut pos, 32)?);
        let root_key = RootKey::from_bytes(rk);

        let has_send = read(&mut pos, 1)?[0];
        let sending_chain = if has_send == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(read(&mut pos, 32)?);
            Some(ChainKey::from_bytes(b))
        } else { None };

        let sc_bytes = read(&mut pos, 4)?;
        let send_count = u32::from_be_bytes([sc_bytes[0], sc_bytes[1], sc_bytes[2], sc_bytes[3]]);

        let has_recv = read(&mut pos, 1)?[0];
        let receiving_chain = if has_recv == 1 {
            let mut b = [0u8; 32];
            b.copy_from_slice(read(&mut pos, 32)?);
            Some(ChainKey::from_bytes(b))
        } else { None };

        let rc_bytes = read(&mut pos, 4)?;
        let recv_count = u32::from_be_bytes([rc_bytes[0], rc_bytes[1], rc_bytes[2], rc_bytes[3]]);

        let psc_bytes = read(&mut pos, 4)?;
        let prev_send_count = u32::from_be_bytes([psc_bytes[0], psc_bytes[1], psc_bytes[2], psc_bytes[3]]);

        let sk_count_bytes = read(&mut pos, 4)?;
        let sk_count = u32::from_be_bytes([sk_count_bytes[0], sk_count_bytes[1], sk_count_bytes[2], sk_count_bytes[3]]) as usize;

        let mut skipped_keys = BTreeMap::new();
        for _ in 0..sk_count {
            let mut rk_id = [0u8; 32];
            rk_id.copy_from_slice(read(&mut pos, 32)?);
            let mn_bytes = read(&mut pos, 4)?;
            let mn = u32::from_be_bytes([mn_bytes[0], mn_bytes[1], mn_bytes[2], mn_bytes[3]]);
            let mut mk = [0u8; 32];
            mk.copy_from_slice(read(&mut pos, 32)?);
            let seq_bytes = read(&mut pos, 8)?;
            let seq = u64::from_be_bytes([
                seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3],
                seq_bytes[4], seq_bytes[5], seq_bytes[6], seq_bytes[7],
            ]);
            skipped_keys.insert(
                SkippedKeyId { ratchet_key: rk_id, message_number: mn },
                (MessageKey::from_bytes(mk), seq),
            );
        }

        let seq_bytes = read(&mut pos, 8)?;
        let skipped_seq = u64::from_be_bytes([
            seq_bytes[0], seq_bytes[1], seq_bytes[2], seq_bytes[3],
            seq_bytes[4], seq_bytes[5], seq_bytes[6], seq_bytes[7],
        ]);

        Ok(RatchetState {
            dh_self,
            dh_remote,
            root_key,
            sending_chain,
            send_count,
            receiving_chain,
            recv_count,
            prev_send_count,
            skipped_keys,
            skipped_seq,
        })
    }
}

/// Initialize ratchet as the initiator (Alice) after X3DH (spec §3.2).
///
/// Alice knows Bob's signed pre-key (which serves as his initial ratchet public key).
/// She performs a DH ratchet step immediately to establish the first sending chain.
pub fn ratchet_init_initiator(
    shared_secret: Zeroizing<[u8; 32]>,
    their_ratchet_key: &PublicKey,
) -> Result<RatchetState> {
    let dh_self = KeyPair::generate();
    let root_key = RootKey::from_bytes(*shared_secret);

    // Perform initial DH ratchet step to derive sending chain
    let dh_output = curve::dh(&dh_self.private, their_ratchet_key)?;
    let (new_root_key, sending_chain) = chain::kdf_rk(&root_key, &dh_output)?;

    Ok(RatchetState {
        dh_self,
        dh_remote: Some(their_ratchet_key.clone()),
        root_key: new_root_key,
        sending_chain: Some(sending_chain),
        send_count: 0,
        receiving_chain: None,
        recv_count: 0,
        prev_send_count: 0,
        skipped_keys: BTreeMap::new(),
        skipped_seq: 0,
    })
}

/// Initialize ratchet as the responder (Bob) after X3DH (spec §3.2).
///
/// Bob uses his signed pre-key pair as his initial ratchet key pair.
/// He has no sending chain yet — it will be created on the first encrypt
/// (which triggers a DH ratchet step).
pub fn ratchet_init_responder(
    shared_secret: Zeroizing<[u8; 32]>,
    our_ratchet_keypair: KeyPair,
) -> RatchetState {
    RatchetState {
        dh_self: our_ratchet_keypair,
        dh_remote: None,
        root_key: RootKey::from_bytes(*shared_secret),
        sending_chain: None,
        send_count: 0,
        receiving_chain: None,
        recv_count: 0,
        prev_send_count: 0,
        skipped_keys: BTreeMap::new(),
        skipped_seq: 0,
    }
}

/// Encrypt a plaintext message (spec §3.3).
///
/// 1. Derive message key from sending chain: (CKs, mk) = KDF_CK(CKs)
/// 2. Build header HEADER(DHs, PN, Ns)
/// 3. Ns += 1
/// 4. Encrypt with AEAD using mk, with AD = ad || header_bytes
pub fn ratchet_encrypt(
    state: &mut RatchetState,
    plaintext: &[u8],
    ad: &[u8],
) -> Result<(MessageHeader, Vec<u8>)> {
    // If we have no sending chain (responder's first message), perform a DH ratchet step
    if state.sending_chain.is_none() {
        // We need a remote key to ratchet against
        if state.dh_remote.is_none() {
            return Err(PackError::InvalidMessage(
                "cannot encrypt: no remote ratchet key and no sending chain".into(),
            ));
        }
        // Generate new DH key pair and derive sending chain
        state.prev_send_count = state.send_count;
        state.send_count = 0;
        state.dh_self = KeyPair::generate();
        let dh_output = curve::dh(&state.dh_self.private, state.dh_remote.as_ref().unwrap())?;
        let (new_rk, new_ck) = chain::kdf_rk(&state.root_key, &dh_output)?;
        state.root_key = new_rk;
        state.sending_chain = Some(new_ck);
    }

    // Step 1: derive message key
    let ck = state.sending_chain.take().unwrap();
    let (new_ck, mk) = chain::kdf_ck(&ck);
    state.sending_chain = Some(new_ck);

    // Step 2: build header
    let header = MessageHeader {
        ratchet_key: state.dh_self.public.clone(),
        prev_chain_length: state.prev_send_count,
        message_number: state.send_count,
    };

    // Step 3: increment counter
    state.send_count += 1;

    // Step 4: AEAD encrypt
    // Full AD = ad || header_bytes
    let header_bytes = header.to_bytes();
    let mut full_ad = Vec::with_capacity(ad.len() + header_bytes.len());
    full_ad.extend_from_slice(ad);
    full_ad.extend_from_slice(&header_bytes);

    // Use first 12 bytes of message key hash as nonce (the key itself provides uniqueness)
    let nonce = derive_nonce(mk.as_bytes());
    let ciphertext = aead::encrypt(mk.as_bytes(), &nonce, plaintext, &full_ad)?;

    Ok((header, ciphertext))
}

/// Decrypt a received message (spec §3.4).
///
/// 1. If header.ratchet_key != DHr: perform DH ratchet step
/// 2. Check MKSKIPPED for (header.ratchet_key, header.message_number)
/// 3. Skip message keys up to header.message_number
/// 4. Derive message key and decrypt
pub fn ratchet_decrypt(
    state: &mut RatchetState,
    header: &MessageHeader,
    ciphertext: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>> {
    // Step 2: check skipped keys first
    let skip_id = SkippedKeyId {
        ratchet_key: *header.ratchet_key.as_bytes(),
        message_number: header.message_number,
    };
    if let Some((mk, _seq)) = state.skipped_keys.remove(&skip_id) {
        let header_bytes = header.to_bytes();
        let mut full_ad = Vec::with_capacity(ad.len() + header_bytes.len());
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&header_bytes);

        let nonce = derive_nonce(mk.as_bytes());
        return aead::decrypt(mk.as_bytes(), &nonce, ciphertext, &full_ad);
    }

    // Step 1: DH ratchet step if new ratchet key
    let need_dh_ratchet = match &state.dh_remote {
        None => true,
        Some(existing) => existing != &header.ratchet_key,
    };

    if need_dh_ratchet {
        // Skip remaining keys in current receiving chain
        if state.receiving_chain.is_some() && state.dh_remote.is_some() {
            skip_message_keys(state, state.dh_remote.as_ref().unwrap().clone(), header.prev_chain_length)?;
        }

        // DH ratchet step (spec §3.5)
        dh_ratchet_step(state, &header.ratchet_key)?;
    }

    // Step 3: skip message keys up to header.message_number
    skip_message_keys_current(state, header.message_number)?;

    // Step 4: derive message key and decrypt
    let ck = state.receiving_chain.take().ok_or_else(|| {
        PackError::InvalidMessage("no receiving chain".into())
    })?;
    let (new_ck, mk) = chain::kdf_ck(&ck);
    state.receiving_chain = Some(new_ck);
    state.recv_count += 1;

    let header_bytes = header.to_bytes();
    let mut full_ad = Vec::with_capacity(ad.len() + header_bytes.len());
    full_ad.extend_from_slice(ad);
    full_ad.extend_from_slice(&header_bytes);

    let nonce = derive_nonce(mk.as_bytes());
    aead::decrypt(mk.as_bytes(), &nonce, ciphertext, &full_ad)
}

/// DH ratchet step (spec §3.5).
fn dh_ratchet_step(state: &mut RatchetState, new_remote_key: &PublicKey) -> Result<()> {
    state.prev_send_count = state.send_count;
    state.send_count = 0;
    state.recv_count = 0;
    state.dh_remote = Some(new_remote_key.clone());

    // Derive new receiving chain
    let dh_output = curve::dh(&state.dh_self.private, new_remote_key)?;
    let (new_rk, receiving_chain) = chain::kdf_rk(&state.root_key, &dh_output)?;
    state.root_key = new_rk;
    state.receiving_chain = Some(receiving_chain);

    // Generate new DH key pair and derive new sending chain
    state.dh_self = KeyPair::generate();
    let dh_output = curve::dh(&state.dh_self.private, new_remote_key)?;
    let (new_rk, sending_chain) = chain::kdf_rk(&state.root_key, &dh_output)?;
    state.root_key = new_rk;
    state.sending_chain = Some(sending_chain);

    Ok(())
}

/// Skip message keys in the current receiving chain up to the target message number.
fn skip_message_keys_current(state: &mut RatchetState, target: u32) -> Result<()> {
    if target < state.recv_count {
        return Err(PackError::DuplicateMessage);
    }
    if target - state.recv_count > MAX_SKIP {
        return Err(PackError::TooManySkippedMessages);
    }

    let ratchet_key = state.dh_remote.as_ref()
        .ok_or_else(|| PackError::InvalidMessage("no remote key for skipping".into()))?
        .clone();

    while state.recv_count < target {
        let ck = state.receiving_chain.take().ok_or_else(|| {
            PackError::InvalidMessage("no receiving chain for skipping".into())
        })?;
        let (new_ck, mk) = chain::kdf_ck(&ck);
        state.receiving_chain = Some(new_ck);

        let skip_id = SkippedKeyId {
            ratchet_key: *ratchet_key.as_bytes(),
            message_number: state.recv_count,
        };
        state.skipped_keys.insert(skip_id, (mk, state.skipped_seq));
        state.skipped_seq += 1;
        evict_oldest_skipped(state);
        state.recv_count += 1;
    }

    Ok(())
}

fn evict_oldest_skipped(state: &mut RatchetState) {
    while state.skipped_keys.len() > MAX_TOTAL_SKIPPED {
        let oldest = state.skipped_keys.iter()
            .min_by_key(|(_, (_, seq))| *seq)
            .map(|(k, _)| k.clone());
        if let Some(key) = oldest {
            state.skipped_keys.remove(&key);
        }
    }
}

/// Skip remaining message keys in a previous receiving chain.
fn skip_message_keys(state: &mut RatchetState, ratchet_key: PublicKey, target: u32) -> Result<()> {
    if target < state.recv_count {
        return Ok(());
    }
    if target - state.recv_count > MAX_SKIP {
        return Err(PackError::TooManySkippedMessages);
    }

    while state.recv_count < target {
        let ck = state.receiving_chain.take().ok_or_else(|| {
            PackError::InvalidMessage("no receiving chain for skipping".into())
        })?;
        let (new_ck, mk) = chain::kdf_ck(&ck);
        state.receiving_chain = Some(new_ck);

        let skip_id = SkippedKeyId {
            ratchet_key: *ratchet_key.as_bytes(),
            message_number: state.recv_count,
        };
        state.skipped_keys.insert(skip_id, (mk, state.skipped_seq));
        state.skipped_seq += 1;
        evict_oldest_skipped(state);
        state.recv_count += 1;
    }

    Ok(())
}

/// Derive a 12-byte nonce from a message key.
/// We use the first 12 bytes of HMAC-SHA256(mk, "nonce") to get a unique nonce per message key.
fn derive_nonce(mk: &[u8; 32]) -> [u8; 12] {
    let hash = crate::crypto::hmac::hmac_sha256(mk, b"nonce");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_alice_bob() -> (RatchetState, RatchetState) {
        // Simulate X3DH: both sides agree on a shared secret
        let shared_secret = [0x42u8; 32];
        let bob_ratchet_kp = KeyPair::generate();
        let bob_ratchet_pub = bob_ratchet_kp.public.clone();

        let alice = ratchet_init_initiator(Zeroizing::new(shared_secret), &bob_ratchet_pub).unwrap();
        let bob = ratchet_init_responder(Zeroizing::new(shared_secret), bob_ratchet_kp);

        (alice, bob)
    }

    #[test]
    fn test_simple_send_receive() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"associated data";

        let (header, ct) = ratchet_encrypt(&mut alice, b"hello bob", ad).unwrap();
        let pt = ratchet_decrypt(&mut bob, &header, &ct, ad).unwrap();

        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn test_ping_pong() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice -> Bob
        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        let pt1 = ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap();
        assert_eq!(pt1, b"msg1");

        // Bob -> Alice
        let (h2, ct2) = ratchet_encrypt(&mut bob, b"msg2", ad).unwrap();
        let pt2 = ratchet_decrypt(&mut alice, &h2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"msg2");

        // Alice -> Bob again
        let (h3, ct3) = ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();
        let pt3 = ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap();
        assert_eq!(pt3, b"msg3");

        // Bob -> Alice again
        let (h4, ct4) = ratchet_encrypt(&mut bob, b"msg4", ad).unwrap();
        let pt4 = ratchet_decrypt(&mut alice, &h4, &ct4, ad).unwrap();
        assert_eq!(pt4, b"msg4");
    }

    #[test]
    fn test_multiple_messages_same_direction() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice sends multiple messages before Bob responds
        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut alice, b"msg2", ad).unwrap();
        let (h3, ct3) = ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();

        // Bob receives them in order
        assert_eq!(ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap(), b"msg1");
        assert_eq!(ratchet_decrypt(&mut bob, &h2, &ct2, ad).unwrap(), b"msg2");
        assert_eq!(ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap(), b"msg3");
    }

    #[test]
    fn test_out_of_order() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut alice, b"msg2", ad).unwrap();
        let (h3, ct3) = ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();

        // Bob receives out of order: 3, 1, 2
        assert_eq!(ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap(), b"msg3");
        assert_eq!(ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap(), b"msg1");
        assert_eq!(ratchet_decrypt(&mut bob, &h2, &ct2, ad).unwrap(), b"msg2");
    }

    #[test]
    fn test_lost_messages() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let (_h1, _ct1) = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        let (_h2, _ct2) = ratchet_encrypt(&mut alice, b"msg2", ad).unwrap();
        let (h3, ct3) = ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();

        // Messages 1 and 2 are lost, Bob only receives 3
        assert_eq!(ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap(), b"msg3");
    }

    #[test]
    fn test_dh_ratchet_advancement() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice -> Bob (uses Alice's initial DH key)
        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        let ratchet_key_1 = h1.ratchet_key.as_bytes().clone();
        ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap();

        // Bob -> Alice (Bob generates new DH key)
        let (h2, ct2) = ratchet_encrypt(&mut bob, b"msg2", ad).unwrap();
        let ratchet_key_2 = h2.ratchet_key.as_bytes().clone();
        ratchet_decrypt(&mut alice, &h2, &ct2, ad).unwrap();

        // Alice -> Bob (Alice generates new DH key)
        let (h3, ct3) = ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();
        let ratchet_key_3 = h3.ratchet_key.as_bytes().clone();
        ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap();

        // Each direction change should produce a new ratchet key
        assert_ne!(ratchet_key_1, ratchet_key_2);
        assert_ne!(ratchet_key_2, ratchet_key_3);
        assert_ne!(ratchet_key_1, ratchet_key_3);
    }

    #[test]
    fn test_wrong_ad_fails() {
        let (mut alice, mut bob) = setup_alice_bob();

        let (header, ct) = ratchet_encrypt(&mut alice, b"secret", b"correct ad").unwrap();
        let result = ratchet_decrypt(&mut bob, &header, &ct, b"wrong ad");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let (header, mut ct) = ratchet_encrypt(&mut alice, b"secret", ad).unwrap();
        ct[0] ^= 0xFF;
        let result = ratchet_decrypt(&mut bob, &header, &ct, ad);
        assert!(result.is_err());
    }

    #[test]
    fn test_out_of_order_across_ratchet_steps() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice sends messages 0, 1
        let (h0, ct0) = ratchet_encrypt(&mut alice, b"a0", ad).unwrap();
        let (h1, ct1) = ratchet_encrypt(&mut alice, b"a1", ad).unwrap();

        // Bob receives only message 0, then responds
        ratchet_decrypt(&mut bob, &h0, &ct0, ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut bob, b"b0", ad).unwrap();

        // Alice receives Bob's response
        ratchet_decrypt(&mut alice, &h2, &ct2, ad).unwrap();

        // Alice sends another message
        let (h3, ct3) = ratchet_encrypt(&mut alice, b"a2", ad).unwrap();

        // Bob now receives the delayed message 1 (from the old ratchet key)
        assert_eq!(ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap(), b"a1");
        // And the new message
        assert_eq!(ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap(), b"a2");
    }

    #[test]
    fn test_header_serialization_roundtrip() {
        let kp = KeyPair::generate();
        let header = MessageHeader {
            ratchet_key: kp.public,
            prev_chain_length: 42,
            message_number: 7,
        };

        let bytes = header.to_bytes();
        let decoded = MessageHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.ratchet_key, decoded.ratchet_key);
        assert_eq!(header.prev_chain_length, decoded.prev_chain_length);
        assert_eq!(header.message_number, decoded.message_number);
    }

    #[test]
    fn test_many_messages_one_direction() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let mut headers_and_cts = Vec::new();
        for i in 0..100 {
            let msg = format!("message {i}");
            let (h, ct) = ratchet_encrypt(&mut alice, msg.as_bytes(), ad).unwrap();
            headers_and_cts.push((h, ct, msg));
        }

        for (h, ct, expected) in &headers_and_cts {
            let pt = ratchet_decrypt(&mut bob, h, ct, ad).unwrap();
            assert_eq!(pt, expected.as_bytes());
        }
    }

    #[test]
    fn test_max_skip_enforcement() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"test-ad".to_vec();

        let mut messages = Vec::new();
        for i in 0..=(MAX_SKIP + 1) {
            let (h, ct) = ratchet_encrypt(&mut alice, format!("msg{i}").as_bytes(), &ad).unwrap();
            messages.push((h, ct));
        }

        let (ref h, ref ct) = messages.last().unwrap();
        let result = ratchet_decrypt(&mut bob, h, ct, &ad);
        assert!(result.is_err(), "should reject when too many messages are skipped");
    }

    #[test]
    fn test_encrypt_decrypt_identity_property() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"prop-test".to_vec();

        let test_cases: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"hello world",
            &[0u8; 1000],
            &[0xFF; 256],
        ];

        for pt in test_cases {
            let (h, ct) = ratchet_encrypt(&mut alice, pt, &ad).unwrap();
            let decrypted = ratchet_decrypt(&mut bob, &h, &ct, &ad).unwrap();
            assert_eq!(decrypted, pt);
        }
    }

    #[test]
    fn test_ratchet_state_consistency_through_serialization() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"serialize-test";

        // Exchange a few messages in both directions to advance the ratchet
        // Alice -> Bob
        let (h, ct) = ratchet_encrypt(&mut alice, b"hello bob", ad).unwrap();
        assert_eq!(ratchet_decrypt(&mut bob, &h, &ct, ad).unwrap(), b"hello bob");

        // Bob -> Alice
        let (h, ct) = ratchet_encrypt(&mut bob, b"hey alice", ad).unwrap();
        assert_eq!(ratchet_decrypt(&mut alice, &h, &ct, ad).unwrap(), b"hey alice");

        // Alice -> Bob (two more to advance counters)
        let (h, ct) = ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();
        assert_eq!(ratchet_decrypt(&mut bob, &h, &ct, ad).unwrap(), b"msg3");

        let (h, ct) = ratchet_encrypt(&mut alice, b"msg4", ad).unwrap();
        assert_eq!(ratchet_decrypt(&mut bob, &h, &ct, ad).unwrap(), b"msg4");

        // Record the next message number Alice will use (visible in the header)
        let (h_before, ct_before) = ratchet_encrypt(&mut alice, b"pre-snapshot", ad).unwrap();
        let alice_msg_num_before = h_before.message_number;
        assert_eq!(ratchet_decrypt(&mut bob, &h_before, &ct_before, ad).unwrap(), b"pre-snapshot");

        // Serialize both states
        let alice_bytes = alice.to_bytes();
        let bob_bytes = bob.to_bytes();

        // Deserialize both states
        let mut alice_restored = RatchetState::from_bytes(&alice_bytes).unwrap();
        let mut bob_restored = RatchetState::from_bytes(&bob_bytes).unwrap();

        // Verify serialization round-trip produces identical bytes
        assert_eq!(alice_restored.to_bytes(), alice_bytes, "Alice state bytes mismatch after round-trip");
        assert_eq!(bob_restored.to_bytes(), bob_bytes, "Bob state bytes mismatch after round-trip");

        // Verify message counters are preserved: the next message from Alice
        // should have message_number = alice_msg_num_before + 1
        let (h_after, ct_after) = ratchet_encrypt(&mut alice_restored, b"post-snapshot", ad).unwrap();
        assert_eq!(
            h_after.message_number,
            alice_msg_num_before + 1,
            "send counter not preserved after serialization round-trip"
        );

        // Bob (restored) can decrypt the message from Alice (restored)
        assert_eq!(
            ratchet_decrypt(&mut bob_restored, &h_after, &ct_after, ad).unwrap(),
            b"post-snapshot"
        );

        // Continue conversation: Bob (restored) -> Alice (restored)
        let (h, ct) = ratchet_encrypt(&mut bob_restored, b"bob reply after restore", ad).unwrap();
        assert_eq!(
            ratchet_decrypt(&mut alice_restored, &h, &ct, ad).unwrap(),
            b"bob reply after restore"
        );

        // Alice (restored) -> Bob (restored) again
        let (h, ct) = ratchet_encrypt(&mut alice_restored, b"alice again", ad).unwrap();
        assert_eq!(
            ratchet_decrypt(&mut bob_restored, &h, &ct, ad).unwrap(),
            b"alice again"
        );

        // Multiple messages in same direction still work
        let (h1, ct1) = ratchet_encrypt(&mut bob_restored, b"batch1", ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut bob_restored, b"batch2", ad).unwrap();
        assert_eq!(ratchet_decrypt(&mut alice_restored, &h1, &ct1, ad).unwrap(), b"batch1");
        assert_eq!(ratchet_decrypt(&mut alice_restored, &h2, &ct2, ad).unwrap(), b"batch2");
    }
}

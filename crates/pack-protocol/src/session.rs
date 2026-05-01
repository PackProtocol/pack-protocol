// Implements: Session state management and SessionCipher
// Source: Derived from X3DH and Double Ratchet protocol flow

use crate::crypto::curve::PublicKey;
use crate::errors::{Result, PackError};
use crate::keys::{IdentityKey, PreKeyBundle};
use crate::message::{PackMessage, PreKeyPackMessage};
use crate::ratchet::{self, RatchetState};
use crate::store::{ProtocolAddress, IdentityKeyStore, PreKeyStore, SignedPreKeyStore, SessionStore, Direction};
use crate::x3dh;

/// A session record holding the current and previous session states.
pub struct SessionRecord {
    pub current: Option<SessionState>,
    pub previous: Vec<SessionState>,
}

impl SessionRecord {
    pub fn new() -> Self {
        Self {
            current: None,
            previous: Vec::new(),
        }
    }

    pub fn from_state(state: SessionState) -> Self {
        Self {
            current: Some(state),
            previous: Vec::new(),
        }
    }

    /// Archive the current session state and set a new one.
    pub fn archive_current_and_set(&mut self, new_state: SessionState) {
        if let Some(old) = self.current.take() {
            self.previous.push(old);
            // Keep bounded history
            while self.previous.len() > 40 {
                self.previous.remove(0);
            }
        }
        self.current = Some(new_state);
    }
}

/// State for a single session.
pub struct SessionState {
    pub ratchet: RatchetState,
    pub local_identity: IdentityKey,
    pub remote_identity: IdentityKey,
    pub alice_base_key: Option<PublicKey>,
    /// True if the local party initiated (is "Alice" in the X3DH sense).
    /// Used to reconstruct the canonical AD = IK_A || IK_B ordering.
    pub is_initiator: bool,
}

impl SessionState {
    /// # Security
    /// Output contains sensitive key material. Must be encrypted at rest.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ratchet_bytes = self.ratchet.to_bytes();
        let mut out = Vec::with_capacity(4 + ratchet_bytes.len() + 32 + 32 + 1 + 32 + 1);
        out.extend_from_slice(&(ratchet_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&ratchet_bytes);
        out.extend_from_slice(self.local_identity.as_bytes());
        out.extend_from_slice(self.remote_identity.as_bytes());
        match &self.alice_base_key {
            Some(k) => { out.push(1); out.extend_from_slice(k.as_bytes()); }
            None => { out.push(0); }
        }
        out.push(if self.is_initiator { 1 } else { 0 });
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(PackError::InvalidMessage("session state too short".into()));
        }
        let ratchet_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut pos = 4;
        if data.len() < pos + ratchet_len + 64 + 1 {
            return Err(PackError::InvalidMessage("session state truncated".into()));
        }
        let ratchet = RatchetState::from_bytes(&data[pos..pos + ratchet_len])?;
        pos += ratchet_len;

        let mut li = [0u8; 32];
        li.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut ri = [0u8; 32];
        ri.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let has_base = data[pos];
        pos += 1;
        let alice_base_key = if has_base == 1 {
            if data.len() < pos + 32 {
                return Err(PackError::InvalidMessage("session state truncated".into()));
            }
            let mut b = [0u8; 32];
            b.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Some(PublicKey::from_bytes_validated(b)?)
        } else { None };

        let is_initiator = if pos < data.len() { data[pos] == 1 } else { false };

        Ok(Self {
            ratchet,
            local_identity: IdentityKey::from_bytes(li)?,
            remote_identity: IdentityKey::from_bytes(ri)?,
            alice_base_key,
            is_initiator,
        })
    }
}

impl SessionRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // current: 1 flag + data, or 0
        match &self.current {
            Some(s) => {
                out.push(1);
                let sb = s.to_bytes();
                out.extend_from_slice(&(sb.len() as u32).to_be_bytes());
                out.extend_from_slice(&sb);
            }
            None => out.push(0),
        }
        // previous count + entries
        out.extend_from_slice(&(self.previous.len() as u32).to_be_bytes());
        for s in &self.previous {
            let sb = s.to_bytes();
            out.extend_from_slice(&(sb.len() as u32).to_be_bytes());
            out.extend_from_slice(&sb);
        }
        out
    }

    pub fn from_bytes_stored(data: &[u8]) -> Result<Self> {
        let mut pos = 0;
        if data.is_empty() {
            return Err(PackError::InvalidMessage("session record empty".into()));
        }
        let has_current = data[pos];
        pos += 1;
        let current = if has_current == 1 {
            if data.len() < pos + 4 {
                return Err(PackError::InvalidMessage("session record truncated".into()));
            }
            let len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            let state = SessionState::from_bytes(&data[pos..pos+len])?;
            pos += len;
            Some(state)
        } else { None };

        if data.len() < pos + 4 {
            return Err(PackError::InvalidMessage("session record truncated".into()));
        }
        let prev_count = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        pos += 4;

        let mut previous = Vec::new();
        for _ in 0..prev_count {
            if data.len() < pos + 4 {
                return Err(PackError::InvalidMessage("session record truncated".into()));
            }
            let len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
            pos += 4;
            let state = SessionState::from_bytes(&data[pos..pos+len])?;
            pos += len;
            previous.push(state);
        }

        Ok(Self { current, previous })
    }
}

/// Process an incoming PreKeyPackMessage to establish a new session.
///
/// This is the responder (Bob) path:
/// 1. Look up our signed pre-key and optional one-time pre-key
/// 2. Run X3DH responder
/// 3. Initialize the Double Ratchet
/// 4. Decrypt the first message
pub async fn process_pre_key_message<S>(
    store: &mut S,
    _our_address: &ProtocolAddress,
    remote_address: &ProtocolAddress,
    message: &PreKeyPackMessage,
) -> Result<Vec<u8>>
where
    S: IdentityKeyStore + PreKeyStore + SignedPreKeyStore + SessionStore,
{
    let our_identity = store.get_identity_key_pair().await?;

    // Verify the sender's identity is trusted
    if !store.is_trusted_identity(remote_address, &message.identity_key, Direction::Receiving).await? {
        return Err(PackError::UntrustedIdentity(remote_address.to_string()));
    }

    // Look up our signed pre-key
    let signed_pre_key = store.get_signed_pre_key(message.signed_pre_key_id).await?;

    // Look up one-time pre-key if referenced
    let one_time_pre_key = if let Some(opk_id) = message.pre_key_id {
        Some(store.get_pre_key(opk_id).await?)
    } else {
        None
    };

    // Run X3DH responder
    let x3dh_result = x3dh::x3dh_respond(
        &our_identity,
        &signed_pre_key,
        one_time_pre_key.as_ref(),
        &message.identity_key,
        &message.base_key,
    )?;

    // Initialize Double Ratchet as responder
    let ratchet = ratchet::ratchet_init_responder(
        x3dh_result.shared_secret,
        signed_pre_key.key_pair,
    );

    let session_state = SessionState {
        ratchet,
        local_identity: our_identity.public.clone(),
        remote_identity: message.identity_key.clone(),
        alice_base_key: Some(message.base_key.clone()),
        is_initiator: false,
    };

    // Create or update session record
    let mut record = store.load_session(remote_address).await?.unwrap_or_else(SessionRecord::new);
    record.archive_current_and_set(session_state);

    // Decrypt the inner message
    let current = record.current.as_mut().unwrap();
    let plaintext = ratchet::ratchet_decrypt(
        &mut current.ratchet,
        &message.message.header,
        &message.message.ciphertext,
        &x3dh_result.associated_data,
    )?;

    // Save session and identity
    store.store_session(remote_address, &record).await?;
    store.save_identity(remote_address, &message.identity_key).await?;

    // Delete one-time pre-key if used
    if let Some(opk_id) = message.pre_key_id {
        store.remove_pre_key(opk_id).await?;
    }

    Ok(plaintext)
}

/// Create a new session and encrypt the first message (initiator / Alice side).
///
/// 1. Run X3DH initiator with the recipient's pre-key bundle
/// 2. Initialize the Double Ratchet
/// 3. Encrypt the first message
/// 4. Wrap in a PreKeyPackMessage
pub async fn create_session_and_encrypt<S>(
    store: &mut S,
    remote_address: &ProtocolAddress,
    their_bundle: &PreKeyBundle,
    plaintext: &[u8],
) -> Result<PreKeyPackMessage>
where
    S: IdentityKeyStore + SessionStore,
{
    let our_identity = store.get_identity_key_pair().await?;

    // Verify bundle signature and identity trust
    if !store.is_trusted_identity(remote_address, &their_bundle.identity_key, Direction::Sending).await? {
        return Err(PackError::UntrustedIdentity(remote_address.to_string()));
    }

    // Run X3DH initiator
    let x3dh_result = x3dh::x3dh_initiate(&our_identity, their_bundle)?;

    // Initialize Double Ratchet as initiator
    let mut ratchet = ratchet::ratchet_init_initiator(
        x3dh_result.shared_secret,
        &their_bundle.signed_pre_key,
    )?;

    // Encrypt the message
    let (header, ciphertext) = ratchet::ratchet_encrypt(
        &mut ratchet,
        plaintext,
        &x3dh_result.associated_data,
    )?;

    let session_state = SessionState {
        ratchet,
        local_identity: our_identity.public.clone(),
        remote_identity: their_bundle.identity_key.clone(),
        alice_base_key: Some(x3dh_result.ephemeral_public.clone()),
        is_initiator: true,
    };

    // Store session
    let mut record = store.load_session(remote_address).await?.unwrap_or_else(SessionRecord::new);
    record.archive_current_and_set(session_state);
    store.store_session(remote_address, &record).await?;
    store.save_identity(remote_address, &their_bundle.identity_key).await?;

    // Build PreKeyPackMessage
    let inner = PackMessage::new(header, ciphertext);
    Ok(PreKeyPackMessage::new(
        their_bundle.signed_pre_key_id,
        their_bundle.one_time_pre_key_id,
        x3dh_result.ephemeral_public,
        our_identity.public,
        inner,
    ))
}

/// Encrypt a message in an existing session.
pub async fn session_encrypt<S>(
    store: &mut S,
    remote_address: &ProtocolAddress,
    plaintext: &[u8],
) -> Result<PackMessage>
where
    S: IdentityKeyStore + SessionStore,
{
    let mut record = store.load_session(remote_address).await?
        .ok_or_else(|| PackError::NoSession(remote_address.to_string()))?;

    let current = record.current.as_mut()
        .ok_or(PackError::SessionNotFound)?;

    let ad = build_associated_data(current);

    let (header, ciphertext) = ratchet::ratchet_encrypt(
        &mut current.ratchet,
        plaintext,
        &ad,
    )?;

    store.store_session(remote_address, &record).await?;
    Ok(PackMessage::new(header, ciphertext))
}

/// Decrypt a regular PackMessage in an existing session.
pub async fn session_decrypt<S>(
    store: &mut S,
    remote_address: &ProtocolAddress,
    message: &PackMessage,
) -> Result<Vec<u8>>
where
    S: IdentityKeyStore + SessionStore,
{
    let mut record = store.load_session(remote_address).await?
        .ok_or_else(|| PackError::NoSession(remote_address.to_string()))?;

    // Try current session first
    if let Some(ref current) = record.current {
        let ad = build_associated_data(current);
        let mut ratchet_clone = current.ratchet.clone();
        match ratchet::ratchet_decrypt(&mut ratchet_clone, &message.header, &message.ciphertext, &ad) {
            Ok(pt) => {
                record.current.as_mut().unwrap().ratchet = ratchet_clone;
                store.store_session(remote_address, &record).await?;
                return Ok(pt);
            }
            Err(_) => {} // ratchet_clone is dropped, original state is unchanged
        }
    }

    // Try previous sessions
    for i in 0..record.previous.len() {
        let ad = build_associated_data(&record.previous[i]);
        let mut ratchet_clone = record.previous[i].ratchet.clone();
        match ratchet::ratchet_decrypt(&mut ratchet_clone, &message.header, &message.ciphertext, &ad) {
            Ok(pt) => {
                record.previous[i].ratchet = ratchet_clone;
                store.store_session(remote_address, &record).await?;
                return Ok(pt);
            }
            Err(_) => {}
        }
    }

    Err(PackError::InvalidMessage("no session could decrypt this message".into()))
}

/// Handle simultaneous initiation: both parties send PreKeyPackMessages to each other.
///
/// When both Alice and Bob initiate sessions at the same time, each receives a
/// PreKeyPackMessage while already having a session. The protocol resolves this
/// by comparing the base keys: the session initiated by the party with the
/// lexicographically higher base key wins and becomes the active session.
/// The other session is archived as a previous state.
pub fn resolve_simultaneous_initiation(
    record: &mut SessionRecord,
    incoming_base_key: &PublicKey,
) -> bool {
    if let Some(ref current) = record.current {
        if let Some(ref our_base_key) = current.alice_base_key {
            if our_base_key.as_bytes() > incoming_base_key.as_bytes() {
                return false;
            }
        }
    }
    true
}

/// Build AD = IK_Alice || IK_Bob (always initiator first, matching X3DH).
fn build_associated_data(state: &SessionState) -> Vec<u8> {
    let mut ad = Vec::with_capacity(64);
    if state.is_initiator {
        ad.extend_from_slice(state.local_identity.as_bytes());
        ad.extend_from_slice(state.remote_identity.as_bytes());
    } else {
        ad.extend_from_slice(state.remote_identity.as_bytes());
        ad.extend_from_slice(state.local_identity.as_bytes());
    }
    ad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::KeyPair;
    use crate::keys::{IdentityKeyPair, SignedPreKey, OneTimePreKey, PreKeyBundle};
    use crate::testing::InMemoryStore;
    use crate::store::ProtocolAddress;

    #[test]
    fn test_session_record_archive() {
        let mut record = SessionRecord::new();
        assert!(record.current.is_none());

        let identity = IdentityKeyPair::generate();
        let remote_identity = IdentityKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let kp = KeyPair::generate();

        let ratchet = ratchet::ratchet_init_responder(shared_secret, kp);
        let state = SessionState {
            ratchet,
            local_identity: identity.public.clone(),
            remote_identity: remote_identity.public.clone(),
            alice_base_key: None,
            is_initiator: false,
        };

        record.archive_current_and_set(state);
        assert!(record.current.is_some());
        assert_eq!(record.previous.len(), 0);

        let kp2 = KeyPair::generate();
        let ratchet2 = ratchet::ratchet_init_responder([0x43; 32], kp2);
        let state2 = SessionState {
            ratchet: ratchet2,
            local_identity: identity.public,
            remote_identity: remote_identity.public,
            alice_base_key: None,
            is_initiator: false,
        };
        record.archive_current_and_set(state2);
        assert!(record.current.is_some());
        assert_eq!(record.previous.len(), 1);
    }

    #[test]
    fn test_session_record_serialization_roundtrip() {
        let identity = IdentityKeyPair::generate();
        let remote_identity = IdentityKeyPair::generate();
        let kp = KeyPair::generate();
        let ratchet_state = ratchet::ratchet_init_responder([0x42; 32], kp);
        let state = SessionState {
            ratchet: ratchet_state,
            local_identity: identity.public.clone(),
            remote_identity: remote_identity.public.clone(),
            alice_base_key: None,
            is_initiator: false,
        };
        let record = SessionRecord::from_state(state);
        let bytes = record.to_bytes();
        let restored = SessionRecord::from_bytes_stored(&bytes).unwrap();
        assert!(restored.current.is_some());
        assert_eq!(restored.previous.len(), 0);
    }

    #[test]
    fn test_ratchet_state_serialization_roundtrip() {
        let kp = KeyPair::generate();
        let their_pub = KeyPair::generate().public;
        let mut state = ratchet::ratchet_init_initiator([0xAB; 32], &their_pub).unwrap();

        let ad = b"test";
        let (h1, ct1) = ratchet::ratchet_encrypt(&mut state, b"hello", ad).unwrap();

        let bytes = state.to_bytes();
        let mut restored = ratchet::RatchetState::from_bytes(&bytes).unwrap();

        let (h2, ct2) = ratchet::ratchet_encrypt(&mut restored, b"world", ad).unwrap();
        assert_eq!(h2.message_number, 1);
    }

    fn make_bundle(
        identity: &IdentityKeyPair,
        spk: &SignedPreKey,
        opk: Option<&OneTimePreKey>,
    ) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: identity.public.clone(),
            signed_pre_key_id: spk.id,
            signed_pre_key: spk.public_key().clone(),
            signed_pre_key_signature: spk.signature,
            one_time_pre_key_id: opk.map(|o| o.id),
            one_time_pre_key: opk.map(|o| o.public_key().clone()),
        }
    }

    #[tokio::test]
    async fn test_full_x3dh_ratchet_message_exchange() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk = OneTimePreKey::generate(100);

        let mut alice_store = InMemoryStore::new(alice_identity, 1);
        let mut bob_store = InMemoryStore::new(bob_identity, 2);

        bob_store.save_signed_pre_key(1, &bob_spk).await.unwrap();
        bob_store.save_pre_key(100, &bob_opk).await.unwrap();

        let alice_addr = ProtocolAddress::new("alice".into(), 1);
        let bob_addr = ProtocolAddress::new("bob".into(), 1);

        let bob_bundle = make_bundle(
            &IdentityKeyPair::from_keys(
                bob_store.get_identity_key_pair().await.unwrap().public,
                crate::crypto::curve::PrivateKey::from_bytes(*bob_store.get_identity_key_pair().await.unwrap().private_key().as_bytes()),
            ),
            &bob_store.get_signed_pre_key(1).await.unwrap(),
            Some(&bob_store.get_pre_key(100).await.unwrap()),
        );

        // Alice sends first message (PreKeyPackMessage)
        let pre_key_msg = create_session_and_encrypt(
            &mut alice_store, &bob_addr, &bob_bundle, b"hello bob!",
        ).await.unwrap();

        // Bob receives and processes
        let plaintext = process_pre_key_message(
            &mut bob_store, &bob_addr, &alice_addr, &pre_key_msg,
        ).await.unwrap();
        assert_eq!(plaintext, b"hello bob!");

        // Bob sends reply (regular PackMessage)
        let reply = session_encrypt(&mut bob_store, &alice_addr, b"hello alice!").await.unwrap();

        // Alice decrypts reply
        let reply_pt = session_decrypt(&mut alice_store, &bob_addr, &reply).await.unwrap();
        assert_eq!(reply_pt, b"hello alice!");

        // Continue conversation — multiple messages back and forth
        for i in 0..5 {
            let msg = format!("alice msg {i}");
            let enc = session_encrypt(&mut alice_store, &bob_addr, msg.as_bytes()).await.unwrap();
            let dec = session_decrypt(&mut bob_store, &alice_addr, &enc).await.unwrap();
            assert_eq!(dec, msg.as_bytes());

            let msg2 = format!("bob msg {i}");
            let enc2 = session_encrypt(&mut bob_store, &alice_addr, msg2.as_bytes()).await.unwrap();
            let dec2 = session_decrypt(&mut alice_store, &bob_addr, &enc2).await.unwrap();
            assert_eq!(dec2, msg2.as_bytes());
        }
    }

    #[test]
    fn test_simultaneous_initiation_resolution() {
        let identity = IdentityKeyPair::generate();
        let remote_identity = IdentityKeyPair::generate();

        let kp1 = KeyPair::generate();
        let base_key_high = PublicKey::from_bytes([0xFF; 32]);
        let base_key_low = PublicKey::from_bytes([0x01; 32]);

        let ratchet_state = ratchet::ratchet_init_responder([0x42; 32], kp1);
        let state = SessionState {
            ratchet: ratchet_state,
            local_identity: identity.public.clone(),
            remote_identity: remote_identity.public.clone(),
            alice_base_key: Some(base_key_high.clone()),
            is_initiator: true,
        };

        let mut record = SessionRecord::from_state(state);

        // Our base key (0xFF) > incoming (0x01): we win, don't accept incoming
        assert!(!resolve_simultaneous_initiation(&mut record, &base_key_low));

        // Our base key (0xFF) < incoming (would need higher): incoming wins
        let kp2 = KeyPair::generate();
        let ratchet_state2 = ratchet::ratchet_init_responder([0x43; 32], kp2);
        let state2 = SessionState {
            ratchet: ratchet_state2,
            local_identity: identity.public,
            remote_identity: remote_identity.public,
            alice_base_key: Some(base_key_low),
            is_initiator: true,
        };
        let mut record2 = SessionRecord::from_state(state2);
        assert!(resolve_simultaneous_initiation(&mut record2, &base_key_high));
    }

    #[tokio::test]
    async fn test_session_renegotiation() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk1 = OneTimePreKey::generate(100);

        let mut alice_store = InMemoryStore::new(alice_identity, 1);
        let mut bob_store = InMemoryStore::new(bob_identity, 2);

        bob_store.save_signed_pre_key(1, &bob_spk).await.unwrap();
        bob_store.save_pre_key(100, &bob_opk1).await.unwrap();

        let alice_addr = ProtocolAddress::new("alice".into(), 1);
        let bob_addr = ProtocolAddress::new("bob".into(), 1);

        let bob_bundle = make_bundle(
            &IdentityKeyPair::from_keys(
                bob_store.get_identity_key_pair().await.unwrap().public,
                crate::crypto::curve::PrivateKey::from_bytes(*bob_store.get_identity_key_pair().await.unwrap().private_key().as_bytes()),
            ),
            &bob_store.get_signed_pre_key(1).await.unwrap(),
            Some(&bob_store.get_pre_key(100).await.unwrap()),
        );

        // First session
        let msg1 = create_session_and_encrypt(
            &mut alice_store, &bob_addr, &bob_bundle, b"first session",
        ).await.unwrap();
        let pt1 = process_pre_key_message(
            &mut bob_store, &bob_addr, &alice_addr, &msg1,
        ).await.unwrap();
        assert_eq!(pt1, b"first session");

        // Renegotiate — Alice creates a new session with a new OPK
        let bob_opk2 = OneTimePreKey::generate(101);
        bob_store.save_pre_key(101, &bob_opk2).await.unwrap();

        let bob_bundle2 = make_bundle(
            &IdentityKeyPair::from_keys(
                bob_store.get_identity_key_pair().await.unwrap().public,
                crate::crypto::curve::PrivateKey::from_bytes(*bob_store.get_identity_key_pair().await.unwrap().private_key().as_bytes()),
            ),
            &bob_store.get_signed_pre_key(1).await.unwrap(),
            Some(&bob_store.get_pre_key(101).await.unwrap()),
        );

        let msg2 = create_session_and_encrypt(
            &mut alice_store, &bob_addr, &bob_bundle2, b"renegotiated session",
        ).await.unwrap();
        let pt2 = process_pre_key_message(
            &mut bob_store, &bob_addr, &alice_addr, &msg2,
        ).await.unwrap();
        assert_eq!(pt2, b"renegotiated session");

        // Verify we can still communicate on the new session
        let reply = session_encrypt(&mut bob_store, &alice_addr, b"reply on new session").await.unwrap();
        let reply_pt = session_decrypt(&mut alice_store, &bob_addr, &reply).await.unwrap();
        assert_eq!(reply_pt, b"reply on new session");
    }
}

use crate::crypto::curve::{PrivateKey, PublicKey};
use crate::errors::{PackError, Result};
use crate::group::{self, SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecord};
use crate::keys::{IdentityKey, IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey};
use crate::message::{PackMessage, PreKeyPackMessage};
use crate::ratchet;
use crate::sealed_sender::{self, SealedSenderResult, SenderCertificate};
use crate::session::{SessionRecord, SessionState};
use crate::store::ProtocolAddress;
use crate::x3dh;

fn copy_identity(ikp: &IdentityKeyPair) -> IdentityKeyPair {
    IdentityKeyPair::from_keys(
        IdentityKey::from_bytes(*ikp.public.as_bytes()).unwrap(),
        PrivateKey::from_bytes(*ikp.private_key().as_bytes()),
    )
}

// ── PackSession ──

pub struct PackSession {
    record: SessionRecord,
    our_identity: IdentityKeyPair,
    our_address: ProtocolAddress,
    remote_address: ProtocolAddress,
    remote_identity: IdentityKey,
    registration_id: u32,
}

impl PackSession {
    /// Create a new session as the initiator (Alice) and encrypt the first message.
    ///
    /// Returns the session and the serialized PreKeyPackMessage to send.
    pub fn initiate(
        our_name: &str,
        our_device_id: u32,
        our_identity: &IdentityKeyPair,
        registration_id: u32,
        remote_name: &str,
        remote_device_id: u32,
        their_bundle: &PreKeyBundle,
        first_message: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let our_address = ProtocolAddress::new(our_name.to_string(), our_device_id);
        let remote_address = ProtocolAddress::new(remote_name.to_string(), remote_device_id);

        let x3dh_result = x3dh::x3dh_initiate(our_identity, their_bundle)?;

        let mut ratchet_state = ratchet::ratchet_init_initiator(
            x3dh_result.shared_secret,
            &their_bundle.signed_pre_key,
        )?;

        let (header, ciphertext) = ratchet::ratchet_encrypt(
            &mut ratchet_state,
            first_message,
            &x3dh_result.associated_data,
        )?;

        let session_state = SessionState {
            ratchet: ratchet_state,
            local_identity: our_identity.public.clone(),
            remote_identity: their_bundle.identity_key.clone(),
            alice_base_key: Some(x3dh_result.ephemeral_public.clone()),
            is_initiator: true,
        };

        let record = SessionRecord::from_state(session_state);

        let inner = PackMessage::new(header, ciphertext);
        let pre_key_msg = PreKeyPackMessage::new(
            their_bundle.signed_pre_key_id,
            their_bundle.one_time_pre_key_id,
            x3dh_result.ephemeral_public,
            our_identity.public.clone(),
            inner,
        );

        let session = Self {
            record,
            our_identity: copy_identity(our_identity),
            our_address,
            remote_address,
            remote_identity: their_bundle.identity_key.clone(),
            registration_id,
        };

        Ok((session, pre_key_msg.serialize()))
    }

    /// Create a new session as the responder (Bob) from an incoming PreKeyPackMessage.
    ///
    /// Returns the session and the decrypted first message.
    pub fn respond(
        our_name: &str,
        our_device_id: u32,
        our_identity: &IdentityKeyPair,
        registration_id: u32,
        remote_name: &str,
        remote_device_id: u32,
        signed_pre_key: &SignedPreKey,
        one_time_pre_key: Option<&OneTimePreKey>,
        pre_key_message_bytes: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let our_address = ProtocolAddress::new(our_name.to_string(), our_device_id);
        let remote_address = ProtocolAddress::new(remote_name.to_string(), remote_device_id);

        let message = PreKeyPackMessage::deserialize(pre_key_message_bytes)?;

        let x3dh_result = x3dh::x3dh_respond(
            our_identity,
            signed_pre_key,
            one_time_pre_key,
            &message.identity_key,
            &message.base_key,
        )?;

        let mut ratchet_state = ratchet::ratchet_init_responder(
            x3dh_result.shared_secret,
            signed_pre_key.key_pair.clone(),
        );

        let plaintext = ratchet::ratchet_decrypt(
            &mut ratchet_state,
            &message.message.header,
            &message.message.ciphertext,
            &x3dh_result.associated_data,
        )?;

        let session_state = SessionState {
            ratchet: ratchet_state,
            local_identity: our_identity.public.clone(),
            remote_identity: message.identity_key.clone(),
            alice_base_key: Some(message.base_key.clone()),
            is_initiator: false,
        };

        let record = SessionRecord::from_state(session_state);

        let session = Self {
            record,
            our_identity: copy_identity(our_identity),
            our_address,
            remote_address,
            remote_identity: message.identity_key.clone(),
            registration_id,
        };

        Ok((session, plaintext))
    }

    /// Encrypt a message in the established session.
    ///
    /// Returns serialized PackMessage bytes.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let current = self
            .record
            .current
            .as_mut()
            .ok_or(PackError::SessionNotFound)?;

        let ad = build_associated_data(current);

        let (header, ciphertext) =
            ratchet::ratchet_encrypt(&mut current.ratchet, plaintext, &ad)?;

        Ok(PackMessage::new(header, ciphertext).serialize())
    }

    /// Decrypt a PackMessage in the established session.
    ///
    /// Takes serialized PackMessage bytes, returns plaintext.
    pub fn decrypt(&mut self, message_bytes: &[u8]) -> Result<Vec<u8>> {
        let message = PackMessage::deserialize(message_bytes)?;

        if let Some(ref current) = self.record.current {
            let ad = build_associated_data(current);
            let mut ratchet_clone = current.ratchet.clone();
            match ratchet::ratchet_decrypt(
                &mut ratchet_clone,
                &message.header,
                &message.ciphertext,
                &ad,
            ) {
                Ok(pt) => {
                    self.record.current.as_mut().unwrap().ratchet = ratchet_clone;
                    return Ok(pt);
                }
                Err(_) => {}
            }
        }

        for i in 0..self.record.previous.len() {
            let ad = build_associated_data(&self.record.previous[i]);
            let mut ratchet_clone = self.record.previous[i].ratchet.clone();
            match ratchet::ratchet_decrypt(
                &mut ratchet_clone,
                &message.header,
                &message.ciphertext,
                &ad,
            ) {
                Ok(pt) => {
                    self.record.previous[i].ratchet = ratchet_clone;
                    return Ok(pt);
                }
                Err(_) => {}
            }
        }

        Err(PackError::InvalidMessage(
            "no session could decrypt this message".into(),
        ))
    }

    pub fn remote_address(&self) -> &ProtocolAddress {
        &self.remote_address
    }

    pub fn our_address(&self) -> &ProtocolAddress {
        &self.our_address
    }

    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }

    pub fn our_identity(&self) -> &IdentityKey {
        &self.our_identity.public
    }

    pub fn remote_identity(&self) -> &IdentityKey {
        &self.remote_identity
    }
}

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

// ── PackGroupSession ──

pub struct PackGroupSession {
    record: SenderKeyRecord,
    distribution_id: String,
}

impl PackGroupSession {
    /// Create a new group session as the sender.
    ///
    /// Returns the session and the serialized SenderKeyDistributionMessage
    /// to send to group members via 1:1 encrypted sessions.
    pub fn create_sender(distribution_id: &str) -> Result<(Self, Vec<u8>)> {
        let mut record = SenderKeyRecord::new();
        let dist_msg =
            group::create_sender_key_distribution_message(distribution_id, &mut record)?;
        let bytes = dist_msg.to_bytes();
        Ok((
            Self {
                record,
                distribution_id: distribution_id.to_string(),
            },
            bytes,
        ))
    }

    /// Create a group session as a receiver from a distribution message.
    pub fn create_receiver(
        distribution_id: &str,
        distribution_message: &[u8],
    ) -> Result<Self> {
        let dist_msg = SenderKeyDistributionMessage::from_bytes(distribution_message)?;
        let mut record = SenderKeyRecord::new();
        group::process_sender_key_distribution_message(&mut record, &dist_msg);
        Ok(Self {
            record,
            distribution_id: distribution_id.to_string(),
        })
    }

    /// Encrypt a message for the group (sender only).
    ///
    /// Returns serialized SenderKeyMessage bytes.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let msg = group::group_encrypt(&mut self.record, plaintext)?;
        Ok(msg.to_bytes())
    }

    /// Decrypt a group message (receiver).
    ///
    /// Takes serialized SenderKeyMessage bytes, returns plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let msg = SenderKeyMessage::from_bytes(ciphertext)?;
        group::group_decrypt(&mut self.record, &msg)
    }

    pub fn distribution_id(&self) -> &str {
        &self.distribution_id
    }
}

// ── PackSealedSender ──

pub struct PackSealedSender;

impl PackSealedSender {
    pub fn encrypt(
        sender_identity: &IdentityKeyPair,
        sender_certificate: &SenderCertificate,
        recipient_identity: &IdentityKey,
        inner_message: &[u8],
        current_time: u64,
    ) -> Result<Vec<u8>> {
        sealed_sender::sealed_sender_encrypt(
            sender_identity,
            sender_certificate,
            recipient_identity,
            inner_message,
            current_time,
        )
    }

    pub fn decrypt(
        our_identity: &IdentityKeyPair,
        ciphertext: &[u8],
        trust_root: &PublicKey,
        current_time: u64,
    ) -> Result<SealedSenderResult> {
        sealed_sender::sealed_sender_decrypt(our_identity, ciphertext, trust_root, current_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::{self, KeyPair};

    #[test]
    fn test_pack_session_full_exchange() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk = OneTimePreKey::generate(100);

        let bob_bundle = PreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk.id,
            signed_pre_key: bob_spk.key_pair.public.clone(),
            signed_pre_key_signature: bob_spk.signature,
            signed_pre_key_timestamp: bob_spk.timestamp,
            one_time_pre_key_id: Some(bob_opk.id),
            one_time_pre_key: Some(bob_opk.key_pair.public.clone()),
        };

        let (mut alice, first_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle,
            b"hello bob!",
        )
        .unwrap();

        let (mut bob, plaintext) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk),
            &first_msg,
        )
        .unwrap();
        assert_eq!(plaintext, b"hello bob!");

        let reply_ct = bob.encrypt(b"hello alice!").unwrap();
        let reply_pt = alice.decrypt(&reply_ct).unwrap();
        assert_eq!(reply_pt, b"hello alice!");

        for i in 0..10 {
            let msg = format!("alice msg {i}");
            let ct = alice.encrypt(msg.as_bytes()).unwrap();
            let pt = bob.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());

            let msg2 = format!("bob msg {i}");
            let ct2 = bob.encrypt(msg2.as_bytes()).unwrap();
            let pt2 = alice.decrypt(&ct2).unwrap();
            assert_eq!(pt2, msg2.as_bytes());
        }
    }

    #[test]
    fn test_pack_session_without_one_time_pre_key() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);

        let bob_bundle = PreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk.id,
            signed_pre_key: bob_spk.key_pair.public.clone(),
            signed_pre_key_signature: bob_spk.signature,
            signed_pre_key_timestamp: bob_spk.timestamp,
            one_time_pre_key_id: None,
            one_time_pre_key: None,
        };

        let (mut alice, first_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle,
            b"no opk",
        )
        .unwrap();

        let (mut bob, plaintext) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, None,
            &first_msg,
        )
        .unwrap();
        assert_eq!(plaintext, b"no opk");

        let ct = bob.encrypt(b"reply").unwrap();
        let pt = alice.decrypt(&ct).unwrap();
        assert_eq!(pt, b"reply");
    }

    #[test]
    fn test_pack_group_session_roundtrip() {
        let (mut sender, dist_bytes) = PackGroupSession::create_sender("group-1").unwrap();
        let mut receiver = PackGroupSession::create_receiver("group-1", &dist_bytes).unwrap();

        for i in 0..5 {
            let msg = format!("group msg {i}");
            let ct = sender.encrypt(msg.as_bytes()).unwrap();
            let pt = receiver.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_pack_group_multiple_receivers() {
        let (mut sender, dist_bytes) = PackGroupSession::create_sender("group-1").unwrap();
        let mut r1 = PackGroupSession::create_receiver("group-1", &dist_bytes).unwrap();
        let mut r2 = PackGroupSession::create_receiver("group-1", &dist_bytes).unwrap();

        let ct = sender.encrypt(b"to all").unwrap();
        assert_eq!(r1.decrypt(&ct).unwrap(), b"to all");
        assert_eq!(r2.decrypt(&ct).unwrap(), b"to all");
    }

    #[test]
    fn test_pack_sealed_sender_roundtrip() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = KeyPair::generate();

        let server_cert = sealed_sender::ServerCertificate {
            key: server_kp.public.clone(),
            id: 1,
        };

        let mut cert = SenderCertificate {
            sender_uuid: "alice-uuid".to_string(),
            sender_device_id: 1,
            sender_identity: alice_identity.public.clone(),
            expiration: 2000,
            server_certificate: server_cert,
            signature: Vec::new(),
        };
        let content = cert.serialize_content();
        let sig = curve::xeddsa_sign(&server_kp.private, &content);
        cert.signature = sig.to_vec();

        let encrypted = PackSealedSender::encrypt(
            &alice_identity,
            &cert,
            &bob_identity.public,
            b"sealed hello",
            1000,
        )
        .unwrap();

        let result =
            PackSealedSender::decrypt(&bob_identity, &encrypted, &server_kp.public, 1000)
                .unwrap();

        assert_eq!(result.sender_uuid, "alice-uuid");
        assert_eq!(result.plaintext, b"sealed hello");
    }
}

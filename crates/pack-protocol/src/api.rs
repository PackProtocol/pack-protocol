use crate::crypto::curve::{PrivateKey, PublicKey};
use crate::errors::{PackError, Result};
use crate::fingerprint::{self, Fingerprint, ScannableFingerprint};
use crate::group::{self, SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecord};
use crate::keys::{IdentityKey, IdentityKeyPair, OneTimePreKey, PQPreKey, PQPreKeyBundle, PreKeyBundle, SignedPreKey};
use crate::message::{CiphertextMessage, PackMessage, PreKeyPackMessage};
use crate::pqxdh;
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

    /// Create a new session as the initiator using PQXDH (post-quantum hybrid).
    pub fn initiate_pqxdh(
        our_name: &str,
        our_device_id: u32,
        our_identity: &IdentityKeyPair,
        registration_id: u32,
        remote_name: &str,
        remote_device_id: u32,
        their_bundle: &PQPreKeyBundle,
        first_message: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let our_address = ProtocolAddress::new(our_name.to_string(), our_device_id);
        let remote_address = ProtocolAddress::new(remote_name.to_string(), remote_device_id);

        let pqxdh_result = pqxdh::pqxdh_initiate(our_identity, their_bundle)?;

        let mut ratchet_state = ratchet::ratchet_init_initiator(
            pqxdh_result.shared_secret,
            &their_bundle.signed_pre_key,
        )?;

        let (header, ciphertext) = ratchet::ratchet_encrypt(
            &mut ratchet_state,
            first_message,
            &pqxdh_result.associated_data,
        )?;

        let session_state = SessionState {
            ratchet: ratchet_state,
            local_identity: our_identity.public.clone(),
            remote_identity: their_bundle.identity_key.clone(),
            alice_base_key: Some(pqxdh_result.ephemeral_public.clone()),
            is_initiator: true,
        };

        let record = SessionRecord::from_state(session_state);

        let inner = PackMessage::new(header, ciphertext);
        let pre_key_msg = PreKeyPackMessage::new_pqxdh(
            their_bundle.signed_pre_key_id,
            their_bundle.one_time_pre_key_id,
            pqxdh_result.ephemeral_public,
            our_identity.public.clone(),
            inner,
            their_bundle.pq_pre_key_id,
            pqxdh_result.kem_ciphertext,
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

    /// Create a new session as the responder from a PQXDH PreKeyPackMessage.
    pub fn respond_pqxdh(
        our_name: &str,
        our_device_id: u32,
        our_identity: &IdentityKeyPair,
        registration_id: u32,
        remote_name: &str,
        remote_device_id: u32,
        signed_pre_key: &SignedPreKey,
        one_time_pre_key: Option<&OneTimePreKey>,
        pq_pre_key: &PQPreKey,
        pre_key_message_bytes: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let our_address = ProtocolAddress::new(our_name.to_string(), our_device_id);
        let remote_address = ProtocolAddress::new(remote_name.to_string(), remote_device_id);

        let message = PreKeyPackMessage::deserialize(pre_key_message_bytes)?;
        if !message.is_pqxdh() {
            return Err(PackError::InvalidMessage("expected PQXDH message (version 2)".into()));
        }

        let kem_ct = message.kem_ciphertext.as_ref()
            .ok_or_else(|| PackError::InvalidMessage("missing KEM ciphertext".into()))?;

        let pqxdh_result = pqxdh::pqxdh_respond(
            our_identity,
            signed_pre_key,
            one_time_pre_key,
            pq_pre_key,
            &message.identity_key,
            &message.base_key,
            kem_ct,
        )?;

        let mut ratchet_state = ratchet::ratchet_init_responder(
            pqxdh_result.shared_secret,
            signed_pre_key.key_pair.clone(),
        );

        let plaintext = ratchet::ratchet_decrypt(
            &mut ratchet_state,
            &message.message.header,
            &message.message.ciphertext,
            &pqxdh_result.associated_data,
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

    /// Decrypt a message that may be either a Standard or PreKey message.
    ///
    /// Checks the type tag byte to determine the message type:
    /// - `0x00` (Standard): decrypts using the existing session ratchet
    /// - `0x01` (PreKey): processes prekey material, archives the current
    ///   session state, establishes a new ratchet, and decrypts
    ///
    /// For the PreKey path, `signed_pre_key` is required and
    /// `one_time_pre_key` is optional (matching X3DH semantics).
    pub fn decrypt_auto(
        &mut self,
        message_bytes: &[u8],
        signed_pre_key: &SignedPreKey,
        one_time_pre_key: Option<&OneTimePreKey>,
    ) -> Result<Vec<u8>> {
        let typed = CiphertextMessage::deserialize(message_bytes)?;
        match typed {
            CiphertextMessage::Standard(message) => {
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
                    "no session could decrypt this standard message".into(),
                ))
            }
            CiphertextMessage::PreKey(pre_key_message) => {
                let x3dh_result = x3dh::x3dh_respond(
                    &self.our_identity,
                    signed_pre_key,
                    one_time_pre_key,
                    &pre_key_message.identity_key,
                    &pre_key_message.base_key,
                )?;

                let mut ratchet_state = ratchet::ratchet_init_responder(
                    x3dh_result.shared_secret,
                    signed_pre_key.key_pair.clone(),
                );

                let plaintext = ratchet::ratchet_decrypt(
                    &mut ratchet_state,
                    &pre_key_message.message.header,
                    &pre_key_message.message.ciphertext,
                    &x3dh_result.associated_data,
                )?;

                let new_state = SessionState {
                    ratchet: ratchet_state,
                    local_identity: self.our_identity.public.clone(),
                    remote_identity: pre_key_message.identity_key.clone(),
                    alice_base_key: Some(pre_key_message.base_key.clone()),
                    is_initiator: false,
                };

                self.record.archive_current_and_set(new_state);
                self.remote_identity = pre_key_message.identity_key;

                Ok(plaintext)
            }
        }
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

    /// Serialize the full session for storage.
    /// Output contains sensitive key material — must be encrypted at rest.
    pub fn to_bytes(&self) -> Vec<u8> {
        let record_bytes = self.record.to_bytes();
        let our_id_pub = self.our_identity.public.as_bytes();
        let our_id_priv = self.our_identity.private_key().as_bytes();
        let our_addr_name = self.our_address.name.as_bytes();
        let remote_addr_name = self.remote_address.name.as_bytes();
        let remote_id = self.remote_identity.as_bytes();

        let mut out = Vec::new();
        out.extend_from_slice(&(record_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&record_bytes);
        out.extend_from_slice(our_id_pub);
        out.extend_from_slice(our_id_priv);
        out.extend_from_slice(&(our_addr_name.len() as u16).to_be_bytes());
        out.extend_from_slice(our_addr_name);
        out.extend_from_slice(&self.our_address.device_id.to_be_bytes());
        out.extend_from_slice(&(remote_addr_name.len() as u16).to_be_bytes());
        out.extend_from_slice(remote_addr_name);
        out.extend_from_slice(&self.remote_address.device_id.to_be_bytes());
        out.extend_from_slice(remote_id);
        out.extend_from_slice(&self.registration_id.to_be_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(PackError::InvalidMessage("pack session too short".into()));
        }
        let mut pos = 0;
        let rec_len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        pos += 4;
        let record = SessionRecord::from_bytes_stored(&data[pos..pos+rec_len])?;
        pos += rec_len;

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&data[pos..pos+32]);
        pos += 32;
        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(&data[pos..pos+32]);
        pos += 32;

        let our_name_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;
        let our_name = std::str::from_utf8(&data[pos..pos+our_name_len])
            .map_err(|_| PackError::InvalidMessage("invalid utf8 in address".into()))?;
        pos += our_name_len;
        let our_device_id = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        pos += 4;

        let remote_name_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;
        let remote_name = std::str::from_utf8(&data[pos..pos+remote_name_len])
            .map_err(|_| PackError::InvalidMessage("invalid utf8 in address".into()))?;
        pos += remote_name_len;
        let remote_device_id = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        pos += 4;

        let mut remote_id_bytes = [0u8; 32];
        remote_id_bytes.copy_from_slice(&data[pos..pos+32]);
        pos += 32;

        let registration_id = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]);

        let our_identity = IdentityKeyPair::from_keys(
            IdentityKey::from_bytes(pub_bytes)?,
            PrivateKey::from_bytes(priv_bytes),
        );

        Ok(Self {
            record,
            our_identity,
            our_address: ProtocolAddress::new(our_name.to_string(), our_device_id),
            remote_address: ProtocolAddress::new(remote_name.to_string(), remote_device_id),
            remote_identity: IdentityKey::from_bytes(remote_id_bytes)?,
            registration_id,
        })
    }

    pub fn to_bytes_encrypted(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>> {
        let plaintext = self.to_bytes();
        let nonce: [u8; 12] = rand::random();
        let ciphertext = crate::crypto::aead::encrypt(storage_key, &nonce, &plaintext, b"pack-session")?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn from_bytes_encrypted(data: &[u8], storage_key: &[u8; 32]) -> Result<Self> {
        if data.len() < 12 {
            return Err(PackError::InvalidMessage("encrypted session too short".into()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[..12]);
        let plaintext = crate::crypto::aead::decrypt(storage_key, &nonce, &data[12..], b"pack-session")?;
        Self::from_bytes(&plaintext)
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
    /// Returns the session and a `SenderKeyDistribution` to deliver to
    /// group members via `PackSealedSender::distribute_sender_key`.
    pub fn create_sender(distribution_id: &str) -> Result<(Self, SenderKeyDistribution)> {
        let mut record = SenderKeyRecord::new();
        let dist_msg =
            group::create_sender_key_distribution_message(distribution_id, &mut record)?;
        let bytes = dist_msg.to_bytes();
        Ok((
            Self {
                record,
                distribution_id: distribution_id.to_string(),
            },
            SenderKeyDistribution(bytes),
        ))
    }

    /// Create a group session as a receiver from a distribution message.
    pub(crate) fn create_receiver(
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

    /// Process SKDM bytes that have already been decrypted through your
    /// own unseal + session decrypt pipeline. Use this when the sealed
    /// sender and session layers are handled separately (e.g. raw cert
    /// format, PreKeyPackMessage session establishment).
    pub fn from_distribution(
        distribution_id: &str,
        skdm_bytes: &[u8],
    ) -> Result<Self> {
        Self::create_receiver(distribution_id, skdm_bytes)
    }

    /// Encrypt a message for the group (sender only).
    ///
    /// Returns serialized SenderKeyMessage bytes.
    /// Use `PackSealedSender::encrypt_message()` instead — it wraps the
    /// output in sealed sender per recipient, which is required by the protocol.
    pub(crate) fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let msg = group::group_encrypt(&mut self.record, plaintext)?;
        Ok(msg.to_bytes())
    }

    /// Decrypt a group message (receiver).
    ///
    /// Takes serialized SenderKeyMessage bytes, returns plaintext.
    /// Use `PackSealedSender::decrypt_message` + `SealedEnvelope::decrypt`
    /// instead — incoming messages must always be sealed sender wrapped.
    pub(crate) fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let msg = SenderKeyMessage::from_bytes(ciphertext)?;
        group::group_decrypt(&mut self.record, &msg)
    }

    /// Encrypt plaintext with the sender key, returning inner ciphertext.
    /// Call once, then wrap the result with `PackSealedSender::encrypt` per
    /// recipient. This advances the chain exactly once regardless of
    /// recipient count.
    pub fn encrypt_for_send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(plaintext)
    }

    pub fn distribution_id(&self) -> &str {
        &self.distribution_id
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let record_bytes = self.record.to_bytes();
        let dist_id = self.distribution_id.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&(record_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&record_bytes);
        out.extend_from_slice(&(dist_id.len() as u16).to_be_bytes());
        out.extend_from_slice(dist_id);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(PackError::InvalidMessage("pack group session too short".into()));
        }
        let mut pos = 0;
        let rec_len = u32::from_be_bytes([data[pos], data[pos+1], data[pos+2], data[pos+3]]) as usize;
        pos += 4;
        let record = SenderKeyRecord::from_bytes(&data[pos..pos+rec_len])?;
        pos += rec_len;
        let dist_len = u16::from_be_bytes([data[pos], data[pos+1]]) as usize;
        pos += 2;
        let distribution_id = std::str::from_utf8(&data[pos..pos+dist_len])
            .map_err(|_| PackError::InvalidMessage("invalid utf8 in distribution id".into()))?;
        Ok(Self {
            record,
            distribution_id: distribution_id.to_string(),
        })
    }

    pub fn to_bytes_encrypted(&self, storage_key: &[u8; 32]) -> Result<Vec<u8>> {
        let plaintext = self.to_bytes();
        let nonce: [u8; 12] = rand::random();
        let ciphertext = crate::crypto::aead::encrypt(storage_key, &nonce, &plaintext, b"pack-group-session")?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn from_bytes_encrypted(data: &[u8], storage_key: &[u8; 32]) -> Result<Self> {
        if data.len() < 12 {
            return Err(PackError::InvalidMessage("encrypted group session too short".into()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[..12]);
        let plaintext = crate::crypto::aead::decrypt(storage_key, &nonce, &data[12..], b"pack-group-session")?;
        Self::from_bytes(&plaintext)
    }
}

// ── Sender key distribution ──

/// Opaque SKDM bytes produced by `PackGroupSession::create_sender`.
/// Can only be consumed by `PackSealedSender::distribute_sender_key`.
pub struct SenderKeyDistribution(Vec<u8>);

impl SenderKeyDistribution {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ── Sealed Sender message types ──

pub struct Recipient<'a> {
    pub address: &'a ProtocolAddress,
    pub identity: &'a IdentityKey,
}

pub struct SealedBlob {
    pub recipient: ProtocolAddress,
    pub ciphertext: Vec<u8>,
}

pub struct SealedEnvelope {
    pub sender_uuid: String,
    pub sender_device_id: u32,
    inner: Vec<u8>,
}

impl SealedEnvelope {
    pub fn sender_uuid(&self) -> &str {
        &self.sender_uuid
    }

    pub fn sender_device_id(&self) -> u32 {
        self.sender_device_id
    }

    pub fn inner_ciphertext(&self) -> Vec<u8> {
        self.inner.clone()
    }

    pub fn from_inner(inner: Vec<u8>) -> Self {
        Self {
            sender_uuid: String::new(),
            sender_device_id: 0,
            inner,
        }
    }

    pub fn decrypt(self, group_session: &mut PackGroupSession) -> Result<Vec<u8>> {
        let msg = SenderKeyMessage::from_bytes(&self.inner)?;
        group::group_decrypt(&mut group_session.record, &msg)
    }
}

// ── PackSealedSender ──

pub struct PackSealedSender;

impl PackSealedSender {
    pub(crate) fn encrypt_with_cert(
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

    pub fn encrypt(
        sender_identity: &IdentityKeyPair,
        raw_cert_blob: &[u8],
        recipient_identity: &IdentityKey,
        inner_message: &[u8],
        current_time: u64,
    ) -> Result<Vec<u8>> {
        sealed_sender::sealed_sender_encrypt_raw_cert(
            sender_identity, raw_cert_blob, recipient_identity, inner_message, current_time,
        )
    }

    pub fn decrypt(
        our_identity: &IdentityKeyPair,
        ciphertext: &[u8],
        trust_root: &PublicKey,
        current_time: u64,
    ) -> Result<SealedSenderResult> {
        sealed_sender::sealed_sender_decrypt_raw_cert(our_identity, ciphertext, trust_root, current_time)
    }

    /// Encrypt a message for all recipients.
    ///
    /// Sender key encrypts the plaintext once, then wraps it in a sealed sender
    /// envelope per recipient. Returns one sealed blob per recipient for delivery.
    /// Takes the raw cert blob from the server as-is.
    pub fn encrypt_message(
        group_session: &mut PackGroupSession,
        sender_identity: &IdentityKeyPair,
        raw_cert_blob: &[u8],
        recipients: &[Recipient],
        plaintext: &[u8],
        current_time: u64,
    ) -> Result<Vec<SealedBlob>> {
        let sender_key_msg = group::group_encrypt(&mut group_session.record, plaintext)?;
        let sender_key_bytes = sender_key_msg.to_bytes();

        let mut result = Vec::with_capacity(recipients.len());
        for r in recipients {
            let sealed = sealed_sender::sealed_sender_encrypt_raw_cert(
                sender_identity,
                raw_cert_blob,
                r.identity,
                &sender_key_bytes,
                current_time,
            )?;
            result.push(SealedBlob {
                recipient: r.address.clone(),
                ciphertext: sealed,
            });
        }

        Ok(result)
    }

    /// Unseal an incoming message.
    ///
    /// Removes the sealed sender envelope, revealing the sender's identity and
    /// an opaque inner ciphertext. Call `SealedEnvelope::decrypt` with the
    /// appropriate group session to recover the plaintext.
    pub fn decrypt_message(
        our_identity: &IdentityKeyPair,
        ciphertext: &[u8],
        trust_root: &PublicKey,
        current_time: u64,
    ) -> Result<SealedEnvelope> {
        let result = sealed_sender::sealed_sender_decrypt_raw_cert(
            our_identity,
            ciphertext,
            trust_root,
            current_time,
        )?;
        Ok(SealedEnvelope {
            sender_uuid: result.sender_uuid,
            sender_device_id: result.sender_device_id,
            inner: result.plaintext,
        })
    }

    /// Distribute a sender key to a recipient via sealed sender + 1:1 session.
    ///
    /// Takes the `SenderKeyDistribution` from `PackGroupSession::create_sender()`
    /// and delivers it encrypted through the 1:1 session with sealed sender wrapping.
    pub fn distribute_sender_key(
        session: &mut PackSession,
        raw_cert_blob: &[u8],
        skdm: &SenderKeyDistribution,
        current_time: u64,
    ) -> Result<Vec<u8>> {
        let session_ciphertext = session.encrypt(&skdm.0)?;
        sealed_sender::sealed_sender_encrypt_raw_cert(
            &session.our_identity,
            raw_cert_blob,
            &session.remote_identity,
            &session_ciphertext,
            current_time,
        )
    }

    /// Receive a sender key distribution from a sealed sender envelope.
    ///
    /// Unseals and session-decrypts the SKDM, then processes it into
    /// a receiver group session for the given distribution ID.
    pub fn receive_sender_key(
        session: &mut PackSession,
        ciphertext: &[u8],
        trust_root: &PublicKey,
        current_time: u64,
        distribution_id: &str,
    ) -> Result<(SealedSenderResult, PackGroupSession)> {
        let unsealed = sealed_sender::sealed_sender_decrypt_raw_cert(
            &session.our_identity,
            ciphertext,
            trust_root,
            current_time,
        )?;
        let skdm_bytes = session.decrypt(&unsealed.plaintext)?;
        let group_session = PackGroupSession::create_receiver(distribution_id, &skdm_bytes)?;
        Ok((
            SealedSenderResult {
                sender_uuid: unsealed.sender_uuid,
                sender_device_id: unsealed.sender_device_id,
                plaintext: skdm_bytes,
            },
            group_session,
        ))
    }
}

// ── PackFingerprint ──

pub struct PackFingerprint;

impl PackFingerprint {
    /// Generate a safety number for a conversation between two parties.
    ///
    /// Identifiers should be stable (e.g. UUID or phone number).
    /// Returns a Fingerprint with both displayable (60-digit) and scannable (QR) forms.
    pub fn generate(
        local_identifier: &str,
        local_identity: &IdentityKey,
        remote_identifier: &str,
        remote_identity: &IdentityKey,
    ) -> Fingerprint {
        fingerprint::generate_fingerprint(
            local_identifier.as_bytes(),
            local_identity,
            remote_identifier.as_bytes(),
            remote_identity,
        )
    }

    /// Generate a safety number from an established session.
    pub fn generate_for_session(
        session: &PackSession,
        local_identifier: &str,
        remote_identifier: &str,
    ) -> Fingerprint {
        Self::generate(
            local_identifier,
            &session.our_identity.public,
            remote_identifier,
            &session.remote_identity,
        )
    }

    /// Verify a scanned fingerprint against the local fingerprint.
    pub fn verify_scanned(
        local: &ScannableFingerprint,
        scanned: &ScannableFingerprint,
    ) -> Result<bool> {
        local.verify(scanned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::{self, KeyPair};

    fn write_protobuf_varint(buf: &mut Vec<u8>, mut val: u64) {
        loop {
            let byte = (val & 0x7F) as u8;
            val >>= 7;
            if val == 0 { buf.push(byte); break; }
            buf.push(byte | 0x80);
        }
    }

    fn create_raw_cert(
        uuid: &str,
        device_id: u32,
        identity: &IdentityKey,
        expiration: u64,
        server_private: &curve::PrivateKey,
    ) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.push(0x0A); // field 1, wire type 2 (bytes): UUID
        write_protobuf_varint(&mut inner, uuid.len() as u64);
        inner.extend_from_slice(uuid.as_bytes());
        inner.push(0x10); // field 2, wire type 0 (varint): device_id
        write_protobuf_varint(&mut inner, device_id as u64);
        inner.push(0x19); // field 3, wire type 1 (fixed64): expiration
        inner.extend_from_slice(&expiration.to_le_bytes());
        inner.push(0x22); // field 4, wire type 2 (bytes): identity key
        write_protobuf_varint(&mut inner, 32);
        inner.extend_from_slice(identity.as_bytes());

        let sig = curve::xeddsa_sign(server_private, &inner);

        let mut out = Vec::new();
        out.push(0x0A); // field 1, wire type 2: inner cert
        write_protobuf_varint(&mut out, inner.len() as u64);
        out.extend_from_slice(&inner);
        out.push(0x12); // field 2, wire type 2: signature
        write_protobuf_varint(&mut out, sig.len() as u64);
        out.extend_from_slice(&sig);
        out
    }

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
        let (mut sender, dist) = PackGroupSession::create_sender("group-1").unwrap();
        let mut receiver = PackGroupSession::create_receiver("group-1", &dist.0).unwrap();

        for i in 0..5 {
            let msg = format!("group msg {i}");
            let ct = sender.encrypt(msg.as_bytes()).unwrap();
            let pt = receiver.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_pack_group_multiple_receivers() {
        let (mut sender, dist) = PackGroupSession::create_sender("group-1").unwrap();
        let mut r1 = PackGroupSession::create_receiver("group-1", &dist.0).unwrap();
        let mut r2 = PackGroupSession::create_receiver("group-1", &dist.0).unwrap();

        let ct = sender.encrypt(b"to all").unwrap();
        assert_eq!(r1.decrypt(&ct).unwrap(), b"to all");
        assert_eq!(r2.decrypt(&ct).unwrap(), b"to all");
    }

    #[test]
    fn test_pack_sealed_sender_roundtrip() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = KeyPair::generate();

        let raw_cert = create_raw_cert(
            "alice-uuid", 1, &alice_identity.public, 2000, &server_kp.private,
        );

        let encrypted = PackSealedSender::encrypt(
            &alice_identity,
            &raw_cert,
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

    #[test]
    fn test_pack_session_serialization_roundtrip() {
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
        ).unwrap();

        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk),
            &first_msg,
        ).unwrap();

        // Exchange a few messages to advance the ratchet
        let ct = bob.encrypt(b"reply").unwrap();
        alice.decrypt(&ct).unwrap();

        // Serialize and restore Alice
        let bytes = alice.to_bytes();
        let mut alice_restored = PackSession::from_bytes(&bytes).unwrap();

        // Verify restored session can still communicate
        let ct2 = alice_restored.encrypt(b"after restore").unwrap();
        let pt2 = bob.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"after restore");
    }

    #[test]
    fn test_pack_session_encrypted_serialization_roundtrip() {
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

        let (alice, _) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle,
            b"hello",
        ).unwrap();

        let storage_key: [u8; 32] = rand::random();
        let encrypted = alice.to_bytes_encrypted(&storage_key).unwrap();
        let restored = PackSession::from_bytes_encrypted(&encrypted, &storage_key).unwrap();
        assert_eq!(restored.registration_id(), 1001);
    }

    #[test]
    fn test_pack_group_session_serialization_roundtrip() {
        let (mut sender, dist) = PackGroupSession::create_sender("group-1").unwrap();

        // Encrypt a message to advance the chain
        let ct = sender.encrypt(b"msg 1").unwrap();

        // Serialize and restore
        let bytes = sender.to_bytes();
        let mut sender_restored = PackGroupSession::from_bytes(&bytes).unwrap();
        assert_eq!(sender_restored.distribution_id(), "group-1");

        // Receiver from original dist message can decrypt messages from restored sender
        let mut receiver = PackGroupSession::create_receiver("group-1", &dist.0).unwrap();
        receiver.decrypt(&ct).unwrap();

        let ct2 = sender_restored.encrypt(b"after restore").unwrap();
        let pt2 = receiver.decrypt(&ct2).unwrap();
        assert_eq!(pt2, b"after restore");
    }

    #[test]
    fn test_pack_group_session_encrypted_serialization_roundtrip() {
        let (sender, _) = PackGroupSession::create_sender("group-2").unwrap();

        let storage_key: [u8; 32] = rand::random();
        let encrypted = sender.to_bytes_encrypted(&storage_key).unwrap();
        let restored = PackGroupSession::from_bytes_encrypted(&encrypted, &storage_key).unwrap();
        assert_eq!(restored.distribution_id(), "group-2");
    }

    #[test]
    fn test_pack_session_pqxdh_full_exchange() {
        use crate::keys::{PQPreKey, PQPreKeyBundle};

        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_identity, 1000);
        let bob_opk = OneTimePreKey::generate(100);
        let bob_pqpk = PQPreKey::generate(200, &bob_identity, 1000);

        let bob_bundle = PQPreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk.id,
            signed_pre_key: bob_spk.key_pair.public.clone(),
            signed_pre_key_signature: bob_spk.signature,
            signed_pre_key_timestamp: bob_spk.timestamp,
            one_time_pre_key_id: Some(bob_opk.id),
            one_time_pre_key: Some(bob_opk.key_pair.public.clone()),
            pq_pre_key_id: bob_pqpk.id,
            pq_pre_key: bob_pqpk.encapsulation_key.clone(),
            pq_pre_key_signature: bob_pqpk.signature,
        };

        let (mut alice, first_msg) = PackSession::initiate_pqxdh(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle,
            b"hello bob pqxdh!",
        ).unwrap();

        let (mut bob, plaintext) = PackSession::respond_pqxdh(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk), &bob_pqpk,
            &first_msg,
        ).unwrap();
        assert_eq!(plaintext, b"hello bob pqxdh!");

        let reply_ct = bob.encrypt(b"hello alice pqxdh!").unwrap();
        let reply_pt = alice.decrypt(&reply_ct).unwrap();
        assert_eq!(reply_pt, b"hello alice pqxdh!");

        for i in 0..5 {
            let msg = format!("pqxdh alice msg {i}");
            let ct = alice.encrypt(msg.as_bytes()).unwrap();
            let pt = bob.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());

            let msg2 = format!("pqxdh bob msg {i}");
            let ct2 = bob.encrypt(msg2.as_bytes()).unwrap();
            let pt2 = alice.decrypt(&ct2).unwrap();
            assert_eq!(pt2, msg2.as_bytes());
        }
    }

    #[test]
    fn test_distribute_and_receive_sender_key() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let server_kp = KeyPair::generate();

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
            b"session init",
        ).unwrap();

        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk),
            &first_msg,
        ).unwrap();

        let raw_cert = create_raw_cert(
            "alice-uuid", 1, &alice_identity.public, 2000, &server_kp.private,
        );

        // Alice creates a group session and distributes the sender key to Bob
        let (mut alice_group, skdm) = PackGroupSession::create_sender("group-1").unwrap();

        let sealed_skdm = PackSealedSender::distribute_sender_key(
            &mut alice, &raw_cert, &skdm, 1000,
        ).unwrap();

        // Bob receives the sender key
        let (result, mut bob_group) = PackSealedSender::receive_sender_key(
            &mut bob, &sealed_skdm, &server_kp.public, 1000, "group-1",
        ).unwrap();

        assert_eq!(result.sender_uuid, "alice-uuid");

        // Now Alice can send group messages that Bob can decrypt
        let bob_addr = ProtocolAddress::new("bob".to_string(), 1);
        let recipients = vec![
            Recipient { address: &bob_addr, identity: &bob_identity.public },
        ];

        let blobs = PackSealedSender::encrypt_message(
            &mut alice_group, &alice_identity, &raw_cert,
            &recipients, b"hello via sender key", 1000,
        ).unwrap();

        let envelope = PackSealedSender::decrypt_message(
            &bob_identity, &blobs[0].ciphertext, &server_kp.public, 1000,
        ).unwrap();
        let plaintext = envelope.decrypt(&mut bob_group).unwrap();
        assert_eq!(plaintext, b"hello via sender key");
    }

    #[test]
    fn test_pack_fingerprint_from_session() {
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

        let (alice_session, first_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle,
            b"init",
        ).unwrap();

        let (bob_session, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, None,
            &first_msg,
        ).unwrap();

        let alice_fp = PackFingerprint::generate_for_session(
            &alice_session, "+14155551234", "+14155555678",
        );
        let bob_fp = PackFingerprint::generate_for_session(
            &bob_session, "+14155555678", "+14155551234",
        );

        // Both sides produce the same display string
        assert_eq!(alice_fp.displayable.display(), bob_fp.displayable.display());
        assert_eq!(alice_fp.displayable.display().len(), 60);

        // QR code verification works both ways
        assert!(PackFingerprint::verify_scanned(
            &alice_fp.scannable, &bob_fp.scannable
        ).unwrap());
        assert!(PackFingerprint::verify_scanned(
            &bob_fp.scannable, &alice_fp.scannable
        ).unwrap());
    }

    #[test]
    fn test_sealed_group_message_roundtrip() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let carol_identity = IdentityKeyPair::generate();
        let server_kp = KeyPair::generate();

        let raw_cert = create_raw_cert(
            "alice-uuid", 1, &alice_identity.public, 2000, &server_kp.private,
        );

        // Alice creates a sender group session
        let (mut alice_group, dist) =
            PackGroupSession::create_sender("group-1").unwrap();

        // Bob and Carol receive the distribution message
        let mut bob_group =
            PackGroupSession::create_receiver("group-1", &dist.0).unwrap();
        let mut carol_group =
            PackGroupSession::create_receiver("group-1", &dist.0).unwrap();

        let bob_addr = ProtocolAddress::new("bob".to_string(), 1);
        let carol_addr = ProtocolAddress::new("carol".to_string(), 1);

        let recipients = vec![
            Recipient { address: &bob_addr, identity: &bob_identity.public },
            Recipient { address: &carol_addr, identity: &carol_identity.public },
        ];

        // Alice encrypts a group message
        let sealed_blobs = PackSealedSender::encrypt_message(
            &mut alice_group,
            &alice_identity,
            &raw_cert,
            &recipients,
            b"hello group!",
            1000,
        ).unwrap();

        assert_eq!(sealed_blobs.len(), 2);
        assert_eq!(sealed_blobs[0].recipient.name, "bob");
        assert_eq!(sealed_blobs[1].recipient.name, "carol");

        // Bob decrypts
        let bob_envelope = PackSealedSender::decrypt_message(
            &bob_identity,
            &sealed_blobs[0].ciphertext,
            &server_kp.public,
            1000,
        ).unwrap();
        assert_eq!(bob_envelope.sender_uuid(), "alice-uuid");
        assert_eq!(bob_envelope.sender_device_id(), 1);
        let bob_plaintext = bob_envelope.decrypt(&mut bob_group).unwrap();
        assert_eq!(bob_plaintext, b"hello group!");

        // Carol decrypts
        let carol_envelope = PackSealedSender::decrypt_message(
            &carol_identity,
            &sealed_blobs[1].ciphertext,
            &server_kp.public,
            1000,
        ).unwrap();
        assert_eq!(carol_envelope.sender_uuid(), "alice-uuid");
        let carol_plaintext = carol_envelope.decrypt(&mut carol_group).unwrap();
        assert_eq!(carol_plaintext, b"hello group!");

        // Multiple messages work (sender key chain advances)
        for i in 0..5 {
            let msg = format!("group msg {i}");
            let blobs = PackSealedSender::encrypt_message(
                &mut alice_group,
                &alice_identity,
                &raw_cert,
                &recipients,
                msg.as_bytes(),
                1000,
            ).unwrap();

            let env = PackSealedSender::decrypt_message(
                &bob_identity, &blobs[0].ciphertext, &server_kp.public, 1000,
            ).unwrap();
            assert_eq!(env.decrypt(&mut bob_group).unwrap(), msg.as_bytes());

            let env = PackSealedSender::decrypt_message(
                &carol_identity, &blobs[1].ciphertext, &server_kp.public, 1000,
            ).unwrap();
            assert_eq!(env.decrypt(&mut carol_group).unwrap(), msg.as_bytes());
        }
    }

    #[test]
    fn test_sealed_group_wrong_recipient_fails() {
        let alice_identity = IdentityKeyPair::generate();
        let bob_identity = IdentityKeyPair::generate();
        let eve_identity = IdentityKeyPair::generate();
        let server_kp = KeyPair::generate();

        let raw_cert = create_raw_cert(
            "alice-uuid", 1, &alice_identity.public, 2000, &server_kp.private,
        );

        let (mut alice_group, _dist) =
            PackGroupSession::create_sender("group-1").unwrap();
        let bob_addr = ProtocolAddress::new("bob".to_string(), 1);
        let recipients = vec![
            Recipient { address: &bob_addr, identity: &bob_identity.public },
        ];

        let blobs = PackSealedSender::encrypt_message(
            &mut alice_group, &alice_identity, &raw_cert,
            &recipients, b"for bob only", 1000,
        ).unwrap();

        // Eve tries to unseal Bob's blob — should fail (wrong identity key)
        let result = PackSealedSender::decrypt_message(
            &eve_identity, &blobs[0].ciphertext, &server_kp.public, 1000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_auto_standard_message() {
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
        ).unwrap();

        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk),
            &first_msg,
        ).unwrap();

        // Bob sends a standard message, Alice decrypts with decrypt_auto
        let reply_ct = bob.encrypt(b"standard msg").unwrap();
        let tagged = CiphertextMessage::Standard(PackMessage::deserialize(&reply_ct).unwrap()).serialize();
        let alice_spk = SignedPreKey::generate(1, &alice_identity, 1000);
        let pt = alice.decrypt_auto(&tagged, &alice_spk, None).unwrap();
        assert_eq!(pt, b"standard msg");
    }

    #[test]
    fn test_decrypt_auto_prekey_message() {
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

        // Alice initiates, producing a PreKeyPackMessage
        let (mut alice, first_msg_bytes) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle,
            b"hello via prekey!",
        ).unwrap();

        // Bob has an empty session and uses decrypt_auto with the tagged prekey message
        let pre_key_msg = PreKeyPackMessage::deserialize(&first_msg_bytes).unwrap();
        let tagged = CiphertextMessage::PreKey(pre_key_msg).serialize();

        // Create a fresh bob session from a prior exchange so we can test the
        // "existing session receives a new PreKey" path
        let bob_spk2 = SignedPreKey::generate(2, &bob_identity, 1000);
        let bob_opk2 = OneTimePreKey::generate(200);
        let bob_bundle2 = PreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk2.id,
            signed_pre_key: bob_spk2.key_pair.public.clone(),
            signed_pre_key_signature: bob_spk2.signature,
            signed_pre_key_timestamp: bob_spk2.timestamp,
            one_time_pre_key_id: Some(bob_opk2.id),
            one_time_pre_key: Some(bob_opk2.key_pair.public.clone()),
        };
        let (_, old_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle2,
            b"old session",
        ).unwrap();
        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk2, Some(&bob_opk2),
            &old_msg,
        ).unwrap();

        // Now bob has an existing session with alice. Alice initiated a new one
        // (first_msg_bytes). Bob uses decrypt_auto to handle the PreKey message.
        let pt = bob.decrypt_auto(&tagged, &bob_spk, Some(&bob_opk)).unwrap();
        assert_eq!(pt, b"hello via prekey!");

        // Verify the session was updated — bob can now encrypt and alice can decrypt
        let reply_ct = bob.encrypt(b"reply after rekey").unwrap();
        let reply_pt = alice.decrypt(&reply_ct).unwrap();
        assert_eq!(reply_pt, b"reply after rekey");
    }

    #[test]
    fn test_decrypt_auto_rejects_unknown_type() {
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

        let (_, first_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle,
            b"init",
        ).unwrap();
        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk),
            &first_msg,
        ).unwrap();

        // Unknown type tag
        let bad_msg = vec![0xFF, 0x01, 0x02, 0x03];
        let result = bob.decrypt_auto(&bad_msg, &bob_spk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_auto_empty_input() {
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

        let (_, first_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle, b"init",
        ).unwrap();
        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk), &first_msg,
        ).unwrap();

        let result = bob.decrypt_auto(&[], &bob_spk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_auto_prekey_without_opk() {
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

        let (mut alice, first_msg_bytes) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle, b"no opk prekey",
        ).unwrap();

        let pre_key_msg = PreKeyPackMessage::deserialize(&first_msg_bytes).unwrap();
        let tagged = CiphertextMessage::PreKey(pre_key_msg).serialize();

        // Bob with a prior session, receives PreKey without OPK
        let bob_spk2 = SignedPreKey::generate(2, &bob_identity, 1000);
        let bob_bundle2 = PreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk2.id,
            signed_pre_key: bob_spk2.key_pair.public.clone(),
            signed_pre_key_signature: bob_spk2.signature,
            signed_pre_key_timestamp: bob_spk2.timestamp,
            one_time_pre_key_id: None,
            one_time_pre_key: None,
        };
        let (_, old_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle2, b"old",
        ).unwrap();
        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk2, None, &old_msg,
        ).unwrap();

        let pt = bob.decrypt_auto(&tagged, &bob_spk, None).unwrap();
        assert_eq!(pt, b"no opk prekey");

        let reply_ct = bob.encrypt(b"reply no opk").unwrap();
        let reply_pt = alice.decrypt(&reply_ct).unwrap();
        assert_eq!(reply_pt, b"reply no opk");
    }

    #[test]
    fn test_decrypt_auto_multiple_standard_then_rekey() {
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
            "bob", 1, &bob_bundle, b"init",
        ).unwrap();
        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk), &first_msg,
        ).unwrap();

        // Several standard messages via decrypt_auto
        for i in 0..5 {
            let msg = format!("standard {i}");
            let ct = bob.encrypt(msg.as_bytes()).unwrap();
            let tagged = CiphertextMessage::Standard(PackMessage::deserialize(&ct).unwrap()).serialize();
            let pt = alice.decrypt_auto(&tagged, &SignedPreKey::generate(1, &alice_identity, 1000), None).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        // Now alice re-initiates (simulating session refresh)
        let bob_spk2 = SignedPreKey::generate(2, &bob_identity, 1000);
        let bob_opk2 = OneTimePreKey::generate(200);
        let bob_bundle2 = PreKeyBundle {
            identity_key: bob_identity.public.clone(),
            signed_pre_key_id: bob_spk2.id,
            signed_pre_key: bob_spk2.key_pair.public.clone(),
            signed_pre_key_signature: bob_spk2.signature,
            signed_pre_key_timestamp: bob_spk2.timestamp,
            one_time_pre_key_id: Some(bob_opk2.id),
            one_time_pre_key: Some(bob_opk2.key_pair.public.clone()),
        };
        let (mut alice2, rekey_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle2, b"rekeyed!",
        ).unwrap();

        let pre_key_msg = PreKeyPackMessage::deserialize(&rekey_msg).unwrap();
        let tagged = CiphertextMessage::PreKey(pre_key_msg).serialize();
        let pt = bob.decrypt_auto(&tagged, &bob_spk2, Some(&bob_opk2)).unwrap();
        assert_eq!(pt, b"rekeyed!");

        // Continue with standard messages on the new session
        for i in 0..3 {
            let msg = format!("post-rekey {i}");
            let ct = bob.encrypt(msg.as_bytes()).unwrap();
            let pt = alice2.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn test_decrypt_auto_corrupted_standard_message() {
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

        let (_, first_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle, b"init",
        ).unwrap();
        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk), &first_msg,
        ).unwrap();

        // Standard type tag but garbage payload
        let mut corrupted = vec![0x00];
        corrupted.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]);
        let result = bob.decrypt_auto(&corrupted, &bob_spk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_auto_sender_key_type_rejected() {
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

        let (_, first_msg) = PackSession::initiate(
            "alice", 1, &alice_identity, 1001,
            "bob", 1, &bob_bundle, b"init",
        ).unwrap();
        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk), &first_msg,
        ).unwrap();

        // Sender key message type byte (0x74) — must be rejected
        let sender_key_bytes = vec![0x74, 0x01, 0x02, 0x03, 0x04];
        let result = bob.decrypt_auto(&sender_key_bytes, &bob_spk, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_auto_session_state_preserved_on_standard_failure() {
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
            "bob", 1, &bob_bundle, b"init",
        ).unwrap();
        let (mut bob, _) = PackSession::respond(
            "bob", 1, &bob_identity, 1002,
            "alice", 1,
            &bob_spk, Some(&bob_opk), &first_msg,
        ).unwrap();

        // Send a valid message
        let ct = bob.encrypt(b"valid msg").unwrap();
        let tagged = CiphertextMessage::Standard(PackMessage::deserialize(&ct).unwrap()).serialize();

        // Try to decrypt garbage first — should fail but not corrupt session
        let mut garbage_tagged = vec![0x00];
        garbage_tagged.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]);
        let _ = alice.decrypt_auto(&garbage_tagged, &SignedPreKey::generate(1, &alice_identity, 1000), None);

        // Original valid message should still decrypt
        let pt = alice.decrypt_auto(&tagged, &SignedPreKey::generate(1, &alice_identity, 1000), None).unwrap();
        assert_eq!(pt, b"valid msg");
    }
}

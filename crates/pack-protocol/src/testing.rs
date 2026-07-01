// In-memory store implementation for testing

use std::collections::HashMap;
use async_trait::async_trait;

use crate::crypto::curve::KeyPair;
use crate::errors::{Result, PackError};
use crate::group::SenderKeyRecord;
use crate::keys::{IdentityKey, IdentityKeyPair, OneTimePreKey, SignedPreKey};
use crate::session::SessionRecord;
use crate::store::*;

pub struct InMemoryStore {
    identity_key_pair: IdentityKeyPair,
    registration_id: u32,
    identities: HashMap<String, IdentityKey>,
    pre_keys: HashMap<u32, OneTimePreKey>,
    signed_pre_keys: HashMap<u32, SignedPreKey>,
    sessions: HashMap<String, Vec<u8>>,
    sender_keys: HashMap<String, Vec<u8>>,
}

impl InMemoryStore {
    pub fn new(identity_key_pair: IdentityKeyPair, registration_id: u32) -> Self {
        Self {
            identity_key_pair,
            registration_id,
            identities: HashMap::new(),
            pre_keys: HashMap::new(),
            signed_pre_keys: HashMap::new(),
            sessions: HashMap::new(),
            sender_keys: HashMap::new(),
        }
    }
}

fn addr_key(address: &ProtocolAddress) -> String {
    format!("{}:{}", address.name, address.device_id)
}

#[async_trait]
impl IdentityKeyStore for InMemoryStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        let pub_bytes = *self.identity_key_pair.public.as_bytes();
        let priv_bytes = *self.identity_key_pair.private_key().as_bytes();
        Ok(IdentityKeyPair::from_keys(
            IdentityKey::from_bytes(pub_bytes).unwrap(),
            crate::crypto::curve::PrivateKey::from_bytes(priv_bytes),
        ))
    }

    async fn get_local_registration_id(&self) -> Result<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool> {
        let key = addr_key(address);
        let changed = self.identities.get(&key).map_or(false, |existing| existing != identity);
        self.identities.insert(key, identity.clone());
        Ok(changed)
    }

    async fn is_trusted_identity(&self, address: &ProtocolAddress, identity: &IdentityKey, _direction: Direction) -> Result<bool> {
        match self.identities.get(&addr_key(address)) {
            None => Ok(true),
            Some(existing) => Ok(existing == identity),
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>> {
        Ok(self.identities.get(&addr_key(address)).cloned())
    }
}

#[async_trait]
impl PreKeyStore for InMemoryStore {
    async fn get_pre_key(&self, id: u32) -> Result<OneTimePreKey> {
        let opk = self.pre_keys.get(&id)
            .ok_or_else(|| PackError::InvalidMessage(format!("pre-key {id} not found")))?;
        let pub_bytes = *opk.public_key().as_bytes();
        let priv_bytes = *opk.private_key().as_bytes();
        Ok(OneTimePreKey {
            id: opk.id,
            key_pair: KeyPair {
                public: crate::crypto::curve::PublicKey::from_bytes(pub_bytes),
                private: crate::crypto::curve::PrivateKey::from_bytes(priv_bytes),
            },
        })
    }

    async fn save_pre_key(&mut self, id: u32, record: &OneTimePreKey) -> Result<()> {
        let pub_bytes = *record.public_key().as_bytes();
        let priv_bytes = *record.private_key().as_bytes();
        self.pre_keys.insert(id, OneTimePreKey {
            id: record.id,
            key_pair: KeyPair {
                public: crate::crypto::curve::PublicKey::from_bytes(pub_bytes),
                private: crate::crypto::curve::PrivateKey::from_bytes(priv_bytes),
            },
        });
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: u32) -> Result<()> {
        self.pre_keys.remove(&id);
        Ok(())
    }
}

#[async_trait]
impl SignedPreKeyStore for InMemoryStore {
    async fn get_signed_pre_key(&self, id: u32) -> Result<SignedPreKey> {
        let spk = self.signed_pre_keys.get(&id)
            .ok_or_else(|| PackError::InvalidMessage(format!("signed pre-key {id} not found")))?;
        let pub_bytes = *spk.public_key().as_bytes();
        let priv_bytes = *spk.private_key().as_bytes();
        Ok(SignedPreKey {
            id: spk.id,
            key_pair: KeyPair {
                public: crate::crypto::curve::PublicKey::from_bytes(pub_bytes),
                private: crate::crypto::curve::PrivateKey::from_bytes(priv_bytes),
            },
            signature: spk.signature,
            timestamp: spk.timestamp,
        })
    }

    async fn save_signed_pre_key(&mut self, id: u32, record: &SignedPreKey) -> Result<()> {
        let pub_bytes = *record.public_key().as_bytes();
        let priv_bytes = *record.private_key().as_bytes();
        self.signed_pre_keys.insert(id, SignedPreKey {
            id: record.id,
            key_pair: KeyPair {
                public: crate::crypto::curve::PublicKey::from_bytes(pub_bytes),
                private: crate::crypto::curve::PrivateKey::from_bytes(priv_bytes),
            },
            signature: record.signature,
            timestamp: record.timestamp,
        });
        Ok(())
    }
}

#[async_trait]
impl SessionStore for InMemoryStore {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>> {
        let key = addr_key(address);
        match self.sessions.get(&key) {
            Some(data) => Ok(Some(SessionRecord::from_bytes_stored(data)?)),
            None => Ok(None),
        }
    }

    async fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<()> {
        let key = addr_key(address);
        self.sessions.insert(key, record.to_bytes());
        Ok(())
    }
}

#[async_trait]
impl SenderKeyStore for InMemoryStore {
    async fn store_sender_key(&mut self, sender: &ProtocolAddress, distribution_id: &str, record: &SenderKeyRecord) -> Result<()> {
        let key = format!("{}:{}:{}", sender.name, sender.device_id, distribution_id);
        self.sender_keys.insert(key, record.to_bytes());
        Ok(())
    }

    async fn load_sender_key(&self, sender: &ProtocolAddress, distribution_id: &str) -> Result<Option<SenderKeyRecord>> {
        let key = format!("{}:{}:{}", sender.name, sender.device_id, distribution_id);
        match self.sender_keys.get(&key) {
            Some(data) => Ok(Some(SenderKeyRecord::from_bytes(data)?)),
            None => Ok(None),
        }
    }
}

impl ProtocolStore for InMemoryStore {}

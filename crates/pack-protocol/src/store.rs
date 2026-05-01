// Implements: Storage trait definitions for persistent state
// Source: Application-level concern; the specs define what must be persisted, not how

use async_trait::async_trait;

use crate::errors::Result;
use crate::keys::{IdentityKey, IdentityKeyPair, SignedPreKey, OneTimePreKey};
use crate::session::SessionRecord;
use crate::group::SenderKeyRecord;

/// Address identifying a specific device of a specific user.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ProtocolAddress {
    pub name: String,
    pub device_id: u32,
}

impl ProtocolAddress {
    pub fn new(name: String, device_id: u32) -> Self {
        Self { name, device_id }
    }
}

impl std::fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.name, self.device_id)
    }
}

/// Direction of a message, used for trust decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Sending,
    Receiving,
}

/// Identity key storage (X3DH §2.1 — IK must be persisted permanently).
#[async_trait]
pub trait IdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair>;
    async fn get_local_registration_id(&self) -> Result<u32>;
    async fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<bool>;
    async fn is_trusted_identity(&self, address: &ProtocolAddress, identity: &IdentityKey, direction: Direction) -> Result<bool>;
    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>>;
}

/// One-time pre-key storage (X3DH §2.3 — must be deletable after use).
#[async_trait]
pub trait PreKeyStore {
    async fn get_pre_key(&self, id: u32) -> Result<OneTimePreKey>;
    async fn save_pre_key(&mut self, id: u32, record: &OneTimePreKey) -> Result<()>;
    async fn remove_pre_key(&mut self, id: u32) -> Result<()>;
}

/// Signed pre-key storage (X3DH §2.2 — rotated periodically).
#[async_trait]
pub trait SignedPreKeyStore {
    async fn get_signed_pre_key(&self, id: u32) -> Result<SignedPreKey>;
    async fn save_signed_pre_key(&mut self, id: u32, record: &SignedPreKey) -> Result<()>;
}

/// Session storage (Double Ratchet §3.1 — ratchet state must survive app restart).
#[async_trait]
pub trait SessionStore {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<Option<SessionRecord>>;
    async fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> Result<()>;
}

/// Sender key storage for group messaging.
#[async_trait]
pub trait SenderKeyStore {
    async fn store_sender_key(&mut self, sender: &ProtocolAddress, distribution_id: &str, record: &SenderKeyRecord) -> Result<()>;
    async fn load_sender_key(&self, sender: &ProtocolAddress, distribution_id: &str) -> Result<Option<SenderKeyRecord>>;
}

/// Combined protocol store trait.
pub trait ProtocolStore:
    IdentityKeyStore + PreKeyStore + SignedPreKeyStore + SessionStore + SenderKeyStore
{
}

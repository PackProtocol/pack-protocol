use std::slice;

use pack_protocol::crypto::curve::PublicKey;
use pack_protocol::errors::{Result as PackResult, PackError};
use pack_protocol::keys::{IdentityKey, IdentityKeyPair, OneTimePreKey, SignedPreKey};
use pack_protocol::session::{self, SessionRecord};
use pack_protocol::store::{
    Direction, IdentityKeyStore, PreKeyStore, ProtocolAddress, SessionStore, SignedPreKeyStore,
};

use crate::error::PackFfiError;
use crate::handles;

// Callback return codes for store operations
const STORE_OK: i32 = 0;

// ── Store callback types ──

type LoadSessionCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    name: *const u8,
    name_len: usize,
    device_id: u32,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> i32;

type StoreSessionCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    name: *const u8,
    name_len: usize,
    device_id: u32,
    data: *const u8,
    data_len: usize,
) -> i32;

type GetIdentityKeyPairCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    out_public: *mut u8,
    out_private: *mut u8,
) -> i32;

type GetRegistrationIdCb =
    unsafe extern "C" fn(ctx: *mut std::ffi::c_void, out_id: *mut u32) -> i32;

type SaveIdentityCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    name: *const u8,
    name_len: usize,
    device_id: u32,
    identity: *const u8,
    out_changed: *mut u8,
) -> i32;

type IsTrustedIdentityCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    name: *const u8,
    name_len: usize,
    device_id: u32,
    identity: *const u8,
    direction: u8,
    out_trusted: *mut u8,
) -> i32;

type GetIdentityCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    name: *const u8,
    name_len: usize,
    device_id: u32,
    out_identity: *mut u8,
    out_found: *mut u8,
) -> i32;

type GetPreKeyCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    id: u32,
    out_public: *mut u8,
    out_private: *mut u8,
) -> i32;

type RemovePreKeyCb =
    unsafe extern "C" fn(ctx: *mut std::ffi::c_void, id: u32) -> i32;

type GetSignedPreKeyCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    id: u32,
    out_public: *mut u8,
    out_private: *mut u8,
    out_signature: *mut u8,
    out_timestamp: *mut u64,
) -> i32;

type StoreSenderKeyCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    sender_name: *const u8,
    sender_name_len: usize,
    sender_device_id: u32,
    distribution_id: *const u8,
    distribution_id_len: usize,
    data: *const u8,
    data_len: usize,
) -> i32;

type LoadSenderKeyCb = unsafe extern "C" fn(
    ctx: *mut std::ffi::c_void,
    sender_name: *const u8,
    sender_name_len: usize,
    sender_device_id: u32,
    distribution_id: *const u8,
    distribution_id_len: usize,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> i32;

#[repr(C)]
pub struct PackSessionStoreCallbacks {
    ctx: *mut std::ffi::c_void,
    load_session: LoadSessionCb,
    store_session: StoreSessionCb,
    get_identity_key_pair: GetIdentityKeyPairCb,
    get_registration_id: GetRegistrationIdCb,
    save_identity: SaveIdentityCb,
    is_trusted_identity: IsTrustedIdentityCb,
    get_identity: GetIdentityCb,
    get_pre_key: GetPreKeyCb,
    remove_pre_key: RemovePreKeyCb,
    get_signed_pre_key: GetSignedPreKeyCb,
    store_sender_key: StoreSenderKeyCb,
    load_sender_key: LoadSenderKeyCb,
}

struct FfiStore {
    cbs: PackSessionStoreCallbacks,
}

// Safety: FfiStore is only used within a single-threaded tokio runtime created
// inline in each FFI function. The raw pointers (ctx) are never shared across threads.
unsafe impl Send for FfiStore {}
unsafe impl Sync for FfiStore {}

#[async_trait::async_trait]
impl SessionStore for FfiStore {
    async fn load_session(&self, address: &ProtocolAddress) -> PackResult<Option<SessionRecord>> {
        let name = address.name.as_bytes();
        let mut len: usize = 0;
        let rc = unsafe {
            (self.cbs.load_session)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                address.device_id,
                std::ptr::null_mut(),
                0,
                &mut len,
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage("load_session callback failed".into()));
        }
        if len == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; len];
        let mut actual_len: usize = 0;
        let rc = unsafe {
            (self.cbs.load_session)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                address.device_id,
                buf.as_mut_ptr(),
                buf.len(),
                &mut actual_len,
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage("load_session callback failed".into()));
        }
        buf.truncate(actual_len);
        Ok(Some(SessionRecord::from_bytes_stored(&buf)?))
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> PackResult<()> {
        let name = address.name.as_bytes();
        let data = record.to_bytes();
        let rc = unsafe {
            (self.cbs.store_session)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                address.device_id,
                data.as_ptr(),
                data.len(),
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage("store_session callback failed".into()));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl IdentityKeyStore for FfiStore {
    async fn get_identity_key_pair(&self) -> PackResult<IdentityKeyPair> {
        let mut pub_bytes = [0u8; 32];
        let mut priv_bytes = [0u8; 32];
        let rc = unsafe {
            (self.cbs.get_identity_key_pair)(
                self.cbs.ctx,
                pub_bytes.as_mut_ptr(),
                priv_bytes.as_mut_ptr(),
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage(
                "get_identity_key_pair callback failed".into(),
            ));
        }
        Ok(IdentityKeyPair::from_keys(
            IdentityKey::from_bytes(pub_bytes)?,
            pack_protocol::crypto::curve::PrivateKey::from_bytes(priv_bytes),
        ))
    }

    async fn get_local_registration_id(&self) -> PackResult<u32> {
        let mut id: u32 = 0;
        let rc =
            unsafe { (self.cbs.get_registration_id)(self.cbs.ctx, &mut id) };
        if rc != STORE_OK {
            return Err(PackError::Storage(
                "get_registration_id callback failed".into(),
            ));
        }
        Ok(id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> PackResult<bool> {
        let name = address.name.as_bytes();
        let mut changed: u8 = 0;
        let rc = unsafe {
            (self.cbs.save_identity)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                address.device_id,
                identity.as_bytes().as_ptr(),
                &mut changed,
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage("save_identity callback failed".into()));
        }
        Ok(changed != 0)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> PackResult<bool> {
        let name = address.name.as_bytes();
        let dir_byte = match direction {
            Direction::Sending => 0u8,
            Direction::Receiving => 1u8,
        };
        let mut trusted: u8 = 0;
        let rc = unsafe {
            (self.cbs.is_trusted_identity)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                address.device_id,
                identity.as_bytes().as_ptr(),
                dir_byte,
                &mut trusted,
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage(
                "is_trusted_identity callback failed".into(),
            ));
        }
        Ok(trusted != 0)
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> PackResult<Option<IdentityKey>> {
        let name = address.name.as_bytes();
        let mut identity = [0u8; 32];
        let mut found: u8 = 0;
        let rc = unsafe {
            (self.cbs.get_identity)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                address.device_id,
                identity.as_mut_ptr(),
                &mut found,
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage("get_identity callback failed".into()));
        }
        if found == 0 {
            Ok(None)
        } else {
            Ok(Some(IdentityKey::from_bytes(identity)?))
        }
    }
}

#[async_trait::async_trait]
impl PreKeyStore for FfiStore {
    async fn get_pre_key(&self, id: u32) -> PackResult<OneTimePreKey> {
        let mut pub_bytes = [0u8; 32];
        let mut priv_bytes = [0u8; 32];
        let rc = unsafe {
            (self.cbs.get_pre_key)(
                self.cbs.ctx,
                id,
                pub_bytes.as_mut_ptr(),
                priv_bytes.as_mut_ptr(),
            )
        };
        if rc != STORE_OK {
            return Err(PackError::InvalidMessage(format!(
                "pre-key {id} not found"
            )));
        }
        Ok(OneTimePreKey {
            id,
            key_pair: pack_protocol::crypto::curve::KeyPair {
                public: PublicKey::from_bytes_validated(pub_bytes)?,
                private: pack_protocol::crypto::curve::PrivateKey::from_bytes(priv_bytes),
            },
        })
    }

    async fn save_pre_key(&mut self, _id: u32, _record: &OneTimePreKey) -> PackResult<()> {
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: u32) -> PackResult<()> {
        let rc = unsafe { (self.cbs.remove_pre_key)(self.cbs.ctx, id) };
        if rc != STORE_OK {
            return Err(PackError::Storage("remove_pre_key callback failed".into()));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl SignedPreKeyStore for FfiStore {
    async fn get_signed_pre_key(&self, id: u32) -> PackResult<SignedPreKey> {
        let mut pub_bytes = [0u8; 32];
        let mut priv_bytes = [0u8; 32];
        let mut sig_bytes = [0u8; 64];
        let mut timestamp: u64 = 0;
        let rc = unsafe {
            (self.cbs.get_signed_pre_key)(
                self.cbs.ctx,
                id,
                pub_bytes.as_mut_ptr(),
                priv_bytes.as_mut_ptr(),
                sig_bytes.as_mut_ptr(),
                &mut timestamp,
            )
        };
        if rc != STORE_OK {
            return Err(PackError::InvalidMessage(format!(
                "signed pre-key {id} not found"
            )));
        }
        Ok(SignedPreKey {
            id,
            key_pair: pack_protocol::crypto::curve::KeyPair {
                public: PublicKey::from_bytes_validated(pub_bytes)?,
                private: pack_protocol::crypto::curve::PrivateKey::from_bytes(priv_bytes),
            },
            signature: sig_bytes,
            timestamp,
        })
    }

    async fn save_signed_pre_key(&mut self, _id: u32, _record: &SignedPreKey) -> PackResult<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl pack_protocol::store::SenderKeyStore for FfiStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: &str,
        record: &pack_protocol::group::SenderKeyRecord,
    ) -> PackResult<()> {
        let name = sender.name.as_bytes();
        let dist = distribution_id.as_bytes();
        let data = record.to_bytes();
        let rc = unsafe {
            (self.cbs.store_sender_key)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                sender.device_id,
                dist.as_ptr(),
                dist.len(),
                data.as_ptr(),
                data.len(),
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage("store_sender_key callback failed".into()));
        }
        Ok(())
    }

    async fn load_sender_key(
        &self,
        sender: &ProtocolAddress,
        distribution_id: &str,
    ) -> PackResult<Option<pack_protocol::group::SenderKeyRecord>> {
        let name = sender.name.as_bytes();
        let dist = distribution_id.as_bytes();
        let mut len: usize = 0;
        let rc = unsafe {
            (self.cbs.load_sender_key)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                sender.device_id,
                dist.as_ptr(),
                dist.len(),
                std::ptr::null_mut(),
                0,
                &mut len,
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage("load_sender_key callback failed".into()));
        }
        if len == 0 {
            return Ok(None);
        }
        let mut buf = vec![0u8; len];
        let mut actual_len: usize = 0;
        let rc = unsafe {
            (self.cbs.load_sender_key)(
                self.cbs.ctx,
                name.as_ptr(),
                name.len(),
                sender.device_id,
                dist.as_ptr(),
                dist.len(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut actual_len,
            )
        };
        if rc != STORE_OK {
            return Err(PackError::Storage("load_sender_key callback failed".into()));
        }
        buf.truncate(actual_len);
        Ok(Some(pack_protocol::group::SenderKeyRecord::from_bytes(&buf)?))
    }
}

impl pack_protocol::store::ProtocolStore for FfiStore {}

// ── FFI functions ──

#[no_mangle]
pub unsafe extern "C" fn pack_session_encrypt(
    callbacks: *const PackSessionStoreCallbacks,
    remote_name: *const u8,
    remote_name_len: usize,
    remote_device_id: u32,
    plaintext: *const u8,
    plaintext_len: usize,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if callbacks.is_null() || remote_name.is_null() || plaintext.is_null() {
        return PackFfiError::InvalidArgument;
    }

    let cbs = std::ptr::read(callbacks);
    let mut store = FfiStore { cbs };
    let name = match std::str::from_utf8(slice::from_raw_parts(remote_name, remote_name_len)) {
        Ok(s) => s.to_string(),
        Err(_) => return PackFfiError::InvalidArgument,
    };
    let addr = ProtocolAddress::new(name, remote_device_id);
    let pt = slice::from_raw_parts(plaintext, plaintext_len);

    let rt = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return PackFfiError::InternalError,
    };
    match rt.block_on(session::session_encrypt(&mut store, &addr, pt)) {
        Ok(msg) => {
            let bytes = msg.serialize();
            if !handles::write_bytes(&bytes, out_buf, buf_len, out_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pack_session_decrypt(
    callbacks: *const PackSessionStoreCallbacks,
    remote_name: *const u8,
    remote_name_len: usize,
    remote_device_id: u32,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if callbacks.is_null() || remote_name.is_null() || ciphertext.is_null() {
        return PackFfiError::InvalidArgument;
    }

    let cbs = std::ptr::read(callbacks);
    let mut store = FfiStore { cbs };
    let name = match std::str::from_utf8(slice::from_raw_parts(remote_name, remote_name_len)) {
        Ok(s) => s.to_string(),
        Err(_) => return PackFfiError::InvalidArgument,
    };
    let addr = ProtocolAddress::new(name, remote_device_id);
    let ct_bytes = slice::from_raw_parts(ciphertext, ciphertext_len);

    let msg = match pack_protocol::message::PackMessage::deserialize(ct_bytes) {
        Ok(m) => m,
        Err(e) => return PackFfiError::from(e),
    };

    let rt = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return PackFfiError::InternalError,
    };
    match rt.block_on(session::session_decrypt(&mut store, &addr, &msg)) {
        Ok(pt) => {
            if !handles::write_bytes(&pt, out_buf, buf_len, out_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pack_session_process_pre_key_message(
    callbacks: *const PackSessionStoreCallbacks,
    our_name: *const u8,
    our_name_len: usize,
    our_device_id: u32,
    remote_name: *const u8,
    remote_name_len: usize,
    remote_device_id: u32,
    message: *const u8,
    message_len: usize,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if callbacks.is_null() || our_name.is_null() || remote_name.is_null() || message.is_null() {
        return PackFfiError::InvalidArgument;
    }

    let cbs = std::ptr::read(callbacks);
    let mut store = FfiStore { cbs };

    let our_name_str =
        match std::str::from_utf8(slice::from_raw_parts(our_name, our_name_len)) {
            Ok(s) => s.to_string(),
            Err(_) => return PackFfiError::InvalidArgument,
        };
    let remote_name_str =
        match std::str::from_utf8(slice::from_raw_parts(remote_name, remote_name_len)) {
            Ok(s) => s.to_string(),
            Err(_) => return PackFfiError::InvalidArgument,
        };
    let our_addr = ProtocolAddress::new(our_name_str, our_device_id);
    let remote_addr = ProtocolAddress::new(remote_name_str, remote_device_id);

    let msg_bytes = slice::from_raw_parts(message, message_len);
    let pre_key_msg = match pack_protocol::message::PreKeyPackMessage::deserialize(msg_bytes) {
        Ok(m) => m,
        Err(e) => return PackFfiError::from(e),
    };

    let rt = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return PackFfiError::InternalError,
    };
    match rt.block_on(session::process_pre_key_message(
        &mut store,
        &our_addr,
        &remote_addr,
        &pre_key_msg,
    )) {
        Ok(pt) => {
            if !handles::write_bytes(&pt, out_buf, buf_len, out_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

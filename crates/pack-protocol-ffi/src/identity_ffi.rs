use std::slice;

use pack_protocol::crypto::curve::KeyPair;
use pack_protocol::keys::{IdentityKeyPair, IdentityKey};

use crate::error::PackFfiError;
use crate::handles;

// ── IdentityKeyPair ──

#[no_mangle]
pub extern "C" fn pack_identity_key_pair_generate(
    out: *mut *mut IdentityKeyPair,
) -> PackFfiError {
    if !handles::write_out(out, IdentityKeyPair::generate()) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_identity_key_pair_destroy(handle: *mut IdentityKeyPair) {
    handles::destroy(handle);
}

#[no_mangle]
pub unsafe extern "C" fn pack_identity_key_pair_get_public(
    handle: *const IdentityKeyPair,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let pair = &*handle;
    let bytes = pair.public.as_bytes();
    if !handles::write_bytes(bytes, out_buf, buf_len, out_len) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_identity_key_pair_sign(
    handle: *const IdentityKeyPair,
    message: *const u8,
    message_len: usize,
    out_sig: *mut u8,
    sig_buf_len: usize,
    out_sig_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() || message.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let pair = &*handle;
    let msg = slice::from_raw_parts(message, message_len);
    let sig = pair.sign(msg);
    if !handles::write_bytes(&sig, out_sig, sig_buf_len, out_sig_len) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

// ── IdentityKey (public only) ──

#[no_mangle]
pub unsafe extern "C" fn pack_identity_key_from_bytes(
    data: *const u8,
    data_len: usize,
    out: *mut *mut IdentityKey,
) -> PackFfiError {
    if data.is_null() || data_len != 32 {
        return PackFfiError::InvalidArgument;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(slice::from_raw_parts(data, 32));
    let key = match IdentityKey::from_bytes(bytes) {
        Ok(k) => k,
        Err(e) => return PackFfiError::from(e),
    };
    if !handles::write_out(out, key) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_identity_key_destroy(handle: *mut IdentityKey) {
    handles::destroy(handle);
}

#[no_mangle]
pub unsafe extern "C" fn pack_identity_key_get_bytes(
    handle: *const IdentityKey,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let key = &*handle;
    if !handles::write_bytes(key.as_bytes(), out_buf, buf_len, out_len) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_identity_key_verify(
    handle: *const IdentityKey,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> PackFfiError {
    if handle.is_null() || message.is_null() || signature.is_null() || signature_len != 64 {
        return PackFfiError::InvalidArgument;
    }
    let key = &*handle;
    let msg = slice::from_raw_parts(message, message_len);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(slice::from_raw_parts(signature, 64));
    match key.verify(msg, &sig) {
        Ok(()) => PackFfiError::Ok,
        Err(e) => PackFfiError::from(e),
    }
}

// ── KeyPair (X25519) ──

#[no_mangle]
pub extern "C" fn pack_keypair_generate(
    out: *mut *mut KeyPair,
) -> PackFfiError {
    if !handles::write_out(out, KeyPair::generate()) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_keypair_destroy(handle: *mut KeyPair) {
    handles::destroy(handle);
}

#[no_mangle]
pub unsafe extern "C" fn pack_keypair_get_public(
    handle: *const KeyPair,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let kp = &*handle;
    if !handles::write_bytes(kp.public.as_bytes(), out_buf, buf_len, out_len) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

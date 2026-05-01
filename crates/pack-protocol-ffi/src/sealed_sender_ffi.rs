use std::slice;

use pack_protocol::crypto::curve::PublicKey;
use pack_protocol::keys::{IdentityKey, IdentityKeyPair};
use pack_protocol::sealed_sender;

use crate::error::PackFfiError;
use crate::handles;

#[no_mangle]
pub unsafe extern "C" fn pack_sealed_sender_encrypt(
    sender_identity: *const IdentityKeyPair,
    sender_cert_data: *const u8,
    sender_cert_len: usize,
    recipient_key: *const IdentityKey,
    inner_message: *const u8,
    inner_message_len: usize,
    current_time: u64,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if sender_identity.is_null() || sender_cert_data.is_null()
        || recipient_key.is_null() || inner_message.is_null()
    {
        return PackFfiError::InvalidArgument;
    }
    let cert_data = slice::from_raw_parts(sender_cert_data, sender_cert_len);
    let cert = match sealed_sender::SenderCertificate::deserialize(cert_data) {
        Ok(c) => c,
        Err(e) => return PackFfiError::from(e),
    };
    let msg = slice::from_raw_parts(inner_message, inner_message_len);

    match sealed_sender::sealed_sender_encrypt(
        &*sender_identity,
        &cert,
        &*recipient_key,
        msg,
        current_time,
    ) {
        Ok(encrypted) => {
            if !handles::write_bytes(&encrypted, out_buf, buf_len, out_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pack_sealed_sender_decrypt(
    our_identity: *const IdentityKeyPair,
    ciphertext: *const u8,
    ciphertext_len: usize,
    trust_root_data: *const u8,
    trust_root_len: usize,
    current_time: u64,
    out_sender_uuid_buf: *mut u8,
    sender_uuid_buf_len: usize,
    out_sender_uuid_len: *mut usize,
    out_message_buf: *mut u8,
    message_buf_len: usize,
    out_message_len: *mut usize,
) -> PackFfiError {
    if our_identity.is_null() || ciphertext.is_null() || trust_root_data.is_null() {
        return PackFfiError::InvalidArgument;
    }
    if trust_root_len != 32 {
        return PackFfiError::InvalidArgument;
    }
    let ct = slice::from_raw_parts(ciphertext, ciphertext_len);
    let mut tr_bytes = [0u8; 32];
    tr_bytes.copy_from_slice(slice::from_raw_parts(trust_root_data, 32));
    let trust_root = match PublicKey::from_bytes_validated(tr_bytes) {
        Ok(k) => k,
        Err(e) => return PackFfiError::from(e),
    };

    match sealed_sender::sealed_sender_decrypt(&*our_identity, ct, &trust_root, current_time) {
        Ok(result) => {
            let sender_bytes = result.sender_uuid.as_bytes();
            if !handles::write_bytes(sender_bytes, out_sender_uuid_buf, sender_uuid_buf_len, out_sender_uuid_len) {
                return PackFfiError::InvalidArgument;
            }
            if !handles::write_bytes(&result.plaintext, out_message_buf, message_buf_len, out_message_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

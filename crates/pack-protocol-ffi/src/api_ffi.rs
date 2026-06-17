use std::slice;

use pack_protocol::api::{PackGroupSession, PackSealedSender, PackSession};
use pack_protocol::crypto::curve::PublicKey;
use pack_protocol::keys::{IdentityKey, IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey};
use pack_protocol::sealed_sender::SenderCertificate;

use crate::error::PackFfiError;
use crate::handles;

// ── PackSession ──

#[no_mangle]
pub unsafe extern "C" fn pack_session_initiate(
    our_name: *const u8,
    our_name_len: usize,
    our_device_id: u32,
    our_identity: *const IdentityKeyPair,
    registration_id: u32,
    remote_name: *const u8,
    remote_name_len: usize,
    remote_device_id: u32,
    bundle: *const PreKeyBundle,
    first_message: *const u8,
    first_message_len: usize,
    out_session: *mut *mut PackSession,
    out_msg_buf: *mut u8,
    msg_buf_len: usize,
    out_msg_len: *mut usize,
) -> PackFfiError {
    if our_name.is_null()
        || our_identity.is_null()
        || remote_name.is_null()
        || bundle.is_null()
        || first_message.is_null()
    {
        return PackFfiError::InvalidArgument;
    }

    let our_name_str =
        match std::str::from_utf8(slice::from_raw_parts(our_name, our_name_len)) {
            Ok(s) => s,
            Err(_) => return PackFfiError::InvalidArgument,
        };
    let remote_name_str =
        match std::str::from_utf8(slice::from_raw_parts(remote_name, remote_name_len)) {
            Ok(s) => s,
            Err(_) => return PackFfiError::InvalidArgument,
        };
    let pt = slice::from_raw_parts(first_message, first_message_len);

    match PackSession::initiate(
        our_name_str,
        our_device_id,
        &*our_identity,
        registration_id,
        remote_name_str,
        remote_device_id,
        &*bundle,
        pt,
    ) {
        Ok((session, msg_bytes)) => {
            if !handles::write_out(out_session, session) {
                return PackFfiError::InvalidArgument;
            }
            if !handles::write_bytes(&msg_bytes, out_msg_buf, msg_buf_len, out_msg_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pack_session_respond(
    our_name: *const u8,
    our_name_len: usize,
    our_device_id: u32,
    our_identity: *const IdentityKeyPair,
    registration_id: u32,
    remote_name: *const u8,
    remote_name_len: usize,
    remote_device_id: u32,
    signed_pre_key: *const SignedPreKey,
    one_time_pre_key: *const OneTimePreKey,
    pre_key_message: *const u8,
    pre_key_message_len: usize,
    out_session: *mut *mut PackSession,
    out_pt_buf: *mut u8,
    pt_buf_len: usize,
    out_pt_len: *mut usize,
) -> PackFfiError {
    if our_name.is_null()
        || our_identity.is_null()
        || remote_name.is_null()
        || signed_pre_key.is_null()
        || pre_key_message.is_null()
    {
        return PackFfiError::InvalidArgument;
    }

    let our_name_str =
        match std::str::from_utf8(slice::from_raw_parts(our_name, our_name_len)) {
            Ok(s) => s,
            Err(_) => return PackFfiError::InvalidArgument,
        };
    let remote_name_str =
        match std::str::from_utf8(slice::from_raw_parts(remote_name, remote_name_len)) {
            Ok(s) => s,
            Err(_) => return PackFfiError::InvalidArgument,
        };
    let msg_bytes = slice::from_raw_parts(pre_key_message, pre_key_message_len);

    let opk = if one_time_pre_key.is_null() {
        None
    } else {
        Some(&*one_time_pre_key)
    };

    match PackSession::respond(
        our_name_str,
        our_device_id,
        &*our_identity,
        registration_id,
        remote_name_str,
        remote_device_id,
        &*signed_pre_key,
        opk,
        msg_bytes,
    ) {
        Ok((session, plaintext)) => {
            if !handles::write_out(out_session, session) {
                return PackFfiError::InvalidArgument;
            }
            if !handles::write_bytes(&plaintext, out_pt_buf, pt_buf_len, out_pt_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pack_session_destroy(handle: *mut PackSession) {
    handles::destroy(handle);
}

#[no_mangle]
pub unsafe extern "C" fn pack_session_encrypt_msg(
    handle: *mut PackSession,
    plaintext: *const u8,
    plaintext_len: usize,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() || plaintext.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let session = &mut *handle;
    let pt = slice::from_raw_parts(plaintext, plaintext_len);

    match session.encrypt(pt) {
        Ok(ct) => {
            if !handles::write_bytes(&ct, out_buf, buf_len, out_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pack_session_decrypt_msg(
    handle: *mut PackSession,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() || ciphertext.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let session = &mut *handle;
    let ct = slice::from_raw_parts(ciphertext, ciphertext_len);

    match session.decrypt(ct) {
        Ok(pt) => {
            if !handles::write_bytes(&pt, out_buf, buf_len, out_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

// ── PackGroupSession ──

#[no_mangle]
pub unsafe extern "C" fn pack_group_session_create_sender(
    distribution_id: *const u8,
    distribution_id_len: usize,
    out_session: *mut *mut PackGroupSession,
    out_dist_buf: *mut u8,
    dist_buf_len: usize,
    out_dist_len: *mut usize,
) -> PackFfiError {
    if distribution_id.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let dist_id = match std::str::from_utf8(slice::from_raw_parts(
        distribution_id,
        distribution_id_len,
    )) {
        Ok(s) => s,
        Err(_) => return PackFfiError::InvalidArgument,
    };

    match PackGroupSession::create_sender(dist_id) {
        Ok((session, skdm)) => {
            if !handles::write_out(out_session, session) {
                return PackFfiError::InvalidArgument;
            }
            if !handles::write_bytes(skdm.as_bytes(), out_dist_buf, dist_buf_len, out_dist_len) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

// pack_group_session_create_receiver removed: receiver creation now goes
// through the sealed sender receive_sender_key path.

#[no_mangle]
pub unsafe extern "C" fn pack_group_session_destroy(handle: *mut PackGroupSession) {
    handles::destroy(handle);
}

// pack_group_session_encrypt and pack_group_session_decrypt removed:
// group messages must go through sealed sender. Use
// pack_sealed_sender_encrypt_group_message / pack_sealed_sender_unseal_group_message
// which enforce the sealed sender wrapping.

// ── PackSealedSender ──

#[no_mangle]
pub unsafe extern "C" fn pack_sealed_sender_encrypt_msg(
    sender_identity: *const IdentityKeyPair,
    sender_cert_data: *const u8,
    sender_cert_len: usize,
    recipient_key_data: *const u8,
    current_time: u64,
    inner_message: *const u8,
    inner_message_len: usize,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if sender_identity.is_null()
        || sender_cert_data.is_null()
        || recipient_key_data.is_null()
        || inner_message.is_null()
    {
        return PackFfiError::InvalidArgument;
    }

    let cert_data = slice::from_raw_parts(sender_cert_data, sender_cert_len);
    let cert = match SenderCertificate::deserialize(cert_data) {
        Ok(c) => c,
        Err(e) => return PackFfiError::from(e),
    };

    let mut rk_bytes = [0u8; 32];
    rk_bytes.copy_from_slice(slice::from_raw_parts(recipient_key_data, 32));
    let recipient_ik = match IdentityKey::from_bytes(rk_bytes) {
        Ok(k) => k,
        Err(e) => return PackFfiError::from(e),
    };

    let msg = slice::from_raw_parts(inner_message, inner_message_len);

    match PackSealedSender::encrypt(&*sender_identity, &cert, &recipient_ik, msg, current_time) {
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
pub unsafe extern "C" fn pack_sealed_sender_decrypt_msg(
    our_identity: *const IdentityKeyPair,
    ciphertext: *const u8,
    ciphertext_len: usize,
    trust_root_data: *const u8,
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

    let ct = slice::from_raw_parts(ciphertext, ciphertext_len);
    let mut tr_bytes = [0u8; 32];
    tr_bytes.copy_from_slice(slice::from_raw_parts(trust_root_data, 32));
    let trust_root = match PublicKey::from_bytes_validated(tr_bytes) {
        Ok(k) => k,
        Err(e) => return PackFfiError::from(e),
    };

    match PackSealedSender::decrypt(&*our_identity, ct, &trust_root, current_time) {
        Ok(result) => {
            let sender_bytes = result.sender_uuid.as_bytes();
            if !handles::write_bytes(
                sender_bytes,
                out_sender_uuid_buf,
                sender_uuid_buf_len,
                out_sender_uuid_len,
            ) {
                return PackFfiError::InvalidArgument;
            }
            if !handles::write_bytes(
                &result.plaintext,
                out_message_buf,
                message_buf_len,
                out_message_len,
            ) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

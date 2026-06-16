use std::slice;

use pack_protocol::group::{
    self, SenderKeyDistributionMessage, SenderKeyRecord,
};

use crate::error::PackFfiError;
use crate::handles;

#[no_mangle]
pub extern "C" fn pack_sender_key_record_create(
    out: *mut *mut SenderKeyRecord,
) -> PackFfiError {
    if !handles::write_out(out, SenderKeyRecord::new()) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_sender_key_record_destroy(handle: *mut SenderKeyRecord) {
    handles::destroy(handle);
}

#[no_mangle]
pub unsafe extern "C" fn pack_create_sender_key_distribution_message(
    distribution_id: *const u8,
    distribution_id_len: usize,
    record: *mut SenderKeyRecord,
    out: *mut *mut SenderKeyDistributionMessage,
) -> PackFfiError {
    if distribution_id.is_null() || record.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let dist_id = match std::str::from_utf8(slice::from_raw_parts(distribution_id, distribution_id_len)) {
        Ok(s) => s,
        Err(_) => return PackFfiError::InvalidArgument,
    };
    let rec = &mut *record;
    match group::create_sender_key_distribution_message(dist_id, rec) {
        Ok(msg) => {
            if !handles::write_out(out, msg) {
                return PackFfiError::InvalidArgument;
            }
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn pack_sender_key_distribution_message_destroy(
    handle: *mut SenderKeyDistributionMessage,
) {
    handles::destroy(handle);
}

#[no_mangle]
pub unsafe extern "C" fn pack_sender_key_distribution_message_serialize(
    handle: *const SenderKeyDistributionMessage,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let msg = &*handle;
    let bytes = msg.to_bytes();
    if !handles::write_bytes(&bytes, out_buf, buf_len, out_len) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_process_sender_key_distribution_message(
    record: *mut SenderKeyRecord,
    message_data: *const u8,
    message_len: usize,
) -> PackFfiError {
    if record.is_null() || message_data.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let data = slice::from_raw_parts(message_data, message_len);
    let msg = match SenderKeyDistributionMessage::from_bytes(data) {
        Ok(m) => m,
        Err(e) => return PackFfiError::from(e),
    };
    group::process_sender_key_distribution_message(&mut *record, &msg);
    PackFfiError::Ok
}

// pack_group_encrypt and pack_group_decrypt removed:
// group messages must go through sealed sender. Use the high-level
// PackSealedSender::encrypt_group_message / unseal_group_message API.

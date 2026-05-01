use std::slice;

use pack_protocol::fingerprint::{self, Fingerprint, ScannableFingerprint};
use pack_protocol::keys::IdentityKey;

use crate::error::PackFfiError;
use crate::handles;

#[no_mangle]
pub unsafe extern "C" fn pack_fingerprint_generate(
    local_id: *const u8,
    local_id_len: usize,
    local_key: *const IdentityKey,
    remote_id: *const u8,
    remote_id_len: usize,
    remote_key: *const IdentityKey,
    out: *mut *mut Fingerprint,
) -> PackFfiError {
    if local_id.is_null() || local_key.is_null() || remote_id.is_null() || remote_key.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let local_id_slice = slice::from_raw_parts(local_id, local_id_len);
    let remote_id_slice = slice::from_raw_parts(remote_id, remote_id_len);
    let fp = fingerprint::generate_fingerprint(
        local_id_slice, &*local_key,
        remote_id_slice, &*remote_key,
    );
    if !handles::write_out(out, fp) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_fingerprint_destroy(handle: *mut Fingerprint) {
    handles::destroy(handle);
}

#[no_mangle]
pub unsafe extern "C" fn pack_fingerprint_display(
    handle: *const Fingerprint,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let fp = &*handle;
    let display = fp.displayable.display();
    if !handles::write_bytes(display.as_bytes(), out_buf, buf_len, out_len) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_fingerprint_scannable_bytes(
    handle: *const Fingerprint,
    out_buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> PackFfiError {
    if handle.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let fp = &*handle;
    let bytes = fp.scannable.to_bytes();
    if !handles::write_bytes(&bytes, out_buf, buf_len, out_len) {
        return PackFfiError::InvalidArgument;
    }
    PackFfiError::Ok
}

#[no_mangle]
pub unsafe extern "C" fn pack_scannable_fingerprint_verify(
    ours: *const u8,
    ours_len: usize,
    theirs: *const u8,
    theirs_len: usize,
    out_match: *mut bool,
) -> PackFfiError {
    if ours.is_null() || theirs.is_null() || out_match.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let ours_data = slice::from_raw_parts(ours, ours_len);
    let theirs_data = slice::from_raw_parts(theirs, theirs_len);

    let our_fp = match ScannableFingerprint::from_bytes(ours_data) {
        Ok(fp) => fp,
        Err(e) => return PackFfiError::from(e),
    };
    let their_fp = match ScannableFingerprint::from_bytes(theirs_data) {
        Ok(fp) => fp,
        Err(e) => return PackFfiError::from(e),
    };

    match our_fp.verify(&their_fp) {
        Ok(result) => {
            *out_match = result;
            PackFfiError::Ok
        }
        Err(e) => PackFfiError::from(e),
    }
}

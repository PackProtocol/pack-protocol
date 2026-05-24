use pack_protocol::keys::{IdentityKeyPair, PQPreKey};

use crate::error::PackFfiError;
use crate::handles;

#[no_mangle]
pub unsafe extern "C" fn pack_pq_prekey_generate(
    id: u32,
    identity: *const IdentityKeyPair,
    timestamp: u64,
    out_seed: *mut u8,
    seed_buf_len: usize,
    out_seed_len: *mut usize,
    out_ek: *mut u8,
    ek_buf_len: usize,
    out_ek_len: *mut usize,
    out_signature: *mut u8,
    sig_buf_len: usize,
    out_sig_len: *mut usize,
) -> PackFfiError {
    if identity.is_null() {
        return PackFfiError::InvalidArgument;
    }
    let ident = &*identity;
    let pq = PQPreKey::generate(id, ident, timestamp);

    let seed = pq.seed_bytes();
    if !handles::write_bytes(&seed, out_seed, seed_buf_len, out_seed_len) {
        return PackFfiError::InvalidArgument;
    }

    let ek = pq.encapsulation_key_bytes();
    if !handles::write_bytes(&ek, out_ek, ek_buf_len, out_ek_len) {
        return PackFfiError::InvalidArgument;
    }

    if !handles::write_bytes(&pq.signature, out_signature, sig_buf_len, out_sig_len) {
        return PackFfiError::InvalidArgument;
    }

    PackFfiError::Ok
}

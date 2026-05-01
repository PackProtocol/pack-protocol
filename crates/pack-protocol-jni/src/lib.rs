// Pack Protocol JNI bindings for Android/Kotlin
//
// JNI entry points for the pack-protocol crate. Each function follows the
// Java_<package>_<class>_<method> naming convention. The Kotlin wrapper
// classes define native methods that map to these.

mod convert;

use jni::JNIEnv;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jlong};

use pack_protocol::keys::{IdentityKeyPair, IdentityKey};
use pack_protocol::fingerprint;
use pack_protocol::group;

use convert::{to_handle, from_handle, from_handle_mut, destroy_handle, throw_error};

// ── IdentityKeyPair ──

#[no_mangle]
pub extern "system" fn Java_org_pack_protocol_IdentityKeyPair_nativeGenerate(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    to_handle(IdentityKeyPair::generate())
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_IdentityKeyPair_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    destroy_handle::<IdentityKeyPair>(handle);
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_IdentityKeyPair_nativeGetPublicKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let pair: &IdentityKeyPair = match from_handle(handle) {
        Some(p) => p,
        None => {
            let _ = throw_error(&mut env, "Invalid handle");
            return std::ptr::null_mut();
        }
    };
    let bytes = pair.public.as_bytes();
    match env.byte_array_from_slice(bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_IdentityKeyPair_nativeSign<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    message: JByteArray<'local>,
) -> jbyteArray {
    let pair: &IdentityKeyPair = match from_handle(handle) {
        Some(p) => p,
        None => {
            let _ = throw_error(&mut env, "Invalid handle");
            return std::ptr::null_mut();
        }
    };
    let msg_bytes = match env.convert_byte_array(&message) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let sig = pair.sign(&msg_bytes);
    match env.byte_array_from_slice(&sig) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ── Fingerprint ──

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_Fingerprint_nativeGenerate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    local_id: JByteArray<'local>,
    local_key: JByteArray<'local>,
    remote_id: JByteArray<'local>,
    remote_key: JByteArray<'local>,
) -> jbyteArray {
    let local_id_bytes = match env.convert_byte_array(&local_id) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let local_key_bytes = match env.convert_byte_array(&local_key) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let remote_id_bytes = match env.convert_byte_array(&remote_id) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let remote_key_bytes = match env.convert_byte_array(&remote_key) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    if local_key_bytes.len() != 32 || remote_key_bytes.len() != 32 {
        let _ = throw_error(&mut env, "Invalid key length");
        return std::ptr::null_mut();
    }

    let mut lk = [0u8; 32];
    lk.copy_from_slice(&local_key_bytes);
    let mut rk = [0u8; 32];
    rk.copy_from_slice(&remote_key_bytes);

    let local_ik = match IdentityKey::from_bytes(lk) {
        Ok(k) => k,
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            return std::ptr::null_mut();
        }
    };
    let remote_ik = match IdentityKey::from_bytes(rk) {
        Ok(k) => k,
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            return std::ptr::null_mut();
        }
    };

    let fp = fingerprint::generate_fingerprint(
        &local_id_bytes,
        &local_ik,
        &remote_id_bytes,
        &remote_ik,
    );

    let display = fp.displayable.display();
    match env.byte_array_from_slice(display.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ── Group (Sender Key) ──

#[no_mangle]
pub extern "system" fn Java_org_pack_protocol_GroupCipher_nativeCreateRecord(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    to_handle(group::SenderKeyRecord::new())
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_GroupCipher_nativeDestroyRecord(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    destroy_handle::<group::SenderKeyRecord>(handle);
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_GroupCipher_nativeCreateDistributionMessage<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    record_handle: jlong,
    distribution_id: JByteArray<'local>,
) -> jbyteArray {
    let record: &mut group::SenderKeyRecord = match from_handle_mut(record_handle) {
        Some(r) => r,
        None => {
            let _ = throw_error(&mut env, "Invalid handle");
            return std::ptr::null_mut();
        }
    };
    let dist_id_bytes = match env.convert_byte_array(&distribution_id) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let dist_id = match std::str::from_utf8(&dist_id_bytes) {
        Ok(s) => s,
        Err(_) => {
            let _ = throw_error(&mut env, "Invalid UTF-8 in distribution ID");
            return std::ptr::null_mut();
        }
    };

    match group::create_sender_key_distribution_message(dist_id, record) {
        Ok(msg) => {
            let bytes = msg.to_bytes();
            match env.byte_array_from_slice(&bytes) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_GroupCipher_nativeEncrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    record_handle: jlong,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    let record: &mut group::SenderKeyRecord = match from_handle_mut(record_handle) {
        Some(r) => r,
        None => {
            let _ = throw_error(&mut env, "Invalid handle");
            return std::ptr::null_mut();
        }
    };
    let pt = match env.convert_byte_array(&plaintext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    match group::group_encrypt(record, &pt) {
        Ok(msg) => {
            let bytes = msg.to_bytes();
            match env.byte_array_from_slice(&bytes) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_GroupCipher_nativeDecrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    record_handle: jlong,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    let record: &mut group::SenderKeyRecord = match from_handle_mut(record_handle) {
        Some(r) => r,
        None => {
            let _ = throw_error(&mut env, "Invalid handle");
            return std::ptr::null_mut();
        }
    };
    let ct = match env.convert_byte_array(&ciphertext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let msg = match group::SenderKeyMessage::from_bytes(&ct) {
        Ok(m) => m,
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            return std::ptr::null_mut();
        }
    };

    match group::group_decrypt(record, &msg) {
        Ok(pt) => {
            match env.byte_array_from_slice(&pt) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

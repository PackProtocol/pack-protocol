use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};

use pack_protocol::api::{PackGroupSession, PackSession};
use pack_protocol::crypto::curve::{PrivateKey, PublicKey};
use pack_protocol::keys::{IdentityKey, IdentityKeyPair, PreKeyBundle};

use crate::convert::{destroy_handle, from_handle_mut, throw_error, to_handle};

// ── PackSession ──

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeInitiate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    our_name: JString<'local>,
    our_device_id: jint,
    identity_public: JByteArray<'local>,
    identity_private: JByteArray<'local>,
    registration_id: jint,
    remote_name: JString<'local>,
    remote_device_id: jint,
    bundle_identity_key: JByteArray<'local>,
    bundle_spk_id: jint,
    bundle_spk: JByteArray<'local>,
    bundle_spk_sig: JByteArray<'local>,
    bundle_spk_timestamp: jlong,
    bundle_opk_id: jint,
    bundle_opk: JByteArray<'local>,
    first_message: JByteArray<'local>,
) -> jlong {
    let our_name_str: String = match env.get_string(&our_name) {
        Ok(s) => s.into(),
        Err(_) => {
            let _ = throw_error(&mut env, "Invalid our_name string");
            return 0;
        }
    };
    let remote_name_str: String = match env.get_string(&remote_name) {
        Ok(s) => s.into(),
        Err(_) => {
            let _ = throw_error(&mut env, "Invalid remote_name string");
            return 0;
        }
    };

    let id_pub = match env.convert_byte_array(&identity_public) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    let id_priv = match env.convert_byte_array(&identity_private) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    if id_pub.len() != 32 || id_priv.len() != 32 {
        let _ = throw_error(&mut env, "Identity key must be 32 bytes");
        return 0;
    }
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&id_pub);
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&id_priv);
    let our_identity = match IdentityKey::from_bytes(pub_bytes) {
        Ok(ik) => IdentityKeyPair::from_keys(ik, PrivateKey::from_bytes(priv_bytes)),
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            return 0;
        }
    };

    let bundle = match build_pre_key_bundle(
        &mut env,
        bundle_identity_key,
        bundle_spk_id,
        bundle_spk,
        bundle_spk_sig,
        bundle_spk_timestamp,
        bundle_opk_id,
        bundle_opk,
    ) {
        Some(b) => b,
        None => return 0,
    };

    let first_msg = match env.convert_byte_array(&first_message) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    match PackSession::initiate(
        &our_name_str,
        our_device_id as u32,
        &our_identity,
        registration_id as u32,
        &remote_name_str,
        remote_device_id as u32,
        &bundle,
        &first_msg,
    ) {
        Ok((session, _msg_bytes)) => to_handle(session),
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeInitiateGetMessage<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    our_name: JString<'local>,
    our_device_id: jint,
    identity_public: JByteArray<'local>,
    identity_private: JByteArray<'local>,
    registration_id: jint,
    remote_name: JString<'local>,
    remote_device_id: jint,
    bundle_identity_key: JByteArray<'local>,
    bundle_spk_id: jint,
    bundle_spk: JByteArray<'local>,
    bundle_spk_sig: JByteArray<'local>,
    bundle_spk_timestamp: jlong,
    bundle_opk_id: jint,
    bundle_opk: JByteArray<'local>,
    first_message: JByteArray<'local>,
) -> jbyteArray {
    let our_name_str: String = match env.get_string(&our_name) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let remote_name_str: String = match env.get_string(&remote_name) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let id_pub = match env.convert_byte_array(&identity_public) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let id_priv = match env.convert_byte_array(&identity_private) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    if id_pub.len() != 32 || id_priv.len() != 32 {
        return std::ptr::null_mut();
    }
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&id_pub);
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&id_priv);
    let our_identity = match IdentityKey::from_bytes(pub_bytes) {
        Ok(ik) => IdentityKeyPair::from_keys(ik, PrivateKey::from_bytes(priv_bytes)),
        Err(_) => return std::ptr::null_mut(),
    };

    let bundle = match build_pre_key_bundle(
        &mut env,
        bundle_identity_key,
        bundle_spk_id,
        bundle_spk,
        bundle_spk_sig,
        bundle_spk_timestamp,
        bundle_opk_id,
        bundle_opk,
    ) {
        Some(b) => b,
        None => return std::ptr::null_mut(),
    };

    let first_msg = match env.convert_byte_array(&first_message) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    match PackSession::initiate(
        &our_name_str,
        our_device_id as u32,
        &our_identity,
        registration_id as u32,
        &remote_name_str,
        remote_device_id as u32,
        &bundle,
        &first_msg,
    ) {
        Ok((_session, msg_bytes)) => match env.byte_array_from_slice(&msg_bytes) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    destroy_handle::<PackSession>(handle);
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeEncrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    let session: &mut PackSession = match from_handle_mut(handle) {
        Some(s) => s,
        None => {
            let _ = throw_error(&mut env, "Invalid session handle");
            return std::ptr::null_mut();
        }
    };
    let pt = match env.convert_byte_array(&plaintext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    match session.encrypt(&pt) {
        Ok(ct) => match env.byte_array_from_slice(&ct) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeDecrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    let session: &mut PackSession = match from_handle_mut(handle) {
        Some(s) => s,
        None => {
            let _ = throw_error(&mut env, "Invalid session handle");
            return std::ptr::null_mut();
        }
    };
    let ct = match env.convert_byte_array(&ciphertext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    match session.decrypt(&ct) {
        Ok(pt) => match env.byte_array_from_slice(&pt) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

// ── PackGroupSession ──

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeCreateSender<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    distribution_id: JString<'local>,
) -> jlong {
    let dist_id: String = match env.get_string(&distribution_id) {
        Ok(s) => s.into(),
        Err(_) => {
            let _ = throw_error(&mut env, "Invalid distribution_id");
            return 0;
        }
    };

    match PackGroupSession::create_sender(&dist_id) {
        Ok((session, _dist_bytes)) => to_handle(session),
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeCreateSenderGetDistribution<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    distribution_id: JString<'local>,
) -> jbyteArray {
    let dist_id: String = match env.get_string(&distribution_id) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    match PackGroupSession::create_sender(&dist_id) {
        Ok((_session, dist_bytes)) => match env.byte_array_from_slice(&dist_bytes) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeCreateReceiver<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    distribution_id: JString<'local>,
    distribution_message: JByteArray<'local>,
) -> jlong {
    let dist_id: String = match env.get_string(&distribution_id) {
        Ok(s) => s.into(),
        Err(_) => {
            let _ = throw_error(&mut env, "Invalid distribution_id");
            return 0;
        }
    };
    let msg = match env.convert_byte_array(&distribution_message) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    match PackGroupSession::create_receiver(&dist_id, &msg) {
        Ok(session) => to_handle(session),
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    destroy_handle::<PackGroupSession>(handle);
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeEncrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    plaintext: JByteArray<'local>,
) -> jbyteArray {
    let session: &mut PackGroupSession = match from_handle_mut(handle) {
        Some(s) => s,
        None => {
            let _ = throw_error(&mut env, "Invalid group session handle");
            return std::ptr::null_mut();
        }
    };
    let pt = match env.convert_byte_array(&plaintext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    match session.encrypt(&pt) {
        Ok(ct) => match env.byte_array_from_slice(&ct) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeDecrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
    ciphertext: JByteArray<'local>,
) -> jbyteArray {
    let session: &mut PackGroupSession = match from_handle_mut(handle) {
        Some(s) => s,
        None => {
            let _ = throw_error(&mut env, "Invalid group session handle");
            return std::ptr::null_mut();
        }
    };
    let ct = match env.convert_byte_array(&ciphertext) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    match session.decrypt(&ct) {
        Ok(pt) => match env.byte_array_from_slice(&pt) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

// ── Helpers ──

unsafe fn build_pre_key_bundle<'local>(
    env: &mut JNIEnv<'local>,
    bundle_identity_key: JByteArray<'local>,
    bundle_spk_id: jint,
    bundle_spk: JByteArray<'local>,
    bundle_spk_sig: JByteArray<'local>,
    bundle_spk_timestamp: jlong,
    bundle_opk_id: jint,
    bundle_opk: JByteArray<'local>,
) -> Option<PreKeyBundle> {
    let ik_bytes = env.convert_byte_array(&bundle_identity_key).ok()?;
    let spk_bytes = env.convert_byte_array(&bundle_spk).ok()?;
    let spk_sig_bytes = env.convert_byte_array(&bundle_spk_sig).ok()?;

    if ik_bytes.len() != 32 || spk_bytes.len() != 32 || spk_sig_bytes.len() != 64 {
        let _ = throw_error(env, "Invalid key/signature lengths in bundle");
        return None;
    }

    let mut ik = [0u8; 32];
    ik.copy_from_slice(&ik_bytes);
    let mut spk = [0u8; 32];
    spk.copy_from_slice(&spk_bytes);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&spk_sig_bytes);

    let identity_key = IdentityKey::from_bytes(ik).ok()?;
    let signed_pre_key = PublicKey::from_bytes_validated(spk).ok()?;

    let (opk_id, opk) = if bundle_opk_id >= 0 {
        let opk_bytes = env.convert_byte_array(&bundle_opk).ok()?;
        if opk_bytes.len() != 32 {
            let _ = throw_error(env, "Invalid OPK length");
            return None;
        }
        let mut opk_arr = [0u8; 32];
        opk_arr.copy_from_slice(&opk_bytes);
        (
            Some(bundle_opk_id as u32),
            Some(PublicKey::from_bytes_validated(opk_arr).ok()?),
        )
    } else {
        (None, None)
    };

    Some(PreKeyBundle {
        identity_key,
        signed_pre_key_id: bundle_spk_id as u32,
        signed_pre_key,
        signed_pre_key_signature: sig,
        signed_pre_key_timestamp: bundle_spk_timestamp as u64,
        one_time_pre_key_id: opk_id,
        one_time_pre_key: opk,
    })
}

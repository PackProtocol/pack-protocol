use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong};

use pack_protocol::api::{PackGroupSession, PackSealedSender, PackSession, SenderKeyDistribution};
use pack_protocol::crypto::curve::{PrivateKey, PublicKey};
use pack_protocol::keys::{IdentityKey, IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey};
use pack_protocol::sealed_sender::{SenderCertificate, ServerCertificate};

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
        Ok((_session, skdm)) => match env.byte_array_from_slice(skdm.as_bytes()) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

// nativeCreateReceiver removed: receiver creation now goes through
// PackSealedSender::receive_sender_key which unseals and processes the SKDM.

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    destroy_handle::<PackGroupSession>(handle);
}

// PackGroupSession.nativeEncrypt and nativeDecrypt removed:
// Group messages must go through sealed sender. Use the high-level
// PackSealedSender::encrypt_group_message / unseal_group_message API.

// ── PackSession serialization ──

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeToBytes<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let session: &PackSession = match crate::convert::from_handle(handle) {
        Some(s) => s,
        None => {
            let _ = throw_error(&mut env, "Invalid session handle");
            return std::ptr::null_mut();
        }
    };
    let bytes = session.to_bytes();
    match env.byte_array_from_slice(&bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeFromBytes<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    data: JByteArray<'local>,
) -> jlong {
    let bytes = match env.convert_byte_array(&data) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    match PackSession::from_bytes(&bytes) {
        Ok(session) => to_handle(session),
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            0
        }
    }
}

// ── PackSession respond ──

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeRespond<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    our_name: JString<'local>,
    our_device_id: jint,
    identity_public: JByteArray<'local>,
    identity_private: JByteArray<'local>,
    registration_id: jint,
    remote_name: JString<'local>,
    remote_device_id: jint,
    spk_id: jint,
    spk_public: JByteArray<'local>,
    spk_private: JByteArray<'local>,
    spk_signature: JByteArray<'local>,
    spk_timestamp: jlong,
    opk_id: jint,
    opk_public: JByteArray<'local>,
    opk_private: JByteArray<'local>,
    pre_key_message_bytes: JByteArray<'local>,
) -> jlong {
    let our_name_str: String = match env.get_string(&our_name) {
        Ok(s) => s.into(),
        Err(_) => { let _ = throw_error(&mut env, "Invalid our_name"); return 0; }
    };
    let remote_name_str: String = match env.get_string(&remote_name) {
        Ok(s) => s.into(),
        Err(_) => { let _ = throw_error(&mut env, "Invalid remote_name"); return 0; }
    };

    let our_identity = match build_identity_pair(&mut env, identity_public, identity_private) {
        Some(id) => id,
        None => return 0,
    };

    let spk = match build_signed_pre_key(&mut env, spk_id as u32, spk_public, spk_private, spk_signature, spk_timestamp as u64) {
        Some(s) => s,
        None => return 0,
    };

    let opk = if opk_id >= 0 {
        match build_one_time_pre_key(&mut env, opk_id as u32, opk_public, opk_private) {
            Some(o) => Some(o),
            None => return 0,
        }
    } else {
        None
    };

    let msg = match env.convert_byte_array(&pre_key_message_bytes) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    match PackSession::respond(
        &our_name_str,
        our_device_id as u32,
        &our_identity,
        registration_id as u32,
        &remote_name_str,
        remote_device_id as u32,
        &spk,
        opk.as_ref(),
        &msg,
    ) {
        Ok((session, _plaintext)) => to_handle(session),
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSession_nativeRespondGetPlaintext<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    our_name: JString<'local>,
    our_device_id: jint,
    identity_public: JByteArray<'local>,
    identity_private: JByteArray<'local>,
    registration_id: jint,
    remote_name: JString<'local>,
    remote_device_id: jint,
    spk_id: jint,
    spk_public: JByteArray<'local>,
    spk_private: JByteArray<'local>,
    spk_signature: JByteArray<'local>,
    spk_timestamp: jlong,
    opk_id: jint,
    opk_public: JByteArray<'local>,
    opk_private: JByteArray<'local>,
    pre_key_message_bytes: JByteArray<'local>,
) -> jbyteArray {
    let our_name_str: String = match env.get_string(&our_name) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let remote_name_str: String = match env.get_string(&remote_name) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let our_identity = match build_identity_pair(&mut env, identity_public, identity_private) {
        Some(id) => id,
        None => return std::ptr::null_mut(),
    };

    let spk = match build_signed_pre_key(&mut env, spk_id as u32, spk_public, spk_private, spk_signature, spk_timestamp as u64) {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };

    let opk = if opk_id >= 0 {
        build_one_time_pre_key(&mut env, opk_id as u32, opk_public, opk_private)
    } else {
        None
    };

    let msg = match env.convert_byte_array(&pre_key_message_bytes) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    match PackSession::respond(
        &our_name_str,
        our_device_id as u32,
        &our_identity,
        registration_id as u32,
        &remote_name_str,
        remote_device_id as u32,
        &spk,
        opk.as_ref(),
        &msg,
    ) {
        Ok((_session, plaintext)) => match env.byte_array_from_slice(&plaintext) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

// ── PackGroupSession serialization ──

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeToBytes<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let session: &PackGroupSession = match crate::convert::from_handle(handle) {
        Some(s) => s,
        None => {
            let _ = throw_error(&mut env, "Invalid group session handle");
            return std::ptr::null_mut();
        }
    };
    let bytes = session.to_bytes();
    match env.byte_array_from_slice(&bytes) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackGroupSession_nativeFromBytes<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    data: JByteArray<'local>,
) -> jlong {
    let bytes = match env.convert_byte_array(&data) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    match PackGroupSession::from_bytes(&bytes) {
        Ok(session) => to_handle(session),
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            0
        }
    }
}

// ── Key generation ──

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeGenerateSignedPreKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    id: jint,
    identity_public: JByteArray<'local>,
    identity_private: JByteArray<'local>,
    timestamp: jlong,
) -> jlong {
    let identity = match build_identity_pair(&mut env, identity_public, identity_private) {
        Some(id) => id,
        None => return 0,
    };
    let spk = SignedPreKey::generate(id as u32, &identity, timestamp as u64);
    to_handle(spk)
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeSignedPreKeyPublic<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let spk: &SignedPreKey = match crate::convert::from_handle(handle) {
        Some(s) => s,
        None => { let _ = throw_error(&mut env, "Invalid handle"); return std::ptr::null_mut(); }
    };
    match env.byte_array_from_slice(spk.key_pair.public.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeSignedPreKeyPrivate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let spk: &SignedPreKey = match crate::convert::from_handle(handle) {
        Some(s) => s,
        None => { let _ = throw_error(&mut env, "Invalid handle"); return std::ptr::null_mut(); }
    };
    match env.byte_array_from_slice(spk.key_pair.private.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeSignedPreKeySignature<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let spk: &SignedPreKey = match crate::convert::from_handle(handle) {
        Some(s) => s,
        None => { let _ = throw_error(&mut env, "Invalid handle"); return std::ptr::null_mut(); }
    };
    match env.byte_array_from_slice(&spk.signature) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeDestroySignedPreKey(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    destroy_handle::<SignedPreKey>(handle);
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeGenerateOneTimePreKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    id: jint,
) -> jlong {
    let opk = OneTimePreKey::generate(id as u32);
    to_handle(opk)
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeOneTimePreKeyPublic<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let opk: &OneTimePreKey = match crate::convert::from_handle(handle) {
        Some(o) => o,
        None => { let _ = throw_error(&mut env, "Invalid handle"); return std::ptr::null_mut(); }
    };
    match env.byte_array_from_slice(opk.key_pair.public.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeOneTimePreKeyPrivate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    let opk: &OneTimePreKey = match crate::convert::from_handle(handle) {
        Some(o) => o,
        None => { let _ = throw_error(&mut env, "Invalid handle"); return std::ptr::null_mut(); }
    };
    match env.byte_array_from_slice(opk.key_pair.private.as_bytes()) {
        Ok(arr) => arr.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackKeyGenerator_nativeDestroyOneTimePreKey(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    destroy_handle::<OneTimePreKey>(handle);
}

// ── Sealed sender ──

#[no_mangle]
pub unsafe extern "system" fn Java_org_pack_protocol_PackSealedSender_nativeDistributeSenderKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    session_handle: jlong,
    sender_uuid: JString<'local>,
    sender_device_id: jint,
    server_cert_key: JByteArray<'local>,
    server_cert_id: jint,
    cert_expiration: jlong,
    cert_signature: JByteArray<'local>,
    skdm_bytes: JByteArray<'local>,
    current_time: jlong,
) -> jbyteArray {
    let session: &mut PackSession = match from_handle_mut(session_handle) {
        Some(s) => s,
        None => { let _ = throw_error(&mut env, "Invalid session handle"); return std::ptr::null_mut(); }
    };

    let uuid_str: String = match env.get_string(&sender_uuid) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let sc_key = match env.convert_byte_array(&server_cert_key) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let sig = match env.convert_byte_array(&cert_signature) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let skdm = match env.convert_byte_array(&skdm_bytes) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    if sc_key.len() != 32 {
        let _ = throw_error(&mut env, "Server cert key must be 32 bytes");
        return std::ptr::null_mut();
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&sc_key);

    let cert = SenderCertificate {
        sender_uuid: uuid_str,
        sender_device_id: sender_device_id as u32,
        sender_identity: session.our_identity().clone(),
        expiration: cert_expiration as u64,
        server_certificate: ServerCertificate { key: PublicKey::from_bytes(key_arr), id: server_cert_id as u32 },
        signature: sig,
    };

    let skdm = SenderKeyDistribution::from_bytes(skdm);

    match PackSealedSender::distribute_sender_key(session, &cert, &skdm, current_time as u64) {
        Ok(sealed) => match env.byte_array_from_slice(&sealed) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(e) => {
            let _ = throw_error(&mut env, &e.to_string());
            std::ptr::null_mut()
        }
    }
}

// receive_sender_key requires returning both a SealedSenderResult and a
// PackGroupSession — this must be orchestrated at the high-level API in
// Kotlin/Java rather than through a single JNI call.

// ── Helpers ──

unsafe fn build_identity_pair<'local>(
    env: &mut JNIEnv<'local>,
    public_bytes: JByteArray<'local>,
    private_bytes: JByteArray<'local>,
) -> Option<IdentityKeyPair> {
    let pub_bytes = env.convert_byte_array(&public_bytes).ok()?;
    let priv_bytes = env.convert_byte_array(&private_bytes).ok()?;
    if pub_bytes.len() != 32 || priv_bytes.len() != 32 {
        let _ = throw_error(env, "Identity key must be 32 bytes");
        return None;
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);
    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&priv_bytes);
    let ik = IdentityKey::from_bytes(pub_arr).ok()?;
    Some(IdentityKeyPair::from_keys(ik, PrivateKey::from_bytes(priv_arr)))
}

unsafe fn build_signed_pre_key<'local>(
    env: &mut JNIEnv<'local>,
    id: u32,
    public_bytes: JByteArray<'local>,
    private_bytes: JByteArray<'local>,
    signature: JByteArray<'local>,
    timestamp: u64,
) -> Option<SignedPreKey> {
    let pub_bytes = env.convert_byte_array(&public_bytes).ok()?;
    let priv_bytes = env.convert_byte_array(&private_bytes).ok()?;
    let sig_bytes = env.convert_byte_array(&signature).ok()?;
    if pub_bytes.len() != 32 || priv_bytes.len() != 32 || sig_bytes.len() != 64 {
        let _ = throw_error(env, "Invalid SPK key/signature lengths");
        return None;
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);
    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&priv_bytes);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    Some(SignedPreKey {
        id,
        key_pair: pack_protocol::crypto::curve::KeyPair {
            public: PublicKey::from_bytes(pub_arr),
            private: PrivateKey::from_bytes(priv_arr),
        },
        signature: sig_arr,
        timestamp,
    })
}

unsafe fn build_one_time_pre_key<'local>(
    env: &mut JNIEnv<'local>,
    id: u32,
    public_bytes: JByteArray<'local>,
    private_bytes: JByteArray<'local>,
) -> Option<OneTimePreKey> {
    let pub_bytes = env.convert_byte_array(&public_bytes).ok()?;
    let priv_bytes = env.convert_byte_array(&private_bytes).ok()?;
    if pub_bytes.len() != 32 || priv_bytes.len() != 32 {
        let _ = throw_error(env, "Invalid OPK key lengths");
        return None;
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);
    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(&priv_bytes);
    Some(OneTimePreKey {
        id,
        key_pair: pack_protocol::crypto::curve::KeyPair {
            public: PublicKey::from_bytes(pub_arr),
            private: PrivateKey::from_bytes(priv_arr),
        },
    })
}

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

use pack_protocol::api;
use pack_protocol::crypto::curve::{KeyPair, PublicKey, PrivateKey};
use pack_protocol::keys::{
    IdentityKey, IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey,
};
use pack_protocol::sealed_sender::{SenderCertificate, ServerCertificate};

#[swift_bridge::bridge]
mod ffi {
    enum PackBridgeError {
        InvalidKey(String),
        UntrustedIdentity(String),
        DuplicateMessage,
        InvalidMessage(String),
        InvalidMac,
        NoSession(String),
        SessionNotFound,
        InvalidSignature,
        StaleKeyExchange,
        TooManySkippedMessages,
        ExpiredCertificate,
        InvalidCertificate,
        Storage(String),
        Crypto(String),
    }

    #[swift_bridge(swift_repr = "struct")]
    struct SealedSenderDecryptResult {
        sender_uuid: String,
        sender_device_id: u32,
        plaintext: Vec<u8>,
    }

    extern "Rust" {
        type PackSessionBridge;

        #[swift_bridge(associated_to = PackSessionBridge)]
        fn initiate(
            our_name: &str,
            our_device_id: u32,
            identity_public: &[u8],
            identity_private: &[u8],
            registration_id: u32,
            remote_name: &str,
            remote_device_id: u32,
            bundle_identity_key: &[u8],
            bundle_spk_id: u32,
            bundle_spk: &[u8],
            bundle_spk_signature: &[u8],
            bundle_spk_timestamp: u64,
            bundle_opk_id: Option<u32>,
            bundle_opk: Option<Vec<u8>>,
            first_message: &[u8],
        ) -> Result<PackSessionBridge, PackBridgeError>;

        #[swift_bridge(associated_to = PackSessionBridge)]
        fn respond(
            our_name: &str,
            our_device_id: u32,
            identity_public: &[u8],
            identity_private: &[u8],
            registration_id: u32,
            remote_name: &str,
            remote_device_id: u32,
            spk_id: u32,
            spk_public: &[u8],
            spk_private: &[u8],
            spk_signature: &[u8],
            spk_timestamp: u64,
            opk_id: Option<u32>,
            opk_public: Option<Vec<u8>>,
            opk_private: Option<Vec<u8>>,
            pre_key_message_bytes: &[u8],
        ) -> Result<PackSessionBridge, PackBridgeError>;

        fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PackBridgeError>;
        fn decrypt(&mut self, message_bytes: &[u8]) -> Result<Vec<u8>, PackBridgeError>;
        fn pre_key_message(&self) -> Option<Vec<u8>>;
        fn first_plaintext(&self) -> Option<Vec<u8>>;
    }

    extern "Rust" {
        type PackGroupSessionBridge;

        #[swift_bridge(associated_to = PackGroupSessionBridge)]
        fn create_sender(
            distribution_id: &str,
        ) -> Result<PackGroupSessionBridge, PackBridgeError>;

        #[swift_bridge(associated_to = PackGroupSessionBridge)]
        fn create_receiver(
            distribution_id: &str,
            distribution_message: &[u8],
        ) -> Result<PackGroupSessionBridge, PackBridgeError>;

        fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PackBridgeError>;
        fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, PackBridgeError>;
        fn distribution_message(&self) -> Option<Vec<u8>>;
    }

    extern "Rust" {
        type PackSealedSenderBridge;

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn sealed_encrypt(
            sender_identity_public: &[u8],
            sender_identity_private: &[u8],
            sender_uuid: &str,
            sender_device_id: u32,
            server_cert_key: &[u8],
            server_cert_id: u32,
            cert_expiration: u64,
            cert_signature: &[u8],
            recipient_identity: &[u8],
            inner_message: &[u8],
            current_time: u64,
        ) -> Result<Vec<u8>, PackBridgeError>;

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn sealed_decrypt(
            our_identity_public: &[u8],
            our_identity_private: &[u8],
            ciphertext: &[u8],
            trust_root: &[u8],
            current_time: u64,
        ) -> Result<SealedSenderDecryptResult, PackBridgeError>;
    }
}

// ── Error conversion ──

impl From<pack_protocol::errors::PackError> for ffi::PackBridgeError {
    fn from(e: pack_protocol::errors::PackError) -> Self {
        use pack_protocol::errors::PackError::*;
        match e {
            InvalidKey(s) => ffi::PackBridgeError::InvalidKey(s),
            UntrustedIdentity(s) => ffi::PackBridgeError::UntrustedIdentity(s),
            DuplicateMessage => ffi::PackBridgeError::DuplicateMessage,
            InvalidMessage(s) => ffi::PackBridgeError::InvalidMessage(s),
            InvalidMac => ffi::PackBridgeError::InvalidMac,
            NoSession(s) => ffi::PackBridgeError::NoSession(s),
            SessionNotFound => ffi::PackBridgeError::SessionNotFound,
            InvalidSignature => ffi::PackBridgeError::InvalidSignature,
            StaleKeyExchange => ffi::PackBridgeError::StaleKeyExchange,
            TooManySkippedMessages => ffi::PackBridgeError::TooManySkippedMessages,
            ExpiredCertificate => ffi::PackBridgeError::ExpiredCertificate,
            InvalidCertificate => ffi::PackBridgeError::InvalidCertificate,
            Storage(s) => ffi::PackBridgeError::Storage(s),
            Crypto(s) => ffi::PackBridgeError::Crypto(s),
        }
    }
}

fn map_err<T>(r: pack_protocol::errors::Result<T>) -> Result<T, ffi::PackBridgeError> {
    r.map_err(Into::into)
}

// ── PackSession bridge ──

pub struct PackSessionBridge {
    inner: api::PackSession,
    pre_key_message: Option<Vec<u8>>,
    first_plaintext: Option<Vec<u8>>,
}

impl PackSessionBridge {
    fn initiate(
        our_name: &str,
        our_device_id: u32,
        identity_public: &[u8],
        identity_private: &[u8],
        registration_id: u32,
        remote_name: &str,
        remote_device_id: u32,
        bundle_identity_key: &[u8],
        bundle_spk_id: u32,
        bundle_spk: &[u8],
        bundle_spk_signature: &[u8],
        bundle_spk_timestamp: u64,
        bundle_opk_id: Option<u32>,
        bundle_opk: Option<Vec<u8>>,
        first_message: &[u8],
    ) -> Result<Self, ffi::PackBridgeError> {
        let our_identity = build_identity_pair(identity_public, identity_private)?;
        let bundle = build_pre_key_bundle(
            bundle_identity_key,
            bundle_spk_id,
            bundle_spk,
            bundle_spk_signature,
            bundle_spk_timestamp,
            bundle_opk_id,
            bundle_opk.as_deref(),
        )?;

        let (session, pre_key_msg) = map_err(api::PackSession::initiate(
            our_name,
            our_device_id,
            &our_identity,
            registration_id,
            remote_name,
            remote_device_id,
            &bundle,
            first_message,
        ))?;

        Ok(Self {
            inner: session,
            pre_key_message: Some(pre_key_msg),
            first_plaintext: None,
        })
    }

    fn respond(
        our_name: &str,
        our_device_id: u32,
        identity_public: &[u8],
        identity_private: &[u8],
        registration_id: u32,
        remote_name: &str,
        remote_device_id: u32,
        spk_id: u32,
        spk_public: &[u8],
        spk_private: &[u8],
        spk_signature: &[u8],
        spk_timestamp: u64,
        opk_id: Option<u32>,
        opk_public: Option<Vec<u8>>,
        opk_private: Option<Vec<u8>>,
        pre_key_message_bytes: &[u8],
    ) -> Result<Self, ffi::PackBridgeError> {
        let our_identity = build_identity_pair(identity_public, identity_private)?;
        let spk = build_signed_pre_key(spk_id, spk_public, spk_private, spk_signature, spk_timestamp)?;
        let opk = match (opk_id, opk_public, opk_private) {
            (Some(id), Some(pub_bytes), Some(priv_bytes)) => {
                Some(build_one_time_pre_key(id, &pub_bytes, &priv_bytes)?)
            }
            _ => None,
        };

        let (session, plaintext) = map_err(api::PackSession::respond(
            our_name,
            our_device_id,
            &our_identity,
            registration_id,
            remote_name,
            remote_device_id,
            &spk,
            opk.as_ref(),
            pre_key_message_bytes,
        ))?;

        Ok(Self {
            inner: session,
            pre_key_message: None,
            first_plaintext: Some(plaintext),
        })
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ffi::PackBridgeError> {
        map_err(self.inner.encrypt(plaintext))
    }

    fn decrypt(&mut self, message_bytes: &[u8]) -> Result<Vec<u8>, ffi::PackBridgeError> {
        map_err(self.inner.decrypt(message_bytes))
    }

    fn pre_key_message(&self) -> Option<Vec<u8>> {
        self.pre_key_message.clone()
    }

    fn first_plaintext(&self) -> Option<Vec<u8>> {
        self.first_plaintext.clone()
    }
}

// ── PackGroupSession bridge ──

pub struct PackGroupSessionBridge {
    inner: api::PackGroupSession,
    distribution_message: Option<Vec<u8>>,
}

impl PackGroupSessionBridge {
    fn create_sender(
        distribution_id: &str,
    ) -> Result<Self, ffi::PackBridgeError> {
        let (session, dist_msg) = map_err(api::PackGroupSession::create_sender(distribution_id))?;
        Ok(Self {
            inner: session,
            distribution_message: Some(dist_msg),
        })
    }

    fn create_receiver(
        distribution_id: &str,
        distribution_message: &[u8],
    ) -> Result<Self, ffi::PackBridgeError> {
        let session =
            map_err(api::PackGroupSession::create_receiver(distribution_id, distribution_message))?;
        Ok(Self {
            inner: session,
            distribution_message: None,
        })
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ffi::PackBridgeError> {
        map_err(self.inner.encrypt(plaintext))
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, ffi::PackBridgeError> {
        map_err(self.inner.decrypt(ciphertext))
    }

    fn distribution_message(&self) -> Option<Vec<u8>> {
        self.distribution_message.clone()
    }
}

// ── PackSealedSender bridge ──

pub struct PackSealedSenderBridge;

impl PackSealedSenderBridge {
    fn sealed_encrypt(
        sender_identity_public: &[u8],
        sender_identity_private: &[u8],
        sender_uuid: &str,
        sender_device_id: u32,
        server_cert_key: &[u8],
        server_cert_id: u32,
        cert_expiration: u64,
        cert_signature: &[u8],
        recipient_identity: &[u8],
        inner_message: &[u8],
        current_time: u64,
    ) -> Result<Vec<u8>, ffi::PackBridgeError> {
        let sender_identity = build_identity_pair(sender_identity_public, sender_identity_private)?;

        let server_pub = PublicKey::from_bytes(
            server_cert_key
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("server cert key must be 32 bytes".into()))?,
        );
        let server_cert = ServerCertificate {
            key: server_pub,
            id: server_cert_id,
        };

        let cert = SenderCertificate {
            sender_uuid: sender_uuid.to_string(),
            sender_device_id,
            sender_identity: sender_identity.public.clone(),
            expiration: cert_expiration,
            server_certificate: server_cert,
            signature: cert_signature.to_vec(),
        };

        let recipient = IdentityKey::from_bytes(
            recipient_identity
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("recipient key must be 32 bytes".into()))?,
        )
        .map_err(|e| ffi::PackBridgeError::InvalidKey(e.to_string()))?;

        map_err(api::PackSealedSender::encrypt(
            &sender_identity,
            &cert,
            &recipient,
            inner_message,
            current_time,
        ))
    }

    fn sealed_decrypt(
        our_identity_public: &[u8],
        our_identity_private: &[u8],
        ciphertext: &[u8],
        trust_root: &[u8],
        current_time: u64,
    ) -> Result<ffi::SealedSenderDecryptResult, ffi::PackBridgeError> {
        let our_identity = build_identity_pair(our_identity_public, our_identity_private)?;

        let trust_root_key = PublicKey::from_bytes(
            trust_root
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("trust root must be 32 bytes".into()))?,
        );

        let result = map_err(api::PackSealedSender::decrypt(
            &our_identity,
            ciphertext,
            &trust_root_key,
            current_time,
        ))?;

        Ok(ffi::SealedSenderDecryptResult {
            sender_uuid: result.sender_uuid,
            sender_device_id: result.sender_device_id,
            plaintext: result.plaintext,
        })
    }
}

// ── Key construction helpers ──

fn build_identity_pair(
    public_bytes: &[u8],
    private_bytes: &[u8],
) -> Result<IdentityKeyPair, ffi::PackBridgeError> {
    let pub_arr: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| ffi::PackBridgeError::InvalidKey("identity public key must be 32 bytes".into()))?;
    let priv_arr: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| ffi::PackBridgeError::InvalidKey("identity private key must be 32 bytes".into()))?;

    let public = IdentityKey::from_bytes(pub_arr)
        .map_err(|e| ffi::PackBridgeError::InvalidKey(e.to_string()))?;
    let private = PrivateKey::from_bytes(priv_arr);

    Ok(IdentityKeyPair::from_keys(public, private))
}

fn build_pre_key_bundle(
    identity_key: &[u8],
    spk_id: u32,
    spk: &[u8],
    spk_signature: &[u8],
    spk_timestamp: u64,
    opk_id: Option<u32>,
    opk: Option<&[u8]>,
) -> Result<PreKeyBundle, ffi::PackBridgeError> {
    let ik_arr: [u8; 32] = identity_key
        .try_into()
        .map_err(|_| ffi::PackBridgeError::InvalidKey("bundle identity key must be 32 bytes".into()))?;
    let spk_arr: [u8; 32] = spk
        .try_into()
        .map_err(|_| ffi::PackBridgeError::InvalidKey("signed pre key must be 32 bytes".into()))?;

    let identity = IdentityKey::from_bytes(ik_arr)
        .map_err(|e| ffi::PackBridgeError::InvalidKey(e.to_string()))?;
    let signed_pre_key = PublicKey::from_bytes(spk_arr);

    let (one_time_pre_key_id, one_time_pre_key) = match (opk_id, opk) {
        (Some(id), Some(bytes)) => {
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("one-time pre key must be 32 bytes".into()))?;
            (Some(id), Some(PublicKey::from_bytes(arr)))
        }
        _ => (None, None),
    };

    Ok(PreKeyBundle {
        identity_key: identity,
        signed_pre_key_id: spk_id,
        signed_pre_key,
        signed_pre_key_signature: spk_signature
            .try_into()
            .map_err(|_| ffi::PackBridgeError::InvalidKey("signature must be 64 bytes".into()))?,
        signed_pre_key_timestamp: spk_timestamp,
        one_time_pre_key_id,
        one_time_pre_key,
    })
}

fn build_signed_pre_key(
    id: u32,
    public_bytes: &[u8],
    private_bytes: &[u8],
    signature: &[u8],
    timestamp: u64,
) -> Result<SignedPreKey, ffi::PackBridgeError> {
    let pub_arr: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| ffi::PackBridgeError::InvalidKey("signed pre key public must be 32 bytes".into()))?;
    let priv_arr: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| ffi::PackBridgeError::InvalidKey("signed pre key private must be 32 bytes".into()))?;

    Ok(SignedPreKey {
        id,
        key_pair: KeyPair {
            public: PublicKey::from_bytes(pub_arr),
            private: PrivateKey::from_bytes(priv_arr),
        },
        signature: signature
            .try_into()
            .map_err(|_| ffi::PackBridgeError::InvalidKey("signature must be 64 bytes".into()))?,
        timestamp,
    })
}

fn build_one_time_pre_key(
    id: u32,
    public_bytes: &[u8],
    private_bytes: &[u8],
) -> Result<OneTimePreKey, ffi::PackBridgeError> {
    let pub_arr: [u8; 32] = public_bytes
        .try_into()
        .map_err(|_| ffi::PackBridgeError::InvalidKey("one-time pre key public must be 32 bytes".into()))?;
    let priv_arr: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| ffi::PackBridgeError::InvalidKey("one-time pre key private must be 32 bytes".into()))?;

    Ok(OneTimePreKey {
        id,
        key_pair: KeyPair {
            public: PublicKey::from_bytes(pub_arr),
            private: PrivateKey::from_bytes(priv_arr),
        },
    })
}

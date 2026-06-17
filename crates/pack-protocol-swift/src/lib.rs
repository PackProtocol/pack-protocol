use pack_protocol::api;
use pack_protocol::crypto::curve::{KeyPair, PublicKey, PrivateKey};
use pack_protocol::fingerprint::ScannableFingerprint;
use pack_protocol::keys::{
    IdentityKey, IdentityKeyPair, OneTimePreKey, PQPreKey, PreKeyBundle, SignedPreKey,
};
use pack_protocol::store::ProtocolAddress;
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
        fn remote_identity_key(&self) -> Vec<u8>;
        fn to_bytes(&self) -> Vec<u8>;

        #[swift_bridge(associated_to = PackSessionBridge)]
        fn from_bytes(data: &[u8]) -> Result<PackSessionBridge, PackBridgeError>;

        fn to_bytes_encrypted(&self, storage_key: &[u8]) -> Result<Vec<u8>, PackBridgeError>;

        #[swift_bridge(associated_to = PackSessionBridge)]
        fn from_bytes_encrypted(data: &[u8], storage_key: &[u8]) -> Result<PackSessionBridge, PackBridgeError>;
    }

    extern "Rust" {
        type PackGroupSessionBridge;

        #[swift_bridge(associated_to = PackGroupSessionBridge)]
        fn create_sender(
            distribution_id: &str,
        ) -> Result<PackGroupSessionBridge, PackBridgeError>;

        fn distribution_message(&self) -> Option<Vec<u8>>;
        fn to_bytes(&self) -> Vec<u8>;

        #[swift_bridge(associated_to = PackGroupSessionBridge)]
        fn from_bytes(data: &[u8]) -> Result<PackGroupSessionBridge, PackBridgeError>;

        #[swift_bridge(associated_to = PackGroupSessionBridge)]
        fn from_distribution(
            distribution_id: &str,
            skdm_bytes: &[u8],
        ) -> Result<PackGroupSessionBridge, PackBridgeError>;
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

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn sealed_encrypt_raw_cert(
            sender_identity_public: &[u8],
            sender_identity_private: &[u8],
            raw_cert_blob: &[u8],
            recipient_identity: &[u8],
            inner_message: &[u8],
            current_time: u64,
        ) -> Result<Vec<u8>, PackBridgeError>;

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn sealed_decrypt_raw_cert(
            our_identity_public: &[u8],
            our_identity_private: &[u8],
            ciphertext: &[u8],
            trust_root: &[u8],
            current_time: u64,
        ) -> Result<SealedSenderDecryptResult, PackBridgeError>;

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn distribute_sender_key(
            session: &mut PackSessionBridge,
            sender_uuid: &str,
            sender_device_id: u32,
            server_cert_key: &[u8],
            server_cert_id: u32,
            cert_expiration: u64,
            cert_signature: &[u8],
            skdm_bytes: &[u8],
            current_time: u64,
        ) -> Result<Vec<u8>, PackBridgeError>;

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn receive_sender_key(
            session: &mut PackSessionBridge,
            ciphertext: &[u8],
            trust_root: &[u8],
            current_time: u64,
            distribution_id: &str,
        ) -> Result<PackGroupSessionBridge, PackBridgeError>;

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn encrypt_message(
            group_session: &mut PackGroupSessionBridge,
            sender_identity_public: &[u8],
            sender_identity_private: &[u8],
            sender_uuid: &str,
            sender_device_id: u32,
            server_cert_key: &[u8],
            server_cert_id: u32,
            cert_expiration: u64,
            cert_signature: &[u8],
            recipient_address_name: &str,
            recipient_address_device_id: u32,
            recipient_identity_key: &[u8],
            plaintext: &[u8],
            current_time: u64,
        ) -> Result<Vec<u8>, PackBridgeError>;

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn decrypt_message(
            our_identity_public: &[u8],
            our_identity_private: &[u8],
            ciphertext: &[u8],
            trust_root: &[u8],
            current_time: u64,
        ) -> Result<SealedSenderDecryptResult, PackBridgeError>;

        #[swift_bridge(associated_to = PackSealedSenderBridge)]
        fn decrypt_envelope(
            group_session: &mut PackGroupSessionBridge,
            inner_ciphertext: &[u8],
        ) -> Result<Vec<u8>, PackBridgeError>;
    }

    #[swift_bridge(swift_repr = "struct")]
    struct FingerprintResult {
        display_text: String,
        scannable_bytes: Vec<u8>,
    }

    extern "Rust" {
        type PackFingerprintBridge;

        #[swift_bridge(associated_to = PackFingerprintBridge)]
        fn generate(
            local_identifier: &str,
            local_identity_key: &[u8],
            remote_identifier: &str,
            remote_identity_key: &[u8],
        ) -> Result<FingerprintResult, PackBridgeError>;

        #[swift_bridge(associated_to = PackFingerprintBridge)]
        fn generate_for_session(
            session: &PackSessionBridge,
            local_identifier: &str,
            remote_identifier: &str,
        ) -> FingerprintResult;

        #[swift_bridge(associated_to = PackFingerprintBridge)]
        fn verify_scanned(
            local_scannable: &[u8],
            scanned: &[u8],
        ) -> Result<bool, PackBridgeError>;
    }

    #[swift_bridge(swift_repr = "struct")]
    struct KeyPairResult {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    #[swift_bridge(swift_repr = "struct")]
    struct SignedPreKeyResult {
        id: u32,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        signature: Vec<u8>,
        timestamp: u64,
    }

    #[swift_bridge(swift_repr = "struct")]
    struct PQPreKeyResult {
        id: u32,
        encapsulation_key: Vec<u8>,
        decapsulation_key: Vec<u8>,
        signature: Vec<u8>,
        timestamp: u64,
    }

    extern "Rust" {
        type PackKeyGeneratorBridge;

        #[swift_bridge(associated_to = PackKeyGeneratorBridge)]
        fn generate_identity_key_pair() -> KeyPairResult;

        #[swift_bridge(associated_to = PackKeyGeneratorBridge)]
        fn generate_signed_pre_key(
            id: u32,
            identity_public: &[u8],
            identity_private: &[u8],
            timestamp: u64,
        ) -> Result<SignedPreKeyResult, PackBridgeError>;

        #[swift_bridge(associated_to = PackKeyGeneratorBridge)]
        fn generate_one_time_pre_key(id: u32) -> KeyPairResult;

        #[swift_bridge(associated_to = PackKeyGeneratorBridge)]
        fn generate_pq_pre_key(
            id: u32,
            identity_public: &[u8],
            identity_private: &[u8],
            timestamp: u64,
        ) -> Result<PQPreKeyResult, PackBridgeError>;

        #[swift_bridge(associated_to = PackKeyGeneratorBridge)]
        fn xeddsa_sign(
            private_key: &[u8],
            message: &[u8],
        ) -> Result<Vec<u8>, PackBridgeError>;
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

    fn remote_identity_key(&self) -> Vec<u8> {
        self.inner.remote_identity().as_bytes().to_vec()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, ffi::PackBridgeError> {
        let session = map_err(api::PackSession::from_bytes(data))?;
        Ok(Self {
            inner: session,
            pre_key_message: None,
            first_plaintext: None,
        })
    }

    fn to_bytes_encrypted(&self, storage_key: &[u8]) -> Result<Vec<u8>, ffi::PackBridgeError> {
        let key: [u8; 32] = storage_key
            .try_into()
            .map_err(|_| ffi::PackBridgeError::InvalidKey("storage key must be 32 bytes".into()))?;
        map_err(self.inner.to_bytes_encrypted(&key))
    }

    fn from_bytes_encrypted(data: &[u8], storage_key: &[u8]) -> Result<Self, ffi::PackBridgeError> {
        let key: [u8; 32] = storage_key
            .try_into()
            .map_err(|_| ffi::PackBridgeError::InvalidKey("storage key must be 32 bytes".into()))?;
        let session = map_err(api::PackSession::from_bytes_encrypted(data, &key))?;
        Ok(Self {
            inner: session,
            pre_key_message: None,
            first_plaintext: None,
        })
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
        let (session, skdm) = map_err(api::PackGroupSession::create_sender(distribution_id))?;
        Ok(Self {
            inner: session,
            distribution_message: Some(skdm.as_bytes().to_vec()),
        })
    }

    fn distribution_message(&self) -> Option<Vec<u8>> {
        self.distribution_message.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, ffi::PackBridgeError> {
        let session = map_err(api::PackGroupSession::from_bytes(data))?;
        Ok(Self {
            inner: session,
            distribution_message: None,
        })
    }

    fn from_distribution(
        distribution_id: &str,
        skdm_bytes: &[u8],
    ) -> Result<Self, ffi::PackBridgeError> {
        let session = map_err(api::PackGroupSession::from_distribution(distribution_id, skdm_bytes))?;
        Ok(Self {
            inner: session,
            distribution_message: None,
        })
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

    fn sealed_encrypt_raw_cert(
        sender_identity_public: &[u8],
        sender_identity_private: &[u8],
        raw_cert_blob: &[u8],
        recipient_identity: &[u8],
        inner_message: &[u8],
        current_time: u64,
    ) -> Result<Vec<u8>, ffi::PackBridgeError> {
        let sender_identity = build_identity_pair(sender_identity_public, sender_identity_private)?;
        let recipient = IdentityKey::from_bytes(
            recipient_identity
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("recipient key must be 32 bytes".into()))?,
        )
        .map_err(|e| ffi::PackBridgeError::InvalidKey(e.to_string()))?;

        map_err(api::PackSealedSender::encrypt_raw_cert(
            &sender_identity, raw_cert_blob, &recipient, inner_message, current_time,
        ))
    }

    fn sealed_decrypt_raw_cert(
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

        let result = map_err(api::PackSealedSender::decrypt_raw_cert(
            &our_identity, ciphertext, &trust_root_key, current_time,
        ))?;

        Ok(ffi::SealedSenderDecryptResult {
            sender_uuid: result.sender_uuid,
            sender_device_id: result.sender_device_id,
            plaintext: result.plaintext,
        })
    }

    fn distribute_sender_key(
        session: &mut PackSessionBridge,
        sender_uuid: &str,
        sender_device_id: u32,
        server_cert_key: &[u8],
        server_cert_id: u32,
        cert_expiration: u64,
        cert_signature: &[u8],
        skdm_bytes: &[u8],
        current_time: u64,
    ) -> Result<Vec<u8>, ffi::PackBridgeError> {
        let server_pub = PublicKey::from_bytes(
            server_cert_key
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("server cert key must be 32 bytes".into()))?,
        );
        let cert = SenderCertificate {
            sender_uuid: sender_uuid.to_string(),
            sender_device_id,
            sender_identity: session.inner.our_identity().clone(),
            expiration: cert_expiration,
            server_certificate: ServerCertificate { key: server_pub, id: server_cert_id },
            signature: cert_signature.to_vec(),
        };

        let skdm = api::SenderKeyDistribution::from_bytes(skdm_bytes.to_vec());

        map_err(api::PackSealedSender::distribute_sender_key(
            &mut session.inner,
            &cert,
            &skdm,
            current_time,
        ))
    }

    fn receive_sender_key(
        session: &mut PackSessionBridge,
        ciphertext: &[u8],
        trust_root: &[u8],
        current_time: u64,
        distribution_id: &str,
    ) -> Result<PackGroupSessionBridge, ffi::PackBridgeError> {
        let trust_root_key = PublicKey::from_bytes(
            trust_root
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("trust root must be 32 bytes".into()))?,
        );

        let (_result, group_session) = map_err(api::PackSealedSender::receive_sender_key(
            &mut session.inner,
            ciphertext,
            &trust_root_key,
            current_time,
            distribution_id,
        ))?;

        Ok(PackGroupSessionBridge {
            inner: group_session,
            distribution_message: None,
        })
    }

    fn encrypt_message(
        group_session: &mut PackGroupSessionBridge,
        sender_identity_public: &[u8],
        sender_identity_private: &[u8],
        sender_uuid: &str,
        sender_device_id: u32,
        server_cert_key: &[u8],
        server_cert_id: u32,
        cert_expiration: u64,
        cert_signature: &[u8],
        recipient_address_name: &str,
        recipient_address_device_id: u32,
        recipient_identity_key: &[u8],
        plaintext: &[u8],
        current_time: u64,
    ) -> Result<Vec<u8>, ffi::PackBridgeError> {
        let sender_identity = build_identity_pair(sender_identity_public, sender_identity_private)?;
        let server_pub = PublicKey::from_bytes(
            server_cert_key
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("server cert key must be 32 bytes".into()))?,
        );
        let cert = SenderCertificate {
            sender_uuid: sender_uuid.to_string(),
            sender_device_id,
            sender_identity: sender_identity.public.clone(),
            expiration: cert_expiration,
            server_certificate: ServerCertificate { key: server_pub, id: server_cert_id },
            signature: cert_signature.to_vec(),
        };
        let recipient_ik = IdentityKey::from_bytes(
            recipient_identity_key
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("recipient key must be 32 bytes".into()))?,
        ).map_err(|e| ffi::PackBridgeError::InvalidKey(e.to_string()))?;
        let addr = ProtocolAddress::new(recipient_address_name.to_string(), recipient_address_device_id);
        let recipients = [api::Recipient { address: &addr, identity: &recipient_ik }];

        let blobs = map_err(api::PackSealedSender::encrypt_message(
            &mut group_session.inner,
            &sender_identity,
            &cert,
            &recipients,
            plaintext,
            current_time,
        ))?;

        Ok(blobs.into_iter().next().map(|b| b.ciphertext).unwrap_or_default())
    }

    fn decrypt_message(
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

        let envelope = map_err(api::PackSealedSender::decrypt_message(
            &our_identity, ciphertext, &trust_root_key, current_time,
        ))?;

        let inner = envelope.inner_ciphertext();
        Ok(ffi::SealedSenderDecryptResult {
            sender_uuid: envelope.sender_uuid,
            sender_device_id: envelope.sender_device_id,
            plaintext: inner,
        })
    }

    fn decrypt_envelope(
        group_session: &mut PackGroupSessionBridge,
        inner_ciphertext: &[u8],
    ) -> Result<Vec<u8>, ffi::PackBridgeError> {
        let envelope = api::SealedEnvelope::from_inner(inner_ciphertext.to_vec());
        map_err(envelope.decrypt(&mut group_session.inner))
    }
}

// ── PackFingerprint bridge ──

pub struct PackFingerprintBridge;

impl PackFingerprintBridge {
    fn generate(
        local_identifier: &str,
        local_identity_key: &[u8],
        remote_identifier: &str,
        remote_identity_key: &[u8],
    ) -> Result<ffi::FingerprintResult, ffi::PackBridgeError> {
        let local_ik = IdentityKey::from_bytes(
            local_identity_key
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("local identity key must be 32 bytes".into()))?,
        ).map_err(|e| ffi::PackBridgeError::InvalidKey(e.to_string()))?;

        let remote_ik = IdentityKey::from_bytes(
            remote_identity_key
                .try_into()
                .map_err(|_| ffi::PackBridgeError::InvalidKey("remote identity key must be 32 bytes".into()))?,
        ).map_err(|e| ffi::PackBridgeError::InvalidKey(e.to_string()))?;

        let fp = api::PackFingerprint::generate(
            local_identifier,
            &local_ik,
            remote_identifier,
            &remote_ik,
        );

        Ok(ffi::FingerprintResult {
            display_text: fp.displayable.display(),
            scannable_bytes: fp.scannable.to_bytes(),
        })
    }

    fn generate_for_session(
        session: &PackSessionBridge,
        local_identifier: &str,
        remote_identifier: &str,
    ) -> ffi::FingerprintResult {
        let fp = api::PackFingerprint::generate_for_session(
            &session.inner,
            local_identifier,
            remote_identifier,
        );

        ffi::FingerprintResult {
            display_text: fp.displayable.display(),
            scannable_bytes: fp.scannable.to_bytes(),
        }
    }

    fn verify_scanned(
        local_scannable: &[u8],
        scanned: &[u8],
    ) -> Result<bool, ffi::PackBridgeError> {
        let local = map_err(ScannableFingerprint::from_bytes(local_scannable))?;
        let remote = map_err(ScannableFingerprint::from_bytes(scanned))?;
        map_err(local.verify(&remote))
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

// ── PackKeyGenerator bridge ──

pub struct PackKeyGeneratorBridge;

impl PackKeyGeneratorBridge {
    fn generate_identity_key_pair() -> ffi::KeyPairResult {
        let ikp = IdentityKeyPair::generate();
        ffi::KeyPairResult {
            public_key: ikp.public.as_bytes().to_vec(),
            private_key: ikp.private_key().as_bytes().to_vec(),
        }
    }

    fn generate_signed_pre_key(
        id: u32,
        identity_public: &[u8],
        identity_private: &[u8],
        timestamp: u64,
    ) -> Result<ffi::SignedPreKeyResult, ffi::PackBridgeError> {
        let identity = build_identity_pair(identity_public, identity_private)?;
        let spk = SignedPreKey::generate(id, &identity, timestamp);
        Ok(ffi::SignedPreKeyResult {
            id: spk.id,
            public_key: spk.key_pair.public.as_bytes().to_vec(),
            private_key: spk.key_pair.private.as_bytes().to_vec(),
            signature: spk.signature.to_vec(),
            timestamp: spk.timestamp,
        })
    }

    fn generate_one_time_pre_key(id: u32) -> ffi::KeyPairResult {
        let opk = OneTimePreKey::generate(id);
        ffi::KeyPairResult {
            public_key: opk.key_pair.public.as_bytes().to_vec(),
            private_key: opk.key_pair.private.as_bytes().to_vec(),
        }
    }

    fn generate_pq_pre_key(
        id: u32,
        identity_public: &[u8],
        identity_private: &[u8],
        timestamp: u64,
    ) -> Result<ffi::PQPreKeyResult, ffi::PackBridgeError> {
        let identity = build_identity_pair(identity_public, identity_private)?;
        let pqpk = PQPreKey::generate(id, &identity, timestamp);
        Ok(ffi::PQPreKeyResult {
            id: pqpk.id,
            encapsulation_key: pqpk.encapsulation_key_bytes(),
            decapsulation_key: pqpk.decapsulation_key_bytes(),
            signature: pqpk.signature.to_vec(),
            timestamp: pqpk.timestamp,
        })
    }

    fn xeddsa_sign(
        private_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, ffi::PackBridgeError> {
        let priv_arr: [u8; 32] = private_key
            .try_into()
            .map_err(|_| ffi::PackBridgeError::InvalidKey("private key must be 32 bytes".into()))?;
        let pk = PrivateKey::from_bytes(priv_arr);
        let sig = pack_protocol::crypto::curve::xeddsa_sign(&pk, message);
        Ok(sig.to_vec())
    }
}

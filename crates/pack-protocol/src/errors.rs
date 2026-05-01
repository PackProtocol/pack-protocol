// Implements: Error types for the pack protocol library
// Source: Application-level concern, not specified by any single protocol document

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("untrusted identity for {0}")]
    UntrustedIdentity(String),

    #[error("duplicate message")]
    DuplicateMessage,

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("invalid MAC")]
    InvalidMac,

    #[error("no session for {0}")]
    NoSession(String),

    #[error("session not found")]
    SessionNotFound,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("stale key exchange")]
    StaleKeyExchange,

    #[error("too many skipped messages")]
    TooManySkippedMessages,

    #[error("expired certificate")]
    ExpiredCertificate,

    #[error("invalid certificate")]
    InvalidCertificate,

    #[error("storage error: {0}")]
    Storage(String),

    #[error("crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, PackError>;

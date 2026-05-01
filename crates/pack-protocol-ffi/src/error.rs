use pack_protocol::errors::PackError;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackFfiError {
    Ok = 0,
    InvalidArgument = 1,
    InvalidKey = 2,
    InvalidSignature = 3,
    InvalidMessage = 4,
    InvalidMac = 5,
    UntrustedIdentity = 6,
    NoSession = 7,
    DuplicateMessage = 8,
    ExpiredCertificate = 9,
    InvalidCertificate = 10,
    TooManySkippedMessages = 11,
    InternalError = 255,
}

impl From<PackError> for PackFfiError {
    fn from(err: PackError) -> Self {
        match err {
            PackError::InvalidKey(_) => PackFfiError::InvalidKey,
            PackError::InvalidSignature => PackFfiError::InvalidSignature,
            PackError::InvalidMessage(_) => PackFfiError::InvalidMessage,
            PackError::InvalidMac => PackFfiError::InvalidMac,
            PackError::UntrustedIdentity(_) => PackFfiError::UntrustedIdentity,
            PackError::NoSession(_) => PackFfiError::NoSession,
            PackError::SessionNotFound => PackFfiError::NoSession,
            PackError::DuplicateMessage => PackFfiError::DuplicateMessage,
            PackError::ExpiredCertificate => PackFfiError::ExpiredCertificate,
            PackError::InvalidCertificate => PackFfiError::InvalidCertificate,
            PackError::TooManySkippedMessages => PackFfiError::TooManySkippedMessages,
            PackError::StaleKeyExchange => PackFfiError::InvalidMessage,
            PackError::Storage(_) => PackFfiError::InternalError,
            PackError::Crypto(_) => PackFfiError::InternalError,
        }
    }
}

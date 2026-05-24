use crate::errors::{PackError, Result};
use ml_kem::kem::Key;
use ml_kem::ml_kem_768::EncapsulationKey;

pub fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey> {
    let key: Key<EncapsulationKey> = bytes
        .try_into()
        .map_err(|_| PackError::InvalidKey(
            format!("invalid encapsulation key length: expected {}, got {}", std::mem::size_of::<Key<EncapsulationKey>>(), bytes.len()),
        ))?;
    EncapsulationKey::new(&key)
        .map_err(|_| PackError::InvalidKey("invalid encapsulation key".into()))
}

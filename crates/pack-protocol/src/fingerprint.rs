// Implements: Safety number / fingerprint generation and verification
// Source: Public safety number specification
//
// Safety numbers let users verify they are communicating with the right person.
// A displayable fingerprint is a 60-digit numeric string (two 30-digit halves,
// one per party). A scannable fingerprint is a compact binary format suitable
// for QR codes that can be verified by scanning.
//
// The fingerprint for each party is computed by iterating SHA-512 over the
// identity key and stable identifier 5200 times, then encoding the result
// as groups of 5-digit numbers.

use sha2::{Sha512, Digest};

use crate::keys::IdentityKey;
use crate::errors::{Result, PackError};

const FINGERPRINT_VERSION: u16 = 0;
const ITERATIONS: usize = 5200;
const DISPLAYABLE_DIGITS: usize = 30;

fn compute_fingerprint_hash(
    stable_identifier: &[u8],
    identity_key: &IdentityKey,
) -> [u8; 32] {
    let pub_key_bytes = identity_key.as_bytes();

    // Start with: version || public_key || stable_identifier
    let mut hash_input = Vec::new();
    hash_input.extend_from_slice(&FINGERPRINT_VERSION.to_be_bytes());
    hash_input.extend_from_slice(pub_key_bytes);
    hash_input.extend_from_slice(stable_identifier);

    // Iterate SHA-512 5200 times
    // Each iteration: SHA-512(hash_input || public_key)
    let mut current = {
        let mut hasher = Sha512::new();
        hasher.update(&hash_input);
        hasher.update(pub_key_bytes);
        hasher.finalize().to_vec()
    };

    for _ in 1..ITERATIONS {
        let mut hasher = Sha512::new();
        hasher.update(&current);
        hasher.update(pub_key_bytes);
        current = hasher.finalize().to_vec();
    }

    // Take first 32 bytes
    let mut result = [0u8; 32];
    result.copy_from_slice(&current[..32]);
    result
}

fn encode_fingerprint_digits(hash: &[u8; 32]) -> String {
    // Encode 30 digits from the hash: 6 groups of 5 digits
    // Each 5-digit group is derived from 5 bytes interpreted as a big-endian integer mod 100000
    let mut digits = String::with_capacity(DISPLAYABLE_DIGITS);
    for chunk_idx in 0..6 {
        let offset = chunk_idx * 5;
        let value = u64::from(hash[offset]) << 32
            | u64::from(hash[offset + 1]) << 24
            | u64::from(hash[offset + 2]) << 16
            | u64::from(hash[offset + 3]) << 8
            | u64::from(hash[offset + 4]);
        digits.push_str(&format!("{:05}", value % 100_000));
    }
    digits
}

/// A displayable fingerprint — the 60-digit safety number shown to users.
pub struct DisplayableFingerprint {
    pub local_digits: String,
    pub remote_digits: String,
}

impl DisplayableFingerprint {
    /// Format as the full safety number (local + remote, sorted for consistency).
    pub fn display(&self) -> String {
        if self.local_digits <= self.remote_digits {
            format!("{}{}", self.local_digits, self.remote_digits)
        } else {
            format!("{}{}", self.remote_digits, self.local_digits)
        }
    }
}

/// A scannable fingerprint for QR code verification.
pub struct ScannableFingerprint {
    pub version: u16,
    pub local_fingerprint: [u8; 32],
    pub remote_fingerprint: [u8; 32],
}

impl ScannableFingerprint {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + 32 + 32);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&self.local_fingerprint);
        buf.extend_from_slice(&self.remote_fingerprint);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 66 {
            return Err(PackError::InvalidMessage("scannable fingerprint too short".into()));
        }
        let version = u16::from_be_bytes([data[0], data[1]]);
        let mut local_fingerprint = [0u8; 32];
        local_fingerprint.copy_from_slice(&data[2..34]);
        let mut remote_fingerprint = [0u8; 32];
        remote_fingerprint.copy_from_slice(&data[34..66]);
        Ok(Self { version, local_fingerprint, remote_fingerprint })
    }

    /// Verify a scanned fingerprint matches our view of the conversation.
    /// The scanned fingerprint's local should match our remote and vice versa.
    pub fn verify(&self, scanned: &ScannableFingerprint) -> Result<bool> {
        use subtle::ConstantTimeEq;
        if self.version != scanned.version {
            return Err(PackError::InvalidMessage("fingerprint version mismatch".into()));
        }
        let local_match = self.local_fingerprint.ct_eq(&scanned.remote_fingerprint);
        let remote_match = self.remote_fingerprint.ct_eq(&scanned.local_fingerprint);
        Ok((local_match & remote_match).into())
    }
}

/// Combined fingerprint holding both displayable and scannable forms.
pub struct Fingerprint {
    pub displayable: DisplayableFingerprint,
    pub scannable: ScannableFingerprint,
}

/// Generate a fingerprint for a conversation between two parties.
///
/// Each party provides their stable identifier (e.g. phone number or UUID)
/// and their identity key. The fingerprint is deterministic given the same inputs.
pub fn generate_fingerprint(
    local_identifier: &[u8],
    local_identity: &IdentityKey,
    remote_identifier: &[u8],
    remote_identity: &IdentityKey,
) -> Fingerprint {
    let local_hash = compute_fingerprint_hash(local_identifier, local_identity);
    let remote_hash = compute_fingerprint_hash(remote_identifier, remote_identity);

    let local_digits = encode_fingerprint_digits(&local_hash);
    let remote_digits = encode_fingerprint_digits(&remote_hash);

    Fingerprint {
        displayable: DisplayableFingerprint {
            local_digits,
            remote_digits,
        },
        scannable: ScannableFingerprint {
            version: FINGERPRINT_VERSION,
            local_fingerprint: local_hash,
            remote_fingerprint: remote_hash,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeyPair;

    #[test]
    fn test_fingerprint_determinism() {
        let alice_id = IdentityKeyPair::generate();
        let bob_id = IdentityKeyPair::generate();

        let fp1 = generate_fingerprint(
            b"+14155551234", &alice_id.public,
            b"+14155555678", &bob_id.public,
        );
        let fp2 = generate_fingerprint(
            b"+14155551234", &alice_id.public,
            b"+14155555678", &bob_id.public,
        );

        assert_eq!(fp1.displayable.display(), fp2.displayable.display());
        assert_eq!(fp1.scannable.local_fingerprint, fp2.scannable.local_fingerprint);
        assert_eq!(fp1.scannable.remote_fingerprint, fp2.scannable.remote_fingerprint);
    }

    #[test]
    fn test_fingerprint_symmetry() {
        let alice_id = IdentityKeyPair::generate();
        let bob_id = IdentityKeyPair::generate();

        let alice_fp = generate_fingerprint(
            b"+14155551234", &alice_id.public,
            b"+14155555678", &bob_id.public,
        );
        let bob_fp = generate_fingerprint(
            b"+14155555678", &bob_id.public,
            b"+14155551234", &alice_id.public,
        );

        // Both sides should produce the same display string
        assert_eq!(alice_fp.displayable.display(), bob_fp.displayable.display());
    }

    #[test]
    fn test_fingerprint_different_keys_different_output() {
        let alice1 = IdentityKeyPair::generate();
        let alice2 = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let fp1 = generate_fingerprint(
            b"+14155551234", &alice1.public,
            b"+14155555678", &bob.public,
        );
        let fp2 = generate_fingerprint(
            b"+14155551234", &alice2.public,
            b"+14155555678", &bob.public,
        );

        assert_ne!(fp1.displayable.display(), fp2.displayable.display());
    }

    #[test]
    fn test_displayable_fingerprint_length() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let fp = generate_fingerprint(
            b"alice", &alice.public,
            b"bob", &bob.public,
        );

        assert_eq!(fp.displayable.local_digits.len(), 30);
        assert_eq!(fp.displayable.remote_digits.len(), 30);
        assert_eq!(fp.displayable.display().len(), 60);
        assert!(fp.displayable.display().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_scannable_fingerprint_roundtrip() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let fp = generate_fingerprint(
            b"alice", &alice.public,
            b"bob", &bob.public,
        );

        let bytes = fp.scannable.to_bytes();
        let parsed = ScannableFingerprint::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, fp.scannable.version);
        assert_eq!(parsed.local_fingerprint, fp.scannable.local_fingerprint);
        assert_eq!(parsed.remote_fingerprint, fp.scannable.remote_fingerprint);
    }

    #[test]
    fn test_scannable_fingerprint_verify() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_fp = generate_fingerprint(
            b"alice", &alice.public,
            b"bob", &bob.public,
        );
        let bob_fp = generate_fingerprint(
            b"bob", &bob.public,
            b"alice", &alice.public,
        );

        // Alice scans Bob's QR code — Bob's scannable has (bob_local, alice_remote)
        // Alice verifies: her local == Bob's remote, her remote == Bob's local
        assert!(alice_fp.scannable.verify(&bob_fp.scannable).unwrap());
        assert!(bob_fp.scannable.verify(&alice_fp.scannable).unwrap());
    }

    #[test]
    fn test_scannable_fingerprint_verify_mismatch() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let eve = IdentityKeyPair::generate();

        let alice_fp = generate_fingerprint(
            b"alice", &alice.public,
            b"bob", &bob.public,
        );
        let eve_fp = generate_fingerprint(
            b"eve", &eve.public,
            b"alice", &alice.public,
        );

        // Eve's fingerprint should not verify against Alice's
        assert!(!alice_fp.scannable.verify(&eve_fp.scannable).unwrap());
    }
}

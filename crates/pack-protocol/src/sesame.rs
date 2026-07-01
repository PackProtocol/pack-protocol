// Implements: Sesame multi-device session management
// Source: SESAME session management specification
//
// Sesame manages sessions across multiple devices belonging to a single user.
// When sending to a user, we encrypt separately for each of their known devices.
// When receiving, we route to the correct session based on device ID.

use crate::errors::{Result, PackError};
use crate::store::ProtocolAddress;

/// Represents a user's set of known devices.
pub struct DeviceSet {
    pub user_id: String,
    pub device_ids: Vec<u32>,
}

impl DeviceSet {
    pub fn new(user_id: String) -> Self {
        Self {
            user_id,
            device_ids: Vec::new(),
        }
    }

    pub fn add_device(&mut self, device_id: u32) {
        if !self.device_ids.contains(&device_id) {
            self.device_ids.push(device_id);
        }
    }

    pub fn remove_device(&mut self, device_id: u32) {
        self.device_ids.retain(|&id| id != device_id);
    }

    pub fn addresses(&self) -> Vec<ProtocolAddress> {
        self.device_ids.iter()
            .map(|&id| ProtocolAddress::new(self.user_id.clone(), id))
            .collect()
    }

    pub fn contains(&self, device_id: u32) -> bool {
        self.device_ids.contains(&device_id)
    }
}

/// Result of encrypting for multiple devices.
pub struct MultiDeviceBundle {
    pub messages: Vec<DeviceMessage>,
    pub stale_devices: Vec<u32>,
}

/// A message targeted to a specific device.
pub struct DeviceMessage {
    pub address: ProtocolAddress,
    pub ciphertext: Vec<u8>,
}

/// Determines which devices to encrypt for, given the known device set.
///
/// Returns addresses for all known devices, excluding any devices
/// explicitly marked as stale by the server.
pub fn resolve_devices(
    device_set: &DeviceSet,
    stale_device_ids: &[u32],
) -> (Vec<ProtocolAddress>, Vec<u32>) {
    let mut active = Vec::new();
    let mut stale = Vec::new();

    for &device_id in &device_set.device_ids {
        if stale_device_ids.contains(&device_id) {
            stale.push(device_id);
        } else {
            active.push(ProtocolAddress::new(device_set.user_id.clone(), device_id));
        }
    }

    (active, stale)
}

/// Check if we have sessions for all target devices.
/// Returns the list of devices that need new sessions established.
pub fn find_devices_without_sessions(
    target_devices: &[ProtocolAddress],
    has_session: impl Fn(&ProtocolAddress) -> bool,
) -> Vec<ProtocolAddress> {
    target_devices.iter()
        .filter(|addr| !has_session(addr))
        .cloned()
        .collect()
}

/// Route an incoming message to the correct session based on sender device.
pub fn route_incoming_message(
    sender_user_id: &str,
    sender_device_id: u32,
) -> ProtocolAddress {
    ProtocolAddress::new(sender_user_id.to_string(), sender_device_id)
}

/// Validate that a device ID is reasonable (non-zero, within bounds).
pub fn validate_device_id(device_id: u32) -> Result<()> {
    if device_id == 0 {
        return Err(PackError::InvalidMessage("device ID cannot be zero".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_set_add_remove() {
        let mut ds = DeviceSet::new("alice".into());
        ds.add_device(1);
        ds.add_device(2);
        ds.add_device(3);
        assert_eq!(ds.device_ids.len(), 3);

        ds.add_device(2);
        assert_eq!(ds.device_ids.len(), 3);

        ds.remove_device(2);
        assert_eq!(ds.device_ids.len(), 2);
        assert!(!ds.contains(2));
        assert!(ds.contains(1));
        assert!(ds.contains(3));
    }

    #[test]
    fn test_device_set_addresses() {
        let mut ds = DeviceSet::new("bob".into());
        ds.add_device(1);
        ds.add_device(5);

        let addrs = ds.addresses();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].name, "bob");
        assert_eq!(addrs[0].device_id, 1);
        assert_eq!(addrs[1].device_id, 5);
    }

    #[test]
    fn test_resolve_devices_filters_stale() {
        let mut ds = DeviceSet::new("carol".into());
        ds.add_device(1);
        ds.add_device(2);
        ds.add_device(3);

        let (active, stale) = resolve_devices(&ds, &[2]);
        assert_eq!(active.len(), 2);
        assert_eq!(stale, vec![2]);
        assert!(active.iter().all(|a| a.device_id != 2));
    }

    #[test]
    fn test_find_devices_without_sessions() {
        let addrs = vec![
            ProtocolAddress::new("alice".into(), 1),
            ProtocolAddress::new("alice".into(), 2),
            ProtocolAddress::new("alice".into(), 3),
        ];

        let needs_session = find_devices_without_sessions(&addrs, |addr| {
            addr.device_id == 1 || addr.device_id == 3
        });

        assert_eq!(needs_session.len(), 1);
        assert_eq!(needs_session[0].device_id, 2);
    }

    #[test]
    fn test_route_incoming_message() {
        let addr = route_incoming_message("dave", 7);
        assert_eq!(addr.name, "dave");
        assert_eq!(addr.device_id, 7);
    }

    #[test]
    fn test_validate_device_id() {
        assert!(validate_device_id(0).is_err());
        assert!(validate_device_id(1).is_ok());
        assert!(validate_device_id(u32::MAX).is_ok());
    }
}

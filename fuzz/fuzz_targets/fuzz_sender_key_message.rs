#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::group::{self, SenderKeyRecord, SenderKeyDistributionMessage, SenderKeyMessage};

fuzz_target!(|data: &[u8]| {
    let _ = SenderKeyDistributionMessage::from_bytes(data);
    let _ = SenderKeyMessage::from_bytes(data);

    if let Ok(msg) = SenderKeyMessage::from_bytes(data) {
        let mut record = SenderKeyRecord::new();
        let _ = group::group_decrypt(&mut record, &msg);
    }
});

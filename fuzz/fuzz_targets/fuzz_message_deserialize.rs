#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::message::{PackMessage, PreKeyPackMessage};

fuzz_target!(|data: &[u8]| {
    let _ = PackMessage::from_bytes(data);
    let _ = PreKeyPackMessage::from_bytes(data);
});

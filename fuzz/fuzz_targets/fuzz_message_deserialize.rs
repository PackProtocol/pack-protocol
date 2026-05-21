#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::message::{PackMessage, PreKeyPackMessage};

fuzz_target!(|data: &[u8]| {
    let _ = PackMessage::deserialize(data);
    let _ = PreKeyPackMessage::deserialize(data);
});

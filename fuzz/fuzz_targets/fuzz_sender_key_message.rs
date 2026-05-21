#![no_main]
use libfuzzer_sys::fuzz_target;
use pack_protocol::group::{
    self, SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecord,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let strategy = data[0] % 4;
    let fuzz_data = &data[1..];

    // Set up a real sender→receiver group session
    let mut sender_record = SenderKeyRecord::new();
    let dist_msg =
        group::create_sender_key_distribution_message("fuzz-group", &mut sender_record).unwrap();

    let mut receiver_record = SenderKeyRecord::new();
    group::process_sender_key_distribution_message(&mut receiver_record, &dist_msg);

    // Encrypt a real message so both sides have advanced state
    let real_msg = group::group_encrypt(&mut sender_record, b"real message").unwrap();
    let _ = group::group_decrypt(&mut receiver_record, &real_msg);

    match strategy {
        0 => {
            // Fuzz: random bytes as SenderKeyMessage
            let _ = SenderKeyDistributionMessage::from_bytes(fuzz_data);
            if let Ok(msg) = SenderKeyMessage::from_bytes(fuzz_data) {
                let _ = group::group_decrypt(&mut receiver_record, &msg);
            }
        }
        1 => {
            // Fuzz: valid message with corrupted ciphertext (signature check should catch)
            let mut msg = group::group_encrypt(&mut sender_record, b"target msg").unwrap();
            for (i, &byte) in fuzz_data.iter().enumerate() {
                if i < msg.ciphertext.len() {
                    msg.ciphertext[i] ^= byte;
                }
            }
            let _ = group::group_decrypt(&mut receiver_record, &msg);
        }
        2 => {
            // Fuzz: valid message with corrupted signature (bypasses nothing)
            let mut msg = group::group_encrypt(&mut sender_record, b"target msg").unwrap();
            for (i, &byte) in fuzz_data.iter().enumerate() {
                if i < msg.signature.len() {
                    msg.signature[i] ^= byte;
                }
            }
            let _ = group::group_decrypt(&mut receiver_record, &msg);
        }
        3 => {
            // Fuzz: out-of-order + replay with fuzz-controlled delivery order
            if fuzz_data.is_empty() {
                return;
            }
            let count = (fuzz_data[0] % 8) as usize + 2;
            let mut messages = Vec::new();
            for i in 0..count {
                let payload = format!("msg-{i}");
                match group::group_encrypt(&mut sender_record, payload.as_bytes()) {
                    Ok(m) => messages.push(m),
                    Err(_) => return,
                }
            }
            // Deliver in fuzz-determined order (with possible replays)
            for &byte in fuzz_data.iter().skip(1).take(count * 2) {
                let idx = (byte as usize) % messages.len();
                let _ = group::group_decrypt(&mut receiver_record, &messages[idx]);
            }
        }
        _ => {}
    }
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use rusti_proto::decoder::{FrameDecoder, MAX_WIRE_BYTES};
use rusti_proto::{encode_privmsg, parse_frame};

fuzz_target!(|bytes: &[u8]| {
    // Never allocate an unbounded output Vec or make network calls.
    let mut decoder = FrameDecoder::new();
    let chunk_size = 1 + (bytes.len() % 43);
    for chunk in bytes.chunks(chunk_size) {
        decoder.push(chunk, |event| {
            if let Ok(msg) = event {
                if let Some(tag) = msg.tag("time") {
                    if let Some(raw) = tag.normalized_raw_value() {
                        let _ = rusti_proto::tags::unescape_tag_value(raw);
                    }
                }
                if msg.command == "PRIVMSG" {
                    let params = msg.params();
                    if params.len() == 2 {
                        let _ = encode_privmsg(params[0], params[1]);
                    }
                }
            }
        });
        assert!(decoder.pending_bytes() <= MAX_WIRE_BYTES);
    }
    let _ = decoder.finish();
    if let Ok(str_data) = std::str::from_utf8(bytes) {
        let _ = parse_frame(str_data);
    }
});

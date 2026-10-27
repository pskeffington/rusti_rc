//! Offline-only deterministic protocol tests. These are not a substitute for
//! fuzzing, TLS/IRC server interoperability or real legacy hardware tests.
#![forbid(unsafe_code)]

use rusti_proto::cap::{CapNegotiator, CapState};
use rusti_proto::decoder::{FrameDecoder, MAX_WIRE_BYTES};
use rusti_proto::tags::{last_tag, unescape_tag_value};
use rusti_proto::{encode_privmsg, parse_frame, FrameError, MAX_BASE_BYTES};

#[test]
fn ircv3_tag_extends_only_its_own_budget() {
    let large_tag = format!("@name={} PING :ok\r\n", "x".repeat(4090));
    assert!(parse_frame(&large_tag).is_ok());
    let too_long_base = format!("@name=a PRIVMSG #x :{}\r\n", "x".repeat(501));
    assert_eq!(parse_frame(&too_long_base), Err(FrameError::OverlongLine));
    let prefix = format!("@{} PING :ok\r\n", "x".repeat(8190));
    assert_eq!(parse_frame(&prefix), Err(FrameError::OverlongLine));
}

#[test]
fn metadata_and_names_never_assert_identity() {
    let frame = parse_frame(
        "@account=overseer;account=untrusted;nonce=abc :overseer!u@host PRIVMSG #ops :hello\r\n",
    )
    .unwrap();
    assert_eq!(frame.tag("account").unwrap().raw_value, Some("untrusted"));
    assert_eq!(frame.prefix, Some("overseer!u@host"));
    assert_eq!(frame.command, "PRIVMSG");
    assert_eq!(last_tag("z;z=", "z").unwrap().normalized_raw_value(), None);
}

#[test]
fn tag_unescape_is_data_not_an_outbound_command() {
    let text = unescape_tag_value(r"evil\r\nOPER root");
    assert_eq!(encode_privmsg("#ops", &text), Err(FrameError::ForbiddenControl));
}

#[test]
fn no_oversize_frame_reaches_callback() {
    let mut decoder = FrameDecoder::new();
    let mut errors = Vec::new();
    let mut payload = vec![b'A'; MAX_WIRE_BYTES + 16];
    payload.extend_from_slice(b"\r\nPING :resync\r\n");
    decoder.push(&payload, |item| {
        errors.push(item.map(|msg| msg.command.to_owned()));
    });
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0], Err(FrameError::OverlongLine));
    assert_eq!(errors[1], Ok("PING".to_owned()));
    assert_eq!(decoder.pending_bytes(), 0);
}

#[test]
fn output_never_crosses_512_bytes_even_with_utf8() {
    let target = "#ops";
    let usable = MAX_BASE_BYTES - format!("PRIVMSG {} :\r\n", target).len();
    let text = "x".repeat(usable);
    assert_eq!(encode_privmsg(target, &text).unwrap().len(), 512);
    assert_eq!(
        encode_privmsg(target, &(text + "z")),
        Err(FrameError::OverlongLine)
    );
}

#[test]
fn cap_requires_explicit_begin_and_exact_ack() {
    let mut cap = CapNegotiator::new(&["message-tags"], &["server-time"]).unwrap();
    let ls = parse_frame("CAP * LS :message-tags server-time\r\n").unwrap();
    assert!(cap.observe(&ls).is_err());
    assert_eq!(cap.begin(), Ok("CAP LS 302\r\n"));
    assert_eq!(
        cap.observe(&ls),
        Ok(Some("CAP REQ :message-tags server-time\r\n".to_owned()))
    );
    let unsolicited = parse_frame("CAP * ACK :message-tags multi-prefix\r\n").unwrap();
    assert!(cap.observe(&unsolicited).is_err());
    assert_eq!(cap.state(), CapState::Failed);
}

#[test]
fn deterministic_arbitrary_streams_remain_bounded_and_never_panic() {
    let mut state: u64 = 0x4d595df4d0f33173;
    for _trial in 0..400 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = (state as usize) % (MAX_WIRE_BYTES * 2);
        let mut bytes = vec![0u8; len];
        for b in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = state as u8;
        }
        let mut decoder = FrameDecoder::new();
        for chunk in bytes.chunks(1 + ((state >> 16) as usize % 47)) {
            decoder.push(chunk, |result| {
                if let Ok(frame) = result {
                    let _ = frame.tag("time");
                    let _ = frame.params();
                }
            });
            assert!(decoder.pending_bytes() <= MAX_WIRE_BYTES);
        }
        let _ = decoder.finish();
    }
}

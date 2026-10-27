//! Limited, dependency-free IRC wire framing.
//!
//! No sockets, credential handling, rendering, or trusted commands.
//! G1b preview only: bounded framing, opaque IRCv3 tags, limited CAP 302.
//! Complete RFC numerics, full IRCv3 and authenticated transport remain pending.
#![forbid(unsafe_code)]

pub mod cap;
pub mod decoder;
pub mod registration;
pub mod tags;

/// RFC 1459 / RFC 2812 line ceiling, including CRLF.
pub const MAX_BASE_BYTES: usize = 512;
/// IRCv3 inbound maximum tag prefix, including '@' and separating space.
/// Client-sent tags have a stricter 4094-byte tag-data limit; sending tagged
/// messages is not implemented by this crate.
pub const MAX_INBOUND_TAG_PREFIX_BYTES: usize = 8191;
pub const MAX_PARAMS: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    MissingCrlf,
    EmptyMessage,
    ForbiddenControl,
    OverlongLine,
    MalformedPrefix,
    MalformedTags,
    InvalidCommand,
    TooManyParameters,
    InvalidTarget,
    EmptyText,
    InvalidUtf8,
    TruncatedFrame,
}

/// Borrowed protocol fields. An IRC prefix/nickname is NOT an authenticated
/// device or organizational identity. Tags are untrusted opaque text.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedMessage<'a> {
    pub tags: Option<&'a str>,
    pub prefix: Option<&'a str>,
    pub command: &'a str,
    params: [&'a str; MAX_PARAMS],
    param_count: usize,
}

impl<'a> ParsedMessage<'a> {
    pub fn params(&self) -> &[&'a str] {
        &self.params[..self.param_count]
    }

    /// Returns the last raw IRCv3 tag matching a case-sensitive key.
    /// This is untrusted metadata, never an authentication assertion.
    pub fn tag(&self, key: &str) -> Option<tags::RawTag<'a>> {
        self.tags.and_then(|raw| tags::last_tag(raw, key))
    }
}

fn unsafe_control(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\u{200e}' | '\u{200f}' | '\u{202a}' | '\u{202b}' | '\u{202c}'
                    | '\u{202d}' | '\u{202e}' | '\u{2066}' | '\u{2067}'
                    | '\u{2068}' | '\u{2069}'
            )
    })
}

fn split_token(s: &str) -> (&str, &str) {
    match s.split_once(' ') {
        Some((token, tail)) => (token, tail.trim_start_matches(' ')),
        None => (s, ""),
    }
}

/// Parse one complete CRLF-terminated UTF-8 IRC line, enforcing byte limits.
///
/// This intentionally rejects CTCP control bytes and Unicode bidi controls.
/// It supports opaque IRCv3 tag prefixes. Tag unescaping and limited CAP 302
/// planning live in separate pure-data modules; no protocol field grants trust.
pub fn parse_frame(frame: &str) -> Result<ParsedMessage<'_>, FrameError> {
    if !frame.ends_with("\r\n") {
        return Err(FrameError::MissingCrlf);
    }
    let line = &frame[..frame.len() - 2];
    if line.is_empty() {
        return Err(FrameError::EmptyMessage);
    }
    if unsafe_control(line) {
        return Err(FrameError::ForbiddenControl);
    }
    let mut rest = line;
    let mut tags = None;
    if let Some(after_at) = rest.strip_prefix('@') {
        let (tag_data, tail) = after_at
            .split_once(' ')
            .ok_or(FrameError::MalformedTags)?;
        if tag_data.is_empty() {
            return Err(FrameError::MalformedTags);
        }
        if tag_data.len() + 2 > MAX_INBOUND_TAG_PREFIX_BYTES {
            return Err(FrameError::OverlongLine);
        }
        tags = Some(tag_data);
        rest = tail.trim_start_matches(' ');
    }
    if rest.len() + 2 > MAX_BASE_BYTES {
        return Err(FrameError::OverlongLine);
    }
    if rest.is_empty() {
        return Err(FrameError::EmptyMessage);
    }
    let mut prefix = None;
    if let Some(after_colon) = rest.strip_prefix(':') {
        let (value, tail) = after_colon
            .split_once(' ')
            .ok_or(FrameError::MalformedPrefix)?;
        if value.is_empty() {
            return Err(FrameError::MalformedPrefix);
        }
        prefix = Some(value);
        rest = tail.trim_start_matches(' ');
    }
    let (command, mut tail) = split_token(rest);
    let valid_command = !command.is_empty()
        && (command.bytes().all(|b| b.is_ascii_alphabetic())
            || (command.len() == 3 && command.bytes().all(|b| b.is_ascii_digit())));
    if !valid_command {
        return Err(FrameError::InvalidCommand);
    }
    let mut params = [""; MAX_PARAMS];
    let mut count = 0;
    while !tail.is_empty() {
        if count == MAX_PARAMS {
            return Err(FrameError::TooManyParameters);
        }
        if let Some(trailing) = tail.strip_prefix(':') {
            params[count] = trailing;
            count += 1;
            break;
        }
        let (word, remainder) = split_token(tail);
        if word.is_empty() {
            break;
        }
        params[count] = word;
        count += 1;
        tail = remainder;
    }
    Ok(ParsedMessage {
        tags,
        prefix,
        command,
        params,
        param_count: count,
    })
}

/// Construct a single IRC PRIVMSG command for an explicitly selected target.
/// This is only an encoder: it does not send, authorize, queue, or encrypt.
pub fn encode_privmsg(target: &str, text: &str) -> Result<String, FrameError> {
    let valid_target = !target.is_empty()
        && target.len() <= 100
        && !target.starts_with(':')
        && target.bytes().all(|b| b.is_ascii_graphic() && b != b',');
    if !valid_target {
        return Err(FrameError::InvalidTarget);
    }
    if text.is_empty() {
        return Err(FrameError::EmptyText);
    }
    if unsafe_control(text) {
        return Err(FrameError::ForbiddenControl);
    }
    let frame = format!("PRIVMSG {} :{}\r\n", target, text);
    if frame.len() > MAX_BASE_BYTES {
        return Err(FrameError::OverlongLine);
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_and_tagged_lines() {
        let ping = parse_frame("PING :server.example\r\n").unwrap();
        assert_eq!(ping.command, "PING");
        assert_eq!(ping.params(), &["server.example"]);
        let msg = parse_frame(
            "@time=2026-10-26T00:00:00Z :n!u@h PRIVMSG #ops :hello there\r\n",
        )
        .unwrap();
        assert_eq!(msg.tags, Some("time=2026-10-26T00:00:00Z"));
        assert_eq!(msg.prefix, Some("n!u@h"));
        assert_eq!(msg.params(), &["#ops", "hello there"]);
    }

    #[test]
    fn rejects_malformed_and_unsafe_frames() {
        assert_eq!(parse_frame("PING :test\n"), Err(FrameError::MissingCrlf));
        assert_eq!(parse_frame("PING :a\nb\r\n"), Err(FrameError::ForbiddenControl));
        assert_eq!(parse_frame("@bad\r\n"), Err(FrameError::MalformedTags));
        assert_eq!(parse_frame(":bad\r\n"), Err(FrameError::MalformedPrefix));
        assert_eq!(parse_frame("TH!NG :x\r\n"), Err(FrameError::InvalidCommand));
        assert_eq!(parse_frame("PRIVMSG #a :\u{202e}spoof\r\n"), Err(FrameError::ForbiddenControl));
    }

    #[test]
    fn rejects_oversize_base_and_tag_prefix() {
        assert_eq!(
            parse_frame(&format!("NOTICE #a :{}\r\n", "x".repeat(501))),
            Err(FrameError::OverlongLine)
        );
        assert_eq!(
            parse_frame(&format!("@{} PING :ok\r\n", "a".repeat(8190))),
            Err(FrameError::OverlongLine)
        );
    }

    #[test]
    fn encoder_rejects_crlf_injection_and_oversize() {
        assert_eq!(encode_privmsg("#ops", "hello\r\nOPER root"), Err(FrameError::ForbiddenControl));
        assert_eq!(encode_privmsg("#bad target", "hi"), Err(FrameError::InvalidTarget));
        assert_eq!(encode_privmsg("#ops", ""), Err(FrameError::EmptyText));
        assert_eq!(
            encode_privmsg("#ops", &"x".repeat(600)),
            Err(FrameError::OverlongLine)
        );
        assert_eq!(encode_privmsg("#ops", "hello").unwrap(), "PRIVMSG #ops :hello\r\n");
    }

    #[test]
    fn preserves_non_ascii_text_and_exact_boundary() {
        let prefix_len = "PRIVMSG #a :\r\n".len();
        assert_eq!(
            encode_privmsg("#a", &"x".repeat(MAX_BASE_BYTES - prefix_len))
                .unwrap().len(),
            MAX_BASE_BYTES
        );
        let frame = encode_privmsg("#a", "café").unwrap();
        assert_eq!(frame.len(), "PRIVMSG #a :café\r\n".len());
    }

    #[test]
    fn limits_parameter_count() {
        let mut frame = String::from("CMD");
        for _ in 0..16 {
            frame.push_str(" a");
        }
        frame.push_str("\r\n");
        assert_eq!(parse_frame(&frame), Err(FrameError::TooManyParameters));
    }
}

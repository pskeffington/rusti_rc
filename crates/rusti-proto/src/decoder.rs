//! Bounded incremental IRC wire framing for byte streams.
//!
//! No sockets or background tasks. A future TLS reader must drive this with
//! bounded chunks and explicitly decide what to do on protocol errors.
#![forbid(unsafe_code)]

use crate::{parse_frame, FrameError, ParsedMessage, MAX_BASE_BYTES, MAX_INBOUND_TAG_PREFIX_BYTES};

/// 8191 bytes of server-to-client tags + 512 bytes of IRC base line.
/// Includes both structural separators and CRLF.
pub const MAX_WIRE_BYTES: usize = MAX_BASE_BYTES + MAX_INBOUND_TAG_PREFIX_BYTES;

/// Each decoder buffers at most MAX_WIRE_BYTES of untrusted data.
/// After overflow it discards through the next newline before resynchronizing.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    dropping_until_newline: bool,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of buffered bytes; always <= MAX_WIRE_BYTES.
    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn discarding_overlong_line(&self) -> bool {
        self.dropping_until_newline
    }

    /// Process a transport chunk synchronously. The callback borrows decoded
    /// frames only while it runs and cannot create an unbounded return queue.
    /// Framing errors are reported once per malformed/oversized line.
    pub fn push<F>(&mut self, bytes: &[u8], mut on_frame: F)
    where
        F: for<'a> FnMut(Result<ParsedMessage<'a>, FrameError>),
    {
        for &byte in bytes {
            if self.dropping_until_newline {
                if byte == b'\n' {
                    self.dropping_until_newline = false;
                }
                continue;
            }

            if self.buffer.len() >= MAX_WIRE_BYTES {
                self.buffer.clear();
                self.dropping_until_newline = byte != b'\n';
                on_frame(Err(FrameError::OverlongLine));
                continue;
            }

            self.buffer.push(byte);
            if byte == b'\n' {
                let result = std::str::from_utf8(&self.buffer)
                    .map_err(|_| FrameError::InvalidUtf8)
                    .and_then(parse_frame);
                on_frame(result);
                self.buffer.clear();
            }
        }
    }

    /// End-of-stream is not a successful empty frame. A partial line is
    /// rejected rather than silently converted into a complete message.
    pub fn finish(&mut self) -> Result<(), FrameError> {
        let truncated = !self.buffer.is_empty() || self.dropping_until_newline;
        self.buffer.clear();
        self.dropping_until_newline = false;
        if truncated {
            Err(FrameError::TruncatedFrame)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_fragmented_crlf_and_multiple_frames() {
        let mut d = FrameDecoder::new();
        let mut seen = Vec::new();
        d.push(b"PING :alp", |item| seen.push(item.map(|frame| frame.command.to_owned())));
        assert!(seen.is_empty());
        d.push(b"ha\r\nPING :beta\r\n", |item| {
            seen.push(item.map(|frame| frame.params()[0].to_owned()))
        });
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], Ok("alpha".to_string()));
        assert_eq!(seen[1], Ok("beta".to_string()));
        assert_eq!(d.pending_bytes(), 0);
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn refuses_invalid_utf8_without_lossy_conversion() {
        let mut d = FrameDecoder::new();
        let mut outcomes = Vec::new();
        d.push(b"PING :\xff\r\nPING :good\r\n", |item| {
            outcomes.push(item.map(|msg| msg.command.to_owned()))
        });
        assert_eq!(outcomes[0], Err(FrameError::InvalidUtf8));
        assert_eq!(outcomes[1], Ok("PING".to_string()));
    }

    #[test]
    fn overflow_is_bounded_and_recovers_exactly_once() {
        let mut d = FrameDecoder::new();
        let mut errors = 0;
        d.push(&vec![b'a'; MAX_WIRE_BYTES * 8], |item| {
            if item == Err(FrameError::OverlongLine) {
                errors += 1;
            }
        });
        assert_eq!(errors, 1);
        assert_eq!(d.pending_bytes(), 0);
        assert!(d.discarding_overlong_line());
        let mut next = None;
        d.push(b"\nPING :ok\r\n", |item| {
            next = Some(item.map(|m| m.params()[0].to_owned()));
        });
        assert_eq!(next, Some(Ok("ok".into())));
        assert!(!d.discarding_overlong_line());
    }

    #[test]
    fn aborts_partial_frames_on_eof_and_can_be_reused() {
        let mut d = FrameDecoder::new();
        d.push(b"PING :partial\r", |_| {});
        assert_eq!(d.finish(), Err(FrameError::TruncatedFrame));
        let mut count = 0;
        d.push(b"PING :complete\r\n", |item| {
            assert!(item.is_ok());
            count += 1;
        });
        assert_eq!(count, 1);
    }

    #[test]
    fn linefeed_only_and_embedded_newline_are_rejected() {
        let mut d = FrameDecoder::new();
        let mut errors = Vec::new();
        d.push(b"PING :bad\nPING :good\r\n", |item| {
            errors.push(item.err());
        });
        assert_eq!(errors, vec![Some(FrameError::MissingCrlf), None]);
    }

    #[test]
    fn valid_size_boundary_stays_bounded() {
        let mut d = FrameDecoder::new();
        let frame = format!("PING :{}\r\n", "x".repeat(MAX_BASE_BYTES - "PING :\r\n".len()));
        let mut ok = false;
        d.push(frame.as_bytes(), |item| ok = item.is_ok());
        assert!(ok);
        assert_eq!(d.pending_bytes(), 0);
    }
}

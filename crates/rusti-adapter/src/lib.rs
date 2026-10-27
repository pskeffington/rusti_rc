//! Read-only, untrusted IRC display preview for potential Rust Boy import.
//!
//! This portable crate never connects to IRC, assigns tasks, or authorizes
//! vault, peer, clinical, or organizational actions. Sanitized text is for
//! plain-text rendering only; nicknames remain unverified remote labels.
#![forbid(unsafe_code)]

use rusti_proto::{parse_frame, sanitize_display_text, FrameError};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderTrust {
    /// IRC nick/prefix is a display hint only, never an organization ID.
    UnverifiedRemoteLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    Disabled,
    InvalidFrame(FrameError),
    InvalidChatShape,
}

/// Borrowed untrusted IRC data. Raw fields are private to prevent accidental
/// terminal/HTML rendering or leaking message text in application logs.
#[derive(PartialEq, Eq)]
pub struct UntrustedChat<'a> {
    sender_label: &'a str,
    target: &'a str,
    text: &'a str,
    pub trust: SenderTrust,
}

impl fmt::Debug for UntrustedChat<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UntrustedChat { content: <redacted> }")
    }
}

impl<'a> UntrustedChat<'a> {
    /// A plain-text, control-stripped display value. Do not insert as HTML.
    pub fn display_text(&self) -> String {
        sanitize_display_text(self.text)
    }

    /// IRC sender labels remain unverified even after sanitization.
    pub fn display_sender(&self) -> String {
        sanitize_display_text(self.sender_label)
    }

    pub fn display_target(&self) -> String {
        sanitize_display_text(self.target)
    }
}

#[derive(Debug, Default)]
pub struct ChatPreviewAdapter {
    /// Explicit local operator permission to inspect fixture data.
    pub enabled: bool,
}

impl ChatPreviewAdapter {
    /// Parse a single IRC fixture. Does not open connections, store messages,
    /// assign jobs, or convert IRC events to authenticated Rust Boy commands.
    pub fn inspect_frame<'a>(
        &self,
        wire: &'a str,
    ) -> Result<Option<UntrustedChat<'a>>, AdapterError> {
        if !self.enabled {
            return Err(AdapterError::Disabled);
        }
        let frame = parse_frame(wire).map_err(AdapterError::InvalidFrame)?;
        if !frame.command.eq_ignore_ascii_case("PRIVMSG")
            && !frame.command.eq_ignore_ascii_case("NOTICE")
        {
            return Ok(None);
        }
        let fields = frame.params();
        if fields.len() != 2 || fields[0].is_empty() {
            return Err(AdapterError::InvalidChatShape);
        }
        Ok(Some(UntrustedChat {
            sender_label: frame.prefix.unwrap_or("unidentified"),
            target: fields[0],
            text: fields[1],
            trust: SenderTrust::UnverifiedRemoteLabel,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_adapter_refuses_fixture_inspection() {
        assert_eq!(
            ChatPreviewAdapter::default().inspect_frame(":any PRIVMSG #ops :hi\r\n"),
            Err(AdapterError::Disabled)
        );
    }

    #[test]
    fn all_sender_labels_remain_untrusted() {
        let adapter = ChatPreviewAdapter { enabled: true };
        let chat = adapter
            .inspect_frame(":OVERSEER!u@host PRIVMSG #ops :do something\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(chat.trust, SenderTrust::UnverifiedRemoteLabel);
        assert_eq!(chat.sender_label, "OVERSEER!u@host");
        assert_eq!(chat.text, "do something");
    }

    #[test]
    fn debug_never_prints_message_or_sender() {
        let adapter = ChatPreviewAdapter { enabled: true };
        let chat = adapter
            .inspect_frame(":secretnick!u@host PRIVMSG #ops :sensitive message\r\n")
            .unwrap()
            .unwrap();
        let shown = format!("{chat:?}");
        assert!(!shown.contains("secretnick"));
        assert!(!shown.contains("sensitive"));
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn untrusted_irc_formatting_is_safe_to_render_as_text() {
        let adapter = ChatPreviewAdapter { enabled: true };
        let chat = adapter
            .inspect_frame(":scout!user@host PRIVMSG #ops :\x02Bold\x0f\x1b[2J\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(chat.display_text(), "Bold[2J");
        assert_eq!(chat.display_sender(), "scout!user@host");
        assert_eq!(chat.trust, SenderTrust::UnverifiedRemoteLabel);
    }

    #[test]
    fn non_chat_command_never_becomes_a_task() {
        let adapter = ChatPreviewAdapter { enabled: true };
        assert_eq!(adapter.inspect_frame("OPER operator secret\r\n"), Ok(None));
    }
}

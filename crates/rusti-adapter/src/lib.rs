//! Rust Boy integration preview. No network, role escalation, or task actions.
#![forbid(unsafe_code)]

use rusti_proto::{parse_frame, FrameError};

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

/// Borrowed, display-only data. Callers must render as text, not HTML.
#[derive(Debug, PartialEq, Eq)]
pub struct UntrustedChat<'a> {
    pub sender_label: &'a str,
    pub target: &'a str,
    pub text: &'a str,
    pub trust: SenderTrust,
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
    fn non_chat_command_never_becomes_a_task() {
        let adapter = ChatPreviewAdapter { enabled: true };
        assert_eq!(adapter.inspect_frame("OPER operator secret\r\n"), Ok(None));
    }
}

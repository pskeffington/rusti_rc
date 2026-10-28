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

/// Wire command class is informational only; neither class grants authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatKind {
    Message,
    Notice,
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
    pub kind: ChatKind,
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

    /// Sanitize first, then cap by Unicode scalar values without splitting UTF-8.
    /// A zero budget deliberately yields an empty preview.
    /// The limit controls display size, not authorization or wire framing.
    pub fn display_text_bounded(&self, max_chars: usize) -> String {
        sanitize_display_text(self.text)
            .chars()
            .take(max_chars)
            .collect()
    }

    /// IRC sender labels remain unverified even after sanitization.
    pub fn display_sender(&self) -> String {
        sanitize_display_text(self.sender_label)
    }

    pub fn display_target(&self) -> String {
        sanitize_display_text(self.target)
    }

    /// Display-only command type. A NOTICE is not a verified system alert.
    pub fn kind(&self) -> ChatKind {
        self.kind
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
        let kind = if frame.command.eq_ignore_ascii_case("PRIVMSG") {
            ChatKind::Message
        } else if frame.command.eq_ignore_ascii_case("NOTICE") {
            ChatKind::Notice
        } else {
            return Ok(None);
        };
        let fields = frame.params();
        if fields.len() != 2 || fields[0].is_empty() {
            return Err(AdapterError::InvalidChatShape);
        }
        Ok(Some(UntrustedChat {
            sender_label: frame.prefix.unwrap_or("unidentified"),
            target: fields[0],
            text: fields[1],
            trust: SenderTrust::UnverifiedRemoteLabel,
            kind,
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
    fn notice_cannot_masquerade_as_verified_system_alert() {
        let adapter = ChatPreviewAdapter { enabled: true };
        let notice = adapter
            .inspect_frame(":server NOTICE #ops :URGENT maintenance\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(notice.kind(), ChatKind::Notice);
        assert_eq!(notice.trust, SenderTrust::UnverifiedRemoteLabel);
        assert_eq!(notice.display_sender(), "server");
        let message = adapter
            .inspect_frame(":scout PRIVMSG #ops :hello\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(message.kind(), ChatKind::Message);
        assert_eq!(message.trust, SenderTrust::UnverifiedRemoteLabel);
    }

    #[test]
    fn preview_is_bounded_after_control_stripping() {
        let adapter = ChatPreviewAdapter { enabled: true };
        let chat = adapter
            .inspect_frame(":scout PRIVMSG #ops :\x02Aé🚀BC\x0f\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(chat.display_text_bounded(0), "");
        assert_eq!(chat.display_text_bounded(1), "A");
        assert_eq!(chat.display_text_bounded(3), "Aé🚀");
        assert_eq!(chat.display_text_bounded(99), "Aé🚀BC");
        assert_eq!(chat.trust, SenderTrust::UnverifiedRemoteLabel);
    }

    #[test]
    fn empty_message_preview_is_safe() {
        let adapter = ChatPreviewAdapter { enabled: true };
        let chat = adapter
            .inspect_frame(":scout PRIVMSG #ops :\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(chat.display_text_bounded(10), "");
    }

    #[test]
    fn non_chat_command_never_becomes_a_task() {
        let adapter = ChatPreviewAdapter { enabled: true };
        assert_eq!(adapter.inspect_frame("OPER operator secret\r\n"), Ok(None));
    }
}

/// Fixed-capacity, read-only micro-screen view model for Rust Boy LINK.
/// This is a host-renderable interface, not a networked or interactive IRC client.
pub mod micro_gui {
    use super::{ChatKind, UntrustedChat};

    pub const WIDTH: usize = 32;
    pub const MESSAGE_ROWS: usize = 5;
    pub const MAX_EVENTS: usize = 16;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Key {
        Left,
        Right,
        Up,
        Down,
    }

    /// Reference viewport. The host scales coordinates into its actual display.
    pub const VIEW_WIDTH: u16 = 320;
    pub const VIEW_HEIGHT: u16 = 240;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Rect {
        pub x: u16,
        pub y: u16,
        pub width: u16,
        pub height: u16,
    }

    impl Rect {
        pub const fn new(x: u16, y: u16, width: u16, height: u16) -> Self {
            Self { x, y, width, height }
        }

        pub fn contains(self, x: u16, y: u16) -> bool {
            x >= self.x
                && y >= self.y
                && x < self.x.saturating_add(self.width)
                && y < self.y.saturating_add(self.height)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Layout {
        pub header: Rect,
        pub content: Rect,
        pub footer: Rect,
        pub previous: Rect,
        pub next: Rect,
        pub older: Rect,
        pub newer: Rect,
    }

    impl Layout {
        pub const fn reference() -> Self {
            Self {
                header: Rect::new(0, 0, 320, 32),
                content: Rect::new(8, 36, 304, 156),
                footer: Rect::new(0, 196, 320, 44),
                previous: Rect::new(0, 196, 80, 44),
                next: Rect::new(80, 196, 80, 44),
                older: Rect::new(160, 196, 80, 44),
                newer: Rect::new(240, 196, 80, 44),
            }
        }

        /// Host-side painting uses these regions; no graphics backend is imported.
        pub fn text_origin(self, row: usize) -> Option<(u16, u16)> {
            if row >= 7 {
                return None;
            }
            let y = 48_u16.saturating_add((row as u16) * 21);
            if y >= self.content.y.saturating_add(self.content.height) {
                return None;
            }
            Some((self.content.x.saturating_add(4), y))
        }

        /// Touch hit testing returns local navigation input only.
        pub fn hit_test(self, x: u16, y: u16) -> Option<Key> {
            if self.previous.contains(x, y) {
                Some(Key::Left)
            } else if self.next.contains(x, y) {
                Some(Key::Right)
            } else if self.older.contains(x, y) {
                Some(Key::Up)
            } else if self.newer.contains(x, y) {
                Some(Key::Down)
            } else {
                None
            }
        }

        /// Integer coordinate scaling avoids floats and external dependencies.
        /// Returns None for zero-size displays and out-of-bounds input.
        pub fn hit_test_scaled(
            self,
            x: u32,
            y: u32,
            display_width: u32,
            display_height: u32,
        ) -> Option<Key> {
            if display_width == 0
                || display_height == 0
                || x >= display_width
                || y >= display_height
            {
                return None;
            }
            let sx = (u64::from(x) * u64::from(VIEW_WIDTH)) / u64::from(display_width);
            let sy = (u64::from(y) * u64::from(VIEW_HEIGHT)) / u64::from(display_height);
            self.hit_test(sx as u16, sy as u16)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Page {
        Chat,
        Channels,
        Status,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LinkState {
        Disabled,
        Disconnected,
        Connecting,
        Connected,
        Error,
    }

    impl LinkState {
        pub fn label(self) -> &'static str {
            match self {
                Self::Disabled => "DISABLED",
                Self::Disconnected => "OFFLINE",
                Self::Connecting => "CONNECTING",
                Self::Connected => "CONNECTED",
                Self::Error => "ERROR",
            }
        }
    }

    /// Safe text only. Sender is never an authenticated user identity.
    #[derive(Clone, PartialEq, Eq)]
    pub struct Preview {
        pub sender: String,
        pub text: String,
        pub kind: ChatKind,
    }

    impl std::fmt::Debug for Preview {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Preview { content: <redacted> }")
        }
    }

    fn clipped(value: &str, max: usize) -> String {
        value.chars().take(max).collect()
    }

    pub struct MicroGui {
        pub page: Page,
        pub link: LinkState,
        events: std::collections::VecDeque<Preview>,
        scroll: usize,
    }

    impl Default for MicroGui {
        fn default() -> Self {
            Self {
                page: Page::Chat,
                link: LinkState::Disabled,
                events: std::collections::VecDeque::new(),
                scroll: 0,
            }
        }
    }

    impl MicroGui {
        /// Only accepts data already parsed and sanitized through the adapter.
        pub fn append(&mut self, chat: &UntrustedChat<'_>) {
            let preview = Preview {
                sender: clipped(&chat.display_sender(), 12),
                text: chat.display_text_bounded(WIDTH),
                kind: chat.kind(),
            };
            if self.events.len() == MAX_EVENTS {
                self.events.pop_front();
            }
            self.events.push_back(preview);
            self.scroll = 0;
        }

        /// Navigation is local and never emits network commands.
        pub fn on_key(&mut self, key: Key) {
            match key {
                Key::Left => self.previous_page(),
                Key::Right => self.next_page(),
                Key::Up if self.page == Page::Chat => self.scroll_older(),
                Key::Down if self.page == Page::Chat => self.scroll_newer(),
                _ => {}
            }
        }

        pub fn next_page(&mut self) {
            self.page = match self.page {
                Page::Chat => Page::Channels,
                Page::Channels => Page::Status,
                Page::Status => Page::Chat,
            };
        }

        pub fn previous_page(&mut self) {
            self.page = match self.page {
                Page::Chat => Page::Status,
                Page::Channels => Page::Chat,
                Page::Status => Page::Channels,
            };
        }

        pub fn scroll_older(&mut self) {
            self.scroll = (self.scroll + 1).min(self.events.len().saturating_sub(MESSAGE_ROWS));
        }

        pub fn scroll_newer(&mut self) {
            self.scroll = self.scroll.saturating_sub(1);
        }

        pub fn visible(&self) -> Vec<&Preview> {
            let end = self.events.len().saturating_sub(self.scroll);
            let start = end.saturating_sub(MESSAGE_ROWS);
            self.events.iter().skip(start).take(end - start).collect()
        }

        /// Fully bounded plain-text viewport; host must render as text, never HTML.
        /// No fabricated channel list, delivery receipt, or operator identity.
        pub fn rows(&self) -> Vec<String> {
            let mut lines = vec![format!("IRC / LINK | {}", self.link.label())];
            let page_name = match self.page {
                Page::Chat => "CHAT",
                Page::Channels => "CHANNELS",
                Page::Status => "STATUS",
            };
            lines.push(format!("< {} >", page_name));
            match self.page {
                Page::Chat => {
                    for msg in self.visible() {
                        let prefix = if msg.kind == ChatKind::Notice {
                            "!"
                        } else {
                            ">"
                        };
                        lines.push(clipped(
                            &format!("{}{}: {}", prefix, msg.sender, msg.text),
                            WIDTH,
                        ));
                    }
                    if self.events.is_empty() {
                        lines.push("No local preview messages".into());
                    }
                }
                Page::Channels => {
                    lines.push("No verified channel state".into());
                }
                Page::Status => {
                    lines.push("Unverified IRC identities".into());
                    lines.push("Read-only preview".into());
                    lines.push("No command authorization".into());
                }
            }
            lines.push("PREV  NEXT  UP  DOWN".into());
            lines
                .into_iter()
                .map(|line| clipped(&line, WIDTH))
                .collect()
        }
    }
}

#[cfg(test)]
mod micro_gui_tests {
    use super::micro_gui::*;
    use super::*;

    #[test]
    fn disabled_empty_view_is_read_only() {
        let view = MicroGui::default();
        assert_eq!(view.link, LinkState::Disabled);
        assert!(view.rows().iter().any(|x| x.contains("DISABLED")));
        assert_eq!(view.visible().len(), 0);
    }

    #[test]
    fn navigation_and_bounded_preview() {
        let adapter = ChatPreviewAdapter { enabled: true };
        let chat = adapter
            .inspect_frame(":scout PRIVMSG #ops :Hello micro screen\r\n")
            .unwrap()
            .unwrap();
        let mut view = MicroGui::default();
        view.append(&chat);
        assert_eq!(view.visible()[0].sender, "scout");
        assert!(view.rows().iter().all(|line| line.chars().count() <= WIDTH));
        view.on_key(Key::Right);
        assert_eq!(view.page, Page::Channels);
        view.on_key(Key::Left);
        assert_eq!(view.page, Page::Chat);
        assert!(!format!("{:?}", view.visible()[0]).contains("Hello"));
    }

    #[test]
    fn touch_regions_are_bounded_and_scaled() {
        let layout = Layout::reference();
        assert_eq!(layout.hit_test(0, 196), Some(Key::Left));
        assert_eq!(layout.hit_test(80, 239), Some(Key::Right));
        assert_eq!(layout.hit_test(160, 200), Some(Key::Up));
        assert_eq!(layout.hit_test(319, 239), Some(Key::Down));
        assert_eq!(layout.hit_test(319, 240), None);
        assert_eq!(layout.hit_test_scaled(0, 392, 640, 480), Some(Key::Left));
        assert_eq!(layout.hit_test_scaled(639, 479, 640, 480), Some(Key::Down));
        assert_eq!(layout.hit_test_scaled(0, 0, 0, 480), None);
        assert_eq!(layout.hit_test_scaled(640, 0, 640, 480), None);
    }

    #[test]
    fn text_origins_stay_inside_content_region() {
        let layout = Layout::reference();
        for row in 0..7 {
            let (x, y) = layout.text_origin(row).unwrap();
            assert!(layout.content.contains(x, y));
        }
        assert_eq!(layout.text_origin(7), None);
    }

    #[test]
    fn directional_input_remains_inert_for_network() {
        let mut view = MicroGui::default();
        view.on_key(Key::Left);
        assert_eq!(view.page, Page::Status);
        view.on_key(Key::Right);
        assert_eq!(view.page, Page::Chat);
        view.on_key(Key::Up);
        view.on_key(Key::Down);
        assert!(view.visible().is_empty());
        assert_eq!(view.link, LinkState::Disabled);
    }

    #[test]
    fn message_history_is_capped() {
        let adapter = ChatPreviewAdapter { enabled: true };
        let chat = adapter
            .inspect_frame(":scout NOTICE #ops :fixture\r\n")
            .unwrap()
            .unwrap();
        let mut view = MicroGui::default();
        for _ in 0..(MAX_EVENTS + 3) {
            view.append(&chat);
        }
        assert_eq!(view.visible().len(), MESSAGE_ROWS);
        for _ in 0..100 {
            view.scroll_older();
        }
        assert_eq!(view.visible().len(), MESSAGE_ROWS);
        assert_eq!(view.visible()[0].kind, ChatKind::Notice);
    }
}

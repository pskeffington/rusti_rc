//! G3a: bounded, RAM-only operator chat drafts for explicit IRC submission.
//!
//! Nothing here connects, sends, logs message content, persists messages,
//! schedules retries, or authenticates Rust Boy peers. A drafted message
//! leaves this queue only after an explicit operator decision. Once removed,
//! the queue never re-inserts it, even if transport submission fails.
//! Successful TLS writes remain submitted/unconfirmed, never delivered.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;

use rusti_proto::{encode_privmsg, FrameError};

const HARD_MAX_MESSAGES: usize = 64;
const HARD_MAX_WIRE_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxLimits {
    pub max_messages: usize,
    /// Total encoded IRC wire bytes held in RAM; counts UTF-8 bytes.
    pub max_wire_bytes: usize,
}

impl Default for OutboxLimits {
    fn default() -> Self {
        Self {
            max_messages: 16,
            max_wire_bytes: 8 * 1024,
        }
    }
}

impl OutboxLimits {
    pub fn validate(self) -> bool {
        (1..=HARD_MAX_MESSAGES).contains(&self.max_messages)
            && (512..=HARD_MAX_WIRE_BYTES).contains(&self.max_wire_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxError {
    InvalidLimits,
    InvalidMessage(FrameError),
    QueueFull,
    ByteBudgetExceeded,
    IdentifierExhausted,
    NotConnected,
    OperatorConfirmationRequired,
}

/// A process-local identifier, not a server message ID or delivery receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DraftId(u64);

impl DraftId {
    pub fn value(self) -> u64 {
        self.0
    }
}

/// A single-use, operator-approved send candidate.
/// It is not Clone so it cannot accidentally be retransmitted by cloning
/// this handle; the caller must never automatically retry after an I/O error.
#[must_use = "A prepared send must be explicitly submitted or discarded"]
pub struct PreparedSend {
    id: DraftId,
    target: String,
    text: String,
    wire_bytes: usize,
}

impl fmt::Debug for PreparedSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedSend")
            .field("id", &self.id)
            .field("content", &"<redacted>")
            .finish()
    }
}

impl PreparedSend {
    pub fn id(&self) -> DraftId {
        self.id
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Pure in-memory FIFO. All messages are local unsubmitted drafts until
/// take_for_operator_send removes one. No disk, timer, socket, or worker.
pub struct OperatorOutbox {
    limits: OutboxLimits,
    drafts: VecDeque<PreparedSend>,
    queued_wire_bytes: usize,
    next_id: u64,
}

impl fmt::Debug for OperatorOutbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorOutbox")
            .field("queued", &self.drafts.len())
            .field("queued_wire_bytes", &self.queued_wire_bytes)
            .finish()
    }
}

impl OperatorOutbox {
    pub fn new(limits: OutboxLimits) -> Result<Self, OutboxError> {
        if !limits.validate() {
            return Err(OutboxError::InvalidLimits);
        }
        Ok(Self {
            limits,
            drafts: VecDeque::new(),
            queued_wire_bytes: 0,
            next_id: 0,
        })
    }

    pub fn len(&self) -> usize {
        self.drafts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.drafts.is_empty()
    }

    pub fn queued_wire_bytes(&self) -> usize {
        self.queued_wire_bytes
    }

    /// Stage one locally authored draft. Validation matches the actual IRC
    /// PRIVMSG encoder, including the 512-byte line limit and CRLF controls.
    /// This method never submits the message and does not imply approval.
    pub fn queue_draft(&mut self, target: &str, text: &str) -> Result<DraftId, OutboxError> {
        let wire_bytes = encode_privmsg(target, text)
            .map_err(OutboxError::InvalidMessage)?
            .len();
        if self.drafts.len() >= self.limits.max_messages {
            return Err(OutboxError::QueueFull);
        }
        if wire_bytes > self.limits.max_wire_bytes - self.queued_wire_bytes {
            return Err(OutboxError::ByteBudgetExceeded);
        }
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or(OutboxError::IdentifierExhausted)?;
        let id = DraftId(next_id);
        self.drafts.push_back(PreparedSend {
            id,
            target: target.to_owned(),
            text: text.to_owned(),
            wire_bytes,
        });
        self.queued_wire_bytes += wire_bytes;
        self.next_id = next_id;
        Ok(id)
    }

    /// Release exactly one oldest draft for a separately approved operator
    /// send, only if the caller has a registered transport. The booleans are
    /// integration assertions, NOT cryptographic authorizations: the UI must
    /// obtain a fresh user confirmation and check actual session state.
    /// Removing the item is terminal: even on partial/failed write it is not
    /// requeued, because receiver acceptance is unknown.
    pub fn take_for_operator_send(
        &mut self,
        transport_registered: bool,
        operator_confirmed: bool,
    ) -> Result<Option<PreparedSend>, OutboxError> {
        if self.drafts.is_empty() {
            return Ok(None);
        }
        if !transport_registered {
            return Err(OutboxError::NotConnected);
        }
        if !operator_confirmed {
            return Err(OutboxError::OperatorConfirmationRequired);
        }
        let candidate = self.drafts.pop_front().expect("checked nonempty");
        self.queued_wire_bytes -= candidate.wire_bytes;
        Ok(Some(candidate))
    }

    /// Disconnect/cancel clears unsubmitted drafts. Callers must also drop
    /// any already-removed PreparedSend: the queue cannot revoke those.
    /// No replay is scheduled when a new network session comes online.
    pub fn discard_on_disconnect(&mut self) -> usize {
        let discarded = self.drafts.len();
        self.drafts.clear();
        self.queued_wire_bytes = 0;
        discarded
    }
}

impl Default for OperatorOutbox {
    fn default() -> Self {
        Self::new(OutboxLimits::default()).expect("default outbox limits are valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_has_no_staged_messages_and_limits_are_bounded() {
        let box_ = OperatorOutbox::default();
        assert!(box_.is_empty());
        assert_eq!(box_.queued_wire_bytes(), 0);
        assert!(OutboxLimits::default().validate());
        assert!(!OutboxLimits { max_messages: 0, max_wire_bytes: 512 }.validate());
        assert!(!OutboxLimits { max_messages: 65, max_wire_bytes: 512 }.validate());
        assert!(!OutboxLimits { max_messages: 1, max_wire_bytes: 32769 }.validate());
        assert!(matches!(
            OperatorOutbox::new(OutboxLimits { max_messages: 0, max_wire_bytes: 512 }),
            Err(OutboxError::InvalidLimits)
        ));
    }

    #[test]
    fn rejects_unsafe_drafts_without_changing_queue_or_id() {
        let mut box_ = OperatorOutbox::default();
        assert_eq!(
            box_.queue_draft("#ops", "hi\r\nOPER root"),
            Err(OutboxError::InvalidMessage(FrameError::ForbiddenControl))
        );
        assert_eq!(
            box_.queue_draft("#bad channel", "hello"),
            Err(OutboxError::InvalidMessage(FrameError::InvalidTarget))
        );
        assert_eq!(
            box_.queue_draft("#ops", &"x".repeat(600)),
            Err(OutboxError::InvalidMessage(FrameError::OverlongLine))
        );
        assert_eq!(box_.len(), 0);
        assert_eq!(box_.queue_draft("#ops", "okay"), Ok(DraftId(1)));
    }

    #[test]
    fn enforces_message_and_total_byte_caps() {
        let mut count_box = OperatorOutbox::new(OutboxLimits {
            max_messages: 1,
            max_wire_bytes: 4096,
        }).unwrap();
        count_box.queue_draft("#ops", "first").unwrap();
        assert_eq!(count_box.queue_draft("#ops", "second"), Err(OutboxError::QueueFull));

        let mut byte_box = OperatorOutbox::new(OutboxLimits {
            max_messages: 4,
            max_wire_bytes: 512,
        }).unwrap();
        let id = byte_box.queue_draft("#ops", &"a".repeat(280)).unwrap();
        assert_eq!(id, DraftId(1));
        assert_eq!(
            byte_box.queue_draft("#ops", &"b".repeat(280)),
            Err(OutboxError::ByteBudgetExceeded)
        );
        assert_eq!(byte_box.len(), 1);
    }

    #[test]
    fn explicit_confirmation_and_registration_are_required() {
        let mut box_ = OperatorOutbox::default();
        box_.queue_draft("#ops", "message").unwrap();
        assert!(matches!(
            box_.take_for_operator_send(false, true),
            Err(OutboxError::NotConnected)
        ));
        assert!(matches!(
            box_.take_for_operator_send(true, false),
            Err(OutboxError::OperatorConfirmationRequired)
        ));
        assert_eq!(box_.len(), 1);
        let prepared = box_.take_for_operator_send(true, true).unwrap().unwrap();
        assert_eq!(prepared.id(), DraftId(1));
        assert_eq!(prepared.target(), "#ops");
        assert_eq!(prepared.text(), "message");
        assert!(box_.take_for_operator_send(true, true).unwrap().is_none());
        assert_eq!(box_.queued_wire_bytes(), 0);
    }

    #[test]
    fn FIFO_bytes_and_debug_are_redacted() {
        let mut box_ = OperatorOutbox::default();
        let first = box_.queue_draft("#ops", "sensitive first").unwrap();
        let second = box_.queue_draft("#ops", "sensitive second").unwrap();
        assert_eq!(second.value(), first.value() + 1);
        assert_eq!(
            box_.queued_wire_bytes(),
            encode_privmsg("#ops", "sensitive first").unwrap().len()
                + encode_privmsg("#ops", "sensitive second").unwrap().len()
        );
        assert!(!format!("{box_:?}").contains("sensitive"));
        let prepared = box_.take_for_operator_send(true, true).unwrap().unwrap();
        assert_eq!(prepared.id(), first);
        assert!(!format!("{prepared:?}").contains("sensitive"));
        let next = box_.take_for_operator_send(true, true).unwrap().unwrap();
        assert_eq!(next.id(), second);
    }

    #[test]
    fn disconnect_discards_backlog_without_replay() {
        let mut box_ = OperatorOutbox::default();
        box_.queue_draft("#ops", "stale 1").unwrap();
        box_.queue_draft("#ops", "stale 2").unwrap();
        assert_eq!(box_.discard_on_disconnect(), 2);
        assert_eq!(box_.discard_on_disconnect(), 0);
        assert!(box_.take_for_operator_send(true, true).unwrap().is_none());
        assert!(box_.is_empty());
        assert_eq!(box_.queued_wire_bytes(), 0);
        assert_eq!(box_.queue_draft("#ops", "fresh").unwrap(), DraftId(3));
    }
}

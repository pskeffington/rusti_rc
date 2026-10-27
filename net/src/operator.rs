//! G3b: explicit operator draft submission over an already verified TLS IRC
//! session. IRC provides no recipient receipt: successful writes are always
//! submitted/unconfirmed, and failed writes have an unknown outcome.
//!
//! This integration has no background worker, retries, persistence, new
//! sockets, IRC command forwarding, or Rust Boy organizational authority.
#![forbid(unsafe_code)]

use rusti_client::outbox::{DraftId, OperatorOutbox, OutboxError};
use rusti_proto::{FrameError, ParsedMessage};

use crate::{Receive, Submission, TlsIrcSession, TransportError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorSendOutcome {
    QueueEmpty,
    /// Locally written to the authenticated TLS session, not delivered.
    SubmittedUnconfirmed {
        draft_id: DraftId,
    },
}

#[derive(Debug)]
pub enum OperatorSendError {
    /// No registered IRC session. Any unsent drafts have been discarded.
    Disconnected,
    /// No message was consumed; for example, confirmation is still required.
    Outbox(OutboxError),
    /// The draft was consumed. The remote side may have received some or all
    /// bytes. No automatic retry is permitted; unsent backlog is discarded.
    OutcomeUnknown {
        draft_id: DraftId,
        source: TransportError,
    },
}

impl OperatorSendError {
    /// Local-only handle for UI status; never a recipient receipt.
    pub fn affected_draft(&self) -> Option<DraftId> {
        match self {
            Self::OutcomeUnknown { draft_id, .. } => Some(*draft_id),
            _ => None,
        }
    }
}

/// Private deterministic send boundary permits failure simulation without
/// creating a fake plaintext transport or relaxing certificate validation.
fn submit_once<F>(
    outbox: &mut OperatorOutbox,
    registered: bool,
    operator_confirmed: bool,
    submit: F,
) -> Result<OperatorSendOutcome, OperatorSendError>
where
    F: FnOnce(&str, &str) -> Result<Submission, TransportError>,
{
    if !registered {
        outbox.discard_on_disconnect();
        return Err(OperatorSendError::Disconnected);
    }
    let draft = outbox
        .take_for_operator_send(true, operator_confirmed)
        .map_err(OperatorSendError::Outbox)?;
    let Some(draft) = draft else {
        return Ok(OperatorSendOutcome::QueueEmpty);
    };
    let id = draft.id();
    match submit(draft.target(), draft.text()) {
        Ok(Submission::SubmittedUnconfirmed) => {
            Ok(OperatorSendOutcome::SubmittedUnconfirmed { draft_id: id })
        }
        Err(source) => {
            // A partial transport write is ambiguous, not a safe retry.
            // No queued draft may carry forward into a new TLS session.
            outbox.discard_on_disconnect();
            Err(OperatorSendError::OutcomeUnknown {
                draft_id: id,
                source,
            })
        }
    }
}

impl TlsIrcSession {
    /// Explicitly submit at most one oldest draft. This reads the session's
    /// actual registered state, not a caller-controlled connection flag.
    ///
    /// The caller must obtain fresh operator approval for this one action;
    /// passing true from a background loop would violate the API contract.
    /// It blocks while the TLS socket writes: call on an operator-controlled
    /// worker, never in the Rust Boy rendering path. A successful return is
    /// only SUBMITTED / UNCONFIRMED. On any write failure, the socket is
    /// closed, the attempted draft becomes OUTCOME UNKNOWN and remaining
    /// unsent drafts are discarded. Nothing is replayed automatically.
    pub fn operator_submit_next(
        &mut self,
        outbox: &mut OperatorOutbox,
        operator_confirmed: bool,
    ) -> Result<OperatorSendOutcome, OperatorSendError> {
        let registered = self.registered;
        let outcome = submit_once(outbox, registered, operator_confirmed, |target, body| {
            self.send_privmsg(target, body)
        });
        if matches!(
            &outcome,
            Err(OperatorSendError::Disconnected | OperatorSendError::OutcomeUnknown { .. })
        ) {
            self.abort_registration_connection();
        }
        outcome
    }

    /// Receive through the existing bounded IRC decoder; discard drafts and
    /// close the socket on EOF, protocol error, capability revocation or
    /// transport failure. Timed-out reads are not disconnections.
    pub fn operator_read_once<F>(
        &mut self,
        outbox: &mut OperatorOutbox,
        on_frame: F,
    ) -> Result<Receive, TransportError>
    where
        F: for<'a> FnMut(Result<ParsedMessage<'a>, FrameError>),
    {
        let result = self.read_once(on_frame);
        if matches!(&result, Ok(Receive::Closed) | Err(_)) {
            self.abort_registration_connection();
            outbox.discard_on_disconnect();
        }
        result
    }

    /// Operator-initiated disconnect. Drops any draft not yet consumed.
    /// A message already submitted cannot be withdrawn or acknowledged.
    pub fn operator_disconnect(&mut self, outbox: &mut OperatorOutbox) -> usize {
        self.abort_registration_connection();
        outbox.discard_on_disconnect()
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn disconnect_discards_without_invoking_sender() {
        let mut outbox = OperatorOutbox::default();
        outbox.queue_draft("#lab", "offline").unwrap();
        let result = submit_once(&mut outbox, false, true, |_, _| {
            panic!("disconnected draft must not reach sender");
        });
        assert!(matches!(result, Err(OperatorSendError::Disconnected)));
        assert!(outbox.is_empty());
    }

    #[test]
    fn refusal_of_unconfirmed_send_preserves_draft() {
        let mut outbox = OperatorOutbox::default();
        let id = outbox.queue_draft("#lab", "pending").unwrap();
        let result = submit_once(&mut outbox, true, false, |_, _| {
            panic!("unconfirmed draft must not reach sender");
        });
        assert!(matches!(
            result,
            Err(OperatorSendError::Outbox(
                OutboxError::OperatorConfirmationRequired
            ))
        ));
        assert_eq!(outbox.len(), 1);
        let submitted = submit_once(&mut outbox, true, true, |target, body| {
            assert_eq!((target, body), ("#lab", "pending"));
            Ok(Submission::SubmittedUnconfirmed)
        })
        .unwrap();
        assert_eq!(
            submitted,
            OperatorSendOutcome::SubmittedUnconfirmed { draft_id: id }
        );
        assert!(outbox.is_empty());
    }

    #[test]
    fn failed_write_has_unknown_outcome_and_clears_remaining_backlog() {
        let mut outbox = OperatorOutbox::default();
        let first = outbox.queue_draft("#lab", "one").unwrap();
        outbox.queue_draft("#lab", "two").unwrap();
        let mut writes = 0;
        let error = submit_once(&mut outbox, true, true, |_, _| {
            writes += 1;
            Err(TransportError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic failure",
            )))
        })
        .unwrap_err();
        assert!(matches!(
            error,
            OperatorSendError::OutcomeUnknown {
                draft_id,
                source: TransportError::Io(_)
            } if draft_id == first
        ));
        assert_eq!(writes, 1);
        assert!(outbox.is_empty(), "no retry or stale queued replay");
        assert_eq!(outbox.queued_wire_bytes(), 0);
        let new_id = outbox.queue_draft("#lab", "new session draft").unwrap();
        assert!(new_id.value() > first.value());
    }

    #[test]
    fn empty_queue_never_invokes_writer() {
        let mut outbox = OperatorOutbox::default();
        let status = submit_once(&mut outbox, true, true, |_, _| {
            panic!("empty queue must not invoke sender");
        })
        .unwrap();
        assert_eq!(status, OperatorSendOutcome::QueueEmpty);
    }
}

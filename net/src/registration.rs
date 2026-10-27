//! Explicit anonymous IRC CAP registration over a verified TLS stream.
//!
//! Authenticated SASL PLAIN registration is a separate opt-in path in sasl.rs.
//! No background connection, secret lookup, timer task, or automatic retry.
//! A server welcome is never Rust Boy organizational authorization.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use rusti_proto::registration::{RegistrationFlow, RegistrationState};

use crate::cancel::RegistrationCancellation;
use crate::{Receive, TlsIrcSession, TransportError};

const MAX_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PROPOSED_COMMANDS_PER_READ: usize = 16;

impl TlsIrcSession {
    /// Perform IRCv3 CAP registration with a known TLS-authenticated server.
    /// The server name and root certificate must have already been verified
    /// by connect_tls. This method intentionally registers without SASL;
    /// authenticated accounts use the separate register_sasl_plain method.
    ///
    /// This operation blocks only when the caller explicitly invokes it.
    /// Call from a worker context, not a handheld/desktop UI render thread.
    /// Caller must discard the session on any error; re-registration on the
    /// same TLS connection is deliberately rejected.
    pub fn register_with_capabilities(
        &mut self,
        nickname: &str,
        username: &str,
        required: &[&str],
        optional: &[&str],
        timeout: Duration,
    ) -> Result<(), TransportError> {
        self.register_with_capabilities_cancellable(
            nickname, username, required, optional, timeout,
            &RegistrationCancellation::new(),
        )
    }

    /// Operator-invoked registration with a shared cancellation token.
    /// A timeout or cancellation closes the TLS socket; never silently
    /// resume negotiation or reuse the stream for anonymous chat.
    pub fn register_with_capabilities_cancellable(
        &mut self,
        nickname: &str,
        username: &str,
        required: &[&str],
        optional: &[&str],
        timeout: Duration,
        cancel: &RegistrationCancellation,
    ) -> Result<(), TransportError> {
        self.run_registration_once(|session| {
            session.register_with_capabilities_inner(
                nickname, username, required, optional, timeout, cancel,
            )
        })
    }

    fn register_with_capabilities_inner(
        &mut self,
        nickname: &str,
        username: &str,
        required: &[&str],
        optional: &[&str],
        timeout: Duration,
        cancel: &RegistrationCancellation,
    ) -> Result<(), TransportError> {
        if timeout < Duration::from_millis(50) || timeout > MAX_REGISTRATION_TIMEOUT {
            return Err(TransportError::InvalidTimeouts);
        }
        let mut flow = RegistrationFlow::new(nickname, username, required, optional)?;
        let initial = flow.start()?;
        let deadline = Instant::now() + timeout;

        for command in &initial {
            self.registration_step(deadline, cancel)?;
            self.write_frame(command)?;
        }

        while flow.state() != RegistrationState::Registered {
            self.registration_step(deadline, cancel)?;
            let mut actions: Vec<String> = Vec::new();
            let mut problem: Option<TransportError> = None;
            let result = self.read_once(|message| {
                if problem.is_some() {
                    return;
                }
                match message {
                    Err(error) => problem = Some(TransportError::Frame(error)),
                    Ok(frame) => match flow.observe(&frame) {
                        Ok(Some(proposal)) => {
                            if actions.len() >= MAX_PROPOSED_COMMANDS_PER_READ {
                                problem = Some(TransportError::RegistrationResponseOverflow);
                            } else {
                                actions.push(proposal);
                            }
                        }
                        Ok(None) => {}
                        Err(error) => problem = Some(TransportError::Registration(error)),
                    },
                }
            });
            if let Some(error) = problem {
                flow.abort();
                return Err(error);
            }
            match result? {
                Receive::Closed => {
                    flow.abort();
                    return Err(TransportError::UnexpectedClose);
                }
                Receive::Data(_) | Receive::TimedOut => {}
            }
            // Prevent a late/partial frame from extending the operator's
            // overall deadline or overriding a requested cancellation.
            self.registration_step(deadline, cancel)?;

            for action in &actions {
                self.registration_step(deadline, cancel)?;
                self.write_frame(action)?;
                if action == "CAP END\r\n" {
                    flow.cap_end_written()?;
                }
            }
        }
        self.registration_step(deadline, cancel)?;
        // Retain capabilities so a later server CAP DEL can revoke
        // authorization for further channel submissions.
        self.registration = Some(flow);
        self.registered = true;
        Ok(())
    }

    pub fn is_registered(&self) -> bool {
        self.registered
    }
}

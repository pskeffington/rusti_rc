//! Explicit IRC registration over an already authenticated TLS stream.
//!
//! No background connection, silent credentials, timer task, or auto retry.
//! A welcome numeric is a server protocol event, NOT Rust Boy authorization.
#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use rusti_proto::registration::{RegistrationFlow, RegistrationState};

use crate::{Receive, TlsIrcSession, TransportError};

const MAX_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PROPOSED_COMMANDS_PER_READ: usize = 16;

impl TlsIrcSession {
    /// Perform IRCv3 CAP registration with a known TLS-authenticated server.
    /// The server name and root certificate must have already been verified
    /// by connect_tls. Client credentials/SASL are not implemented.
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
        if self.registered || self.registration_attempted {
            return Err(TransportError::RegistrationAlreadyAttempted);
        }
        if timeout < Duration::from_millis(50) || timeout > MAX_REGISTRATION_TIMEOUT {
            return Err(TransportError::InvalidTimeouts);
        }

        let mut flow = RegistrationFlow::new(nickname, username, required, optional)?;
        let initial = flow.start()?;
        self.registration_attempted = true;
        let deadline = Instant::now() + timeout;

        for command in &initial {
            if let Err(error) = self.write_frame(command) {
                flow.abort();
                return Err(error);
            }
        }

        while flow.state() != RegistrationState::Registered {
            if Instant::now() >= deadline {
                flow.abort();
                return Err(TransportError::RegistrationTimedOut);
            }

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
            let status = match result {
                Ok(status) => status,
                Err(error) => {
                    flow.abort();
                    return Err(error);
                }
            };
            if matches!(status, Receive::Closed) {
                flow.abort();
                return Err(TransportError::UnexpectedClose);
            }

            for action in &actions {
                if let Err(error) = self.write_frame(action) {
                    flow.abort();
                    return Err(error);
                }
                if action == "CAP END\r\n" {
                    flow.cap_end_written()?;
                }
            }
        }

        // Preserve negotiated required capabilities so a later CAP DEL can
        // revoke the session instead of silently retaining a false trust state.
        self.registration = Some(flow);
        self.registered = true;
        Ok(())
    }

    pub fn is_registered(&self) -> bool {
        self.registered
    }
}

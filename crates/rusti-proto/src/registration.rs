//! Pure-data IRC registration state machine, suitable for legacy Rust 1.70.
//!
//! This is protocol coordination, not an authenticated device identity.
//! Neither a server numeric nor IRC CAP/SASL accounts authorize Rust Boy tasks.
//! No sockets, DNS, credentials, threads or background work are started here.
#![forbid(unsafe_code)]

use crate::cap::{CapError, CapNegotiator, CapState};
use crate::ParsedMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    Idle,
    Negotiating,
    /// A CAP END proposal must actually be written before numeric 001 counts.
    AwaitingCapEndWrite,
    AwaitingWelcome,
    Registered,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationError {
    InvalidIdentifier,
    InvalidState,
    Capability(CapError),
    UnsupportedRequiredCapability,
    UnexpectedWelcome,
    RejectedByServer,
    InvalidPing,
}

#[derive(Debug, Clone)]
pub struct RegistrationFlow {
    nickname: String,
    username: String,
    required_count: usize,
    caps: CapNegotiator,
    state: RegistrationState,
}

/// Conservative, portable ASCII identifiers; not full IRC nickname syntax.
/// A larger allowed character set needs a separate interoperability review.
fn valid_atom(s: &str) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else { return false };
    s.len() <= 24
        && first.is_ascii_alphabetic()
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl RegistrationFlow {
    pub fn new(
        nickname: &str,
        username: &str,
        required_caps: &[&str],
        optional_caps: &[&str],
    ) -> Result<Self, RegistrationError> {
        if !valid_atom(nickname) || !valid_atom(username) {
            return Err(RegistrationError::InvalidIdentifier);
        }
        let caps = CapNegotiator::new(required_caps, optional_caps)
            .map_err(RegistrationError::Capability)?;
        Ok(Self {
            nickname: nickname.to_owned(),
            username: username.to_owned(),
            required_count: required_caps.len(),
            caps,
            state: RegistrationState::Idle,
        })
    }

    pub fn state(&self) -> RegistrationState {
        self.state
    }

    pub fn is_registered(&self) -> bool {
        self.state == RegistrationState::Registered
    }

    pub fn capabilities(&self) -> &[String] {
        self.caps.enabled()
    }

    pub fn start(&mut self) -> Result<[String; 3], RegistrationError> {
        if self.state != RegistrationState::Idle {
            return Err(RegistrationError::InvalidState);
        }
        let cap_ls = self.caps.begin().map_err(RegistrationError::Capability)?;
        self.state = RegistrationState::Negotiating;
        // IRCv3 CAP negotiation is initiated with NICK/USER in the same
        // registration phase; the server suspends welcome until CAP END.
        Ok([
            cap_ls.to_owned(),
            format!("NICK {}\r\n", self.nickname),
            format!("USER {} 0 * :rusti_rc\r\n", self.username),
        ])
    }

    /// Interpret one syntactically valid, **untrusted** server frame. The
    /// returned string is a bounded, allowlisted response proposal.
    /// On failure the entire registration must be abandoned and socket closed.
    pub fn observe(
        &mut self,
        frame: &ParsedMessage<'_>,
    ) -> Result<Option<String>, RegistrationError> {
        if matches!(self.state, RegistrationState::Idle | RegistrationState::Failed) {
            return Err(RegistrationError::InvalidState);
        }
        if frame.command.eq_ignore_ascii_case("PING") {
            let params = frame.params();
            if params.len() != 1 || params[0].is_empty() || params[0].len() > 256
                || !params[0].bytes().all(|b| (0x20..=0x7e).contains(&b))
            {
                self.state = RegistrationState::Failed;
                return Err(RegistrationError::InvalidPing);
            }
            return Ok(Some(format!("PONG :{}\r\n", params[0])));
        }

        if frame.command.eq_ignore_ascii_case("ERROR")
            || matches!(
                frame.command,
                "431" | "432" | "433" | "436" | "451" | "462" | "463" | "464" | "465"
                    | "466" | "410"
            )
        {
            self.state = RegistrationState::Failed;
            return Err(RegistrationError::RejectedByServer);
        }

        // Numeric 421 is a legacy server's CAP unknown-command response.
        if frame.command == "421" && frame.params().iter().any(|p| *p == "CAP") {
            if self.state != RegistrationState::Negotiating
                || self.caps.state() != CapState::Listing
            {
                self.state = RegistrationState::Failed;
                return Err(RegistrationError::InvalidState);
            }
            if self.required_count != 0 {
                self.state = RegistrationState::Failed;
                return Err(RegistrationError::UnsupportedRequiredCapability);
            }
            // Legacy fallback is allowed only when explicitly no capability
            // is mandatory; ordinary TLS transport validation still applies.
            self.state = RegistrationState::AwaitingWelcome;
            return Ok(None);
        }

        if frame.command.eq_ignore_ascii_case("CAP") {
            if !matches!(
                self.state,
                RegistrationState::Negotiating
                    | RegistrationState::AwaitingWelcome
                    | RegistrationState::Registered
            ) {
                self.state = RegistrationState::Failed;
                return Err(RegistrationError::InvalidState);
            }
            let proposal = match self.caps.observe(frame) {
                Ok(value) => value,
                Err(error) => {
                    self.state = RegistrationState::Failed;
                    return Err(RegistrationError::Capability(error));
                }
            };
            if proposal.as_deref() == Some("CAP END\r\n") {
                self.state = RegistrationState::AwaitingCapEndWrite;
            }
            return Ok(proposal);
        }

        if frame.command == "001" {
            if self.state == RegistrationState::AwaitingWelcome {
                self.state = RegistrationState::Registered;
                return Ok(None);
            }
            // RFC compatibility: non-CAP servers may welcome immediately.
            if self.state == RegistrationState::Negotiating
                && self.caps.state() == CapState::Listing
                && self.required_count == 0
            {
                self.state = RegistrationState::Registered;
                return Ok(None);
            }
            self.state = RegistrationState::Failed;
            return Err(RegistrationError::UnexpectedWelcome);
        }

        Ok(None)
    }

    /// Must be called only after the transport confirms that CAP END was
    /// successfully written. Prevents premature 001 acceptance.
    pub fn cap_end_written(&mut self) -> Result<(), RegistrationError> {
        if self.state != RegistrationState::AwaitingCapEndWrite {
            return Err(RegistrationError::InvalidState);
        }
        self.state = RegistrationState::AwaitingWelcome;
        Ok(())
    }

    /// A failed transport, timeout, invalid protocol frame or inability to
    /// send a mandatory control frame always invalidates the registration.
    pub fn abort(&mut self) {
        self.state = RegistrationState::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_frame;

    fn feed(flow: &mut RegistrationFlow, wire: &str) -> Result<Option<String>, RegistrationError> {
        let msg = parse_frame(wire).unwrap();
        flow.observe(&msg)
    }

    #[test]
    fn negotiates_before_accepting_welcome() {
        let mut flow = RegistrationFlow::new(
            "Scout_1", "scout", &["message-tags"], &["server-time"],
        ).unwrap();
        assert_eq!(
            flow.start().unwrap(),
            [
                "CAP LS 302\r\n".to_owned(),
                "NICK Scout_1\r\n".to_owned(),
                "USER scout 0 * :rusti_rc\r\n".to_owned(),
            ]
        );
        assert_eq!(
            feed(&mut flow, "CAP * LS :message-tags server-time\r\n"),
            Ok(Some("CAP REQ :message-tags server-time\r\n".into()))
        );
        assert_eq!(
            feed(&mut flow, "CAP Scout_1 ACK :server-time message-tags\r\n"),
            Ok(Some("CAP END\r\n".into()))
        );
        assert_eq!(flow.state(), RegistrationState::AwaitingCapEndWrite);
        assert_eq!(
            feed(&mut flow, ":irc 001 Scout_1 :welcome\r\n"),
            Err(RegistrationError::UnexpectedWelcome)
        );
    }

    #[test]
    fn happy_path_registers_only_after_cap_end_write() {
        let mut flow = RegistrationFlow::new(
            "Scout", "scout", &["message-tags"], &[],
        ).unwrap();
        flow.start().unwrap();
        feed(&mut flow, "CAP * LS :message-tags\r\n").unwrap();
        assert_eq!(
            feed(&mut flow, "CAP Scout ACK :message-tags\r\n"),
            Ok(Some("CAP END\r\n".into()))
        );
        flow.cap_end_written().unwrap();
        feed(&mut flow, ":irc 001 Scout :Welcome\r\n").unwrap();
        assert!(flow.is_registered());
        assert_eq!(flow.capabilities(), &["message-tags"]);
    }

    #[test]
    fn optional_only_legacy_server_works_without_cap() {
        let mut flow = RegistrationFlow::new(
            "Scout", "scout", &[], &["multi-prefix"],
        ).unwrap();
        flow.start().unwrap();
        feed(&mut flow, ":irc 421 Scout CAP :Unknown command\r\n").unwrap();
        assert_eq!(flow.state(), RegistrationState::AwaitingWelcome);
        feed(&mut flow, ":irc 001 Scout :welcome\r\n").unwrap();
        assert!(flow.is_registered());
        assert!(flow.capabilities().is_empty());
    }

    #[test]
    fn missing_mandatory_cap_does_not_downgrade() {
        let mut flow = RegistrationFlow::new(
            "Scout", "scout", &["message-tags"], &[],
        ).unwrap();
        flow.start().unwrap();
        assert_eq!(
            feed(&mut flow, ":irc 421 Scout CAP :Unknown command\r\n"),
            Err(RegistrationError::UnsupportedRequiredCapability)
        );
        assert_eq!(flow.state(), RegistrationState::Failed);
    }

    #[test]
    fn server_rejection_blocks_registration() {
        let mut flow = RegistrationFlow::new("Scout", "scout", &[], &[]).unwrap();
        flow.start().unwrap();
        assert_eq!(
            feed(&mut flow, ":irc 433 * Scout :Nickname taken\r\n"),
            Err(RegistrationError::RejectedByServer)
        );
        assert_eq!(flow.state(), RegistrationState::Failed);
    }

    #[test]
    fn ping_is_bounded_and_data_not_command_execution() {
        let mut flow = RegistrationFlow::new("Scout", "scout", &[], &[]).unwrap();
        flow.start().unwrap();
        assert_eq!(
            feed(&mut flow, "PING :abc 123\r\n"),
            Ok(Some("PONG :abc 123\r\n".into()))
        );
        assert_eq!(
            feed(&mut flow, &format!("PING :{}\r\n", "x".repeat(257))),
            Err(RegistrationError::InvalidPing)
        );
    }

    #[test]
    fn rejects_identifier_injection_before_network() {
        assert_eq!(
            RegistrationFlow::new("admin\r\nOPER", "user", &[], &[]).unwrap_err(),
            RegistrationError::InvalidIdentifier
        );
        assert_eq!(
            RegistrationFlow::new("Scout", "bad name", &[], &[]).unwrap_err(),
            RegistrationError::InvalidIdentifier
        );
    }

    #[test]
    fn required_cap_revocation_terminates_ready_session() {
        let mut flow = RegistrationFlow::new(
            "Scout", "scout", &["message-tags"], &[],
        ).unwrap();
        flow.start().unwrap();
        feed(&mut flow, "CAP * LS :message-tags\r\n").unwrap();
        feed(&mut flow, "CAP Scout ACK :message-tags\r\n").unwrap();
        flow.cap_end_written().unwrap();
        feed(&mut flow, ":irc 001 Scout :welcome\r\n").unwrap();
        assert_eq!(
            feed(&mut flow, ":irc CAP Scout DEL :message-tags\r\n"),
            Err(RegistrationError::Capability(CapError::RequiredCapabilityRemoved))
        );
        assert_eq!(flow.state(), RegistrationState::Failed);
    }
}

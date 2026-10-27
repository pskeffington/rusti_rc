//! Opt-in SASL PLAIN registration state machine for the Rust 1.70 core.
//!
//! **No secrets and no network I/O live here.** It only processes untrusted
//! IRC server messages, producing strictly allowlisted control-frame actions.
//! A separate, already verified TLS transport must perform credential lookup,
//! write the sensitive response, and acknowledge each required write barrier.
//! IRC account login does NOT grant Rust Boy organizational authorization.
#![forbid(unsafe_code)]

use crate::ParsedMessage;

const CAP_REQ_SASL: &str = "CAP REQ :sasl\r\n";
const AUTH_PLAIN: &str = "AUTHENTICATE PLAIN\r\n";
const CAP_END: &str = "CAP END\r\n";
const MAX_LS_FRAMES: u8 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslStage {
    Idle,
    Listing,
    AwaitingCapRequestWrite,
    AwaitingCapAck,
    AwaitingMechanismWrite,
    AwaitingChallenge,
    AwaitingPayloadWrite,
    AwaitingResult,
    AwaitingCapEndWrite,
    AwaitingWelcome,
    Registered,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslError {
    InvalidIdentity,
    UnexpectedFrame,
    InvalidServerTarget,
    MissingSaslPlain,
    ServerRejected,
    MalformedChallenge,
    TooManyCapabilityFrames,
    PrematureWelcome,
    CapabilityRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaslAction {
    None,
    Send(&'static str),
    Pong(String),
    /// Driver must fetch from the protected credential store *now*, over an
    /// authenticated TLS connection, and immediately zeroize temporary bytes.
    SupplySecret,
}

/// No credential material is stored here. Values are public IRC nick/username
/// labels only; private Rust Boy identity remains a separate trust boundary.
#[derive(Debug)]
pub struct SaslPlainFlow {
    nick: String,
    user: String,
    stage: SaslStage,
    ls_frames: u8,
    plain_offered: bool,
    authenticated: bool,
}

fn valid_atom(s: &str) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    s.len() <= 24
        && first.is_ascii_alphabetic()
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl SaslPlainFlow {
    pub fn new(nick: &str, user: &str) -> Result<Self, SaslError> {
        if !valid_atom(nick) || !valid_atom(user) {
            return Err(SaslError::InvalidIdentity);
        }
        Ok(Self {
            nick: nick.to_string(),
            user: user.to_string(),
            stage: SaslStage::Idle,
            ls_frames: 0,
            plain_offered: false,
            authenticated: false,
        })
    }

    pub fn stage(&self) -> SaslStage {
        self.stage
    }

    pub fn registered(&self) -> bool {
        self.stage == SaslStage::Registered && self.authenticated
    }

    pub fn begin(&mut self) -> Result<[String; 3], SaslError> {
        if self.stage != SaslStage::Idle {
            return Err(SaslError::UnexpectedFrame);
        }
        self.stage = SaslStage::Listing;
        Ok([
            "CAP LS 302\r\n".to_string(),
            format!("NICK {}\r\n", self.nick),
            format!("USER {} 0 * :rusti_rc\r\n", self.user),
        ])
    }

    fn target_matches(&self, frame: &ParsedMessage<'_>, allow_wildcard: bool) -> bool {
        match frame.params().first() {
            Some(&"*") => allow_wildcard,
            Some(nick) => nick.eq_ignore_ascii_case(&self.nick),
            None => false,
        }
    }

    fn fail<T>(&mut self, error: SaslError) -> Result<T, SaslError> {
        self.stage = SaslStage::Failed;
        self.authenticated = false;
        Err(error)
    }

    /// Only caller-confirmed successful writes advance barriers. This rejects
    /// a server ACK/challenge/success arriving before the expected local send.
    pub fn cap_request_written(&mut self) -> Result<(), SaslError> {
        if self.stage != SaslStage::AwaitingCapRequestWrite {
            return self.fail(SaslError::UnexpectedFrame);
        }
        self.stage = SaslStage::AwaitingCapAck;
        Ok(())
    }

    pub fn mechanism_written(&mut self) -> Result<(), SaslError> {
        if self.stage != SaslStage::AwaitingMechanismWrite {
            return self.fail(SaslError::UnexpectedFrame);
        }
        self.stage = SaslStage::AwaitingChallenge;
        Ok(())
    }

    pub fn payload_written(&mut self) -> Result<(), SaslError> {
        if self.stage != SaslStage::AwaitingPayloadWrite {
            return self.fail(SaslError::UnexpectedFrame);
        }
        self.stage = SaslStage::AwaitingResult;
        Ok(())
    }

    pub fn cap_end_written(&mut self) -> Result<(), SaslError> {
        if self.stage != SaslStage::AwaitingCapEndWrite {
            return self.fail(SaslError::UnexpectedFrame);
        }
        self.stage = SaslStage::AwaitingWelcome;
        Ok(())
    }

    pub fn abort(&mut self) {
        self.stage = SaslStage::Failed;
        self.authenticated = false;
    }

    pub fn observe(&mut self, frame: &ParsedMessage<'_>) -> Result<SaslAction, SaslError> {
        if matches!(self.stage, SaslStage::Idle | SaslStage::Failed) {
            return self.fail(SaslError::UnexpectedFrame);
        }

        if frame.command.eq_ignore_ascii_case("PING") {
            let params = frame.params();
            if params.len() != 1
                || params[0].is_empty()
                || params[0].len() > 256
                || !params[0].bytes().all(|b| (0x20..=0x7e).contains(&b))
            {
                return self.fail(SaslError::MalformedChallenge);
            }
            return Ok(SaslAction::Pong(format!("PONG :{}\r\n", params[0])));
        }

        if frame.command.eq_ignore_ascii_case("ERROR")
            || matches!(
                frame.command,
                "410"
                    | "421"
                    | "431"
                    | "432"
                    | "433"
                    | "436"
                    | "451"
                    | "462"
                    | "463"
                    | "464"
                    | "465"
                    | "466"
                    | "902"
                    | "904"
                    | "905"
                    | "906"
                    | "907"
                    | "908"
            )
        {
            return self.fail(SaslError::ServerRejected);
        }

        if frame.command.eq_ignore_ascii_case("CAP") {
            if !self.target_matches(frame, true) {
                return self.fail(SaslError::InvalidServerTarget);
            }
            let params = frame.params();
            if params.len() < 3 {
                return self.fail(SaslError::UnexpectedFrame);
            }
            match params[1] {
                "LS" if self.stage == SaslStage::Listing => {
                    self.ls_frames = self.ls_frames.saturating_add(1);
                    if self.ls_frames > MAX_LS_FRAMES {
                        return self.fail(SaslError::TooManyCapabilityFrames);
                    }
                    let (more, offered) = match params {
                        [_, _, offered] => (false, *offered),
                        [_, _, "*", offered] => (true, *offered),
                        _ => return self.fail(SaslError::UnexpectedFrame),
                    };
                    for item in offered.split_whitespace() {
                        if let Some(mechanisms) = item.strip_prefix("sasl=") {
                            if mechanisms.split(',').any(|m| m == "PLAIN") {
                                self.plain_offered = true;
                            }
                        }
                    }
                    if more {
                        return Ok(SaslAction::None);
                    }
                    if !self.plain_offered {
                        return self.fail(SaslError::MissingSaslPlain);
                    }
                    self.stage = SaslStage::AwaitingCapRequestWrite;
                    return Ok(SaslAction::Send(CAP_REQ_SASL));
                }
                "ACK" if self.stage == SaslStage::AwaitingCapAck => {
                    if params.len() != 3 || params[2] != "sasl" {
                        return self.fail(SaslError::ServerRejected);
                    }
                    self.stage = SaslStage::AwaitingMechanismWrite;
                    return Ok(SaslAction::Send(AUTH_PLAIN));
                }
                "NAK" => return self.fail(SaslError::ServerRejected),
                "DEL" if params.len() == 3 => {
                    if params[2].split_whitespace().any(|v| v == "sasl") {
                        return self.fail(SaslError::CapabilityRevoked);
                    }
                    return Ok(SaslAction::None);
                }
                "NEW" | "LIST" => return Ok(SaslAction::None),
                _ => return self.fail(SaslError::UnexpectedFrame),
            }
        }

        if frame.command.eq_ignore_ascii_case("AUTHENTICATE") {
            if self.stage != SaslStage::AwaitingChallenge || frame.params() != ["+"] {
                return self.fail(SaslError::MalformedChallenge);
            }
            self.stage = SaslStage::AwaitingPayloadWrite;
            return Ok(SaslAction::SupplySecret);
        }

        if frame.command == "900" {
            // Login informational only; 903 is required for completion.
            if self.stage != SaslStage::AwaitingResult {
                return self.fail(SaslError::UnexpectedFrame);
            }
            return Ok(SaslAction::None);
        }

        if frame.command == "903" {
            // Servers can address pre-registration SASL numerics to '*'.
            // Acceptance is still gated on the authenticated TLS session,
            // negotiated SASL, challenge response write and numeric 903.
            // The final 001 welcome must target the exact chosen nickname.
            if self.stage != SaslStage::AwaitingResult || !self.target_matches(frame, true) {
                return self.fail(SaslError::UnexpectedFrame);
            }
            self.authenticated = true;
            self.stage = SaslStage::AwaitingCapEndWrite;
            return Ok(SaslAction::Send(CAP_END));
        }

        if frame.command == "001" {
            if !self.target_matches(frame, false) {
                return self.fail(SaslError::InvalidServerTarget);
            }
            if self.stage != SaslStage::AwaitingWelcome || !self.authenticated {
                return self.fail(SaslError::PrematureWelcome);
            }
            self.stage = SaslStage::Registered;
            return Ok(SaslAction::None);
        }

        if frame.command == "901" {
            return self.fail(SaslError::ServerRejected);
        }

        Ok(SaslAction::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_frame;

    fn feed(flow: &mut SaslPlainFlow, wire: &str) -> Result<SaslAction, SaslError> {
        flow.observe(&parse_frame(wire).unwrap())
    }

    #[test]
    fn explicit_happy_path_requires_all_writes_and_903() {
        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        let init = s.begin().unwrap();
        assert_eq!(init[0], "CAP LS 302\r\n");
        assert_eq!(init[1], "NICK tester\r\n");
        assert_eq!(
            feed(&mut s, "CAP * LS * :multi-prefix\r\n"),
            Ok(SaslAction::None)
        );
        assert_eq!(
            feed(&mut s, "CAP * LS :message-tags sasl=EXTERNAL,PLAIN\r\n"),
            Ok(SaslAction::Send(CAP_REQ_SASL))
        );
        s.cap_request_written().unwrap();
        assert_eq!(
            feed(&mut s, "CAP tester ACK :sasl\r\n"),
            Ok(SaslAction::Send(AUTH_PLAIN))
        );
        s.mechanism_written().unwrap();
        assert_eq!(
            feed(&mut s, "AUTHENTICATE +\r\n"),
            Ok(SaslAction::SupplySecret)
        );
        s.payload_written().unwrap();
        assert_eq!(
            feed(&mut s, ":irc 900 tester :Logged in\r\n"),
            Ok(SaslAction::None)
        );
        assert_eq!(
            feed(&mut s, ":irc 903 tester :SASL complete\r\n"),
            Ok(SaslAction::Send(CAP_END))
        );
        s.cap_end_written().unwrap();
        assert_eq!(
            feed(&mut s, ":irc 001 tester :Welcome\r\n"),
            Ok(SaslAction::None)
        );
        assert!(s.registered());
    }

    #[test]
    fn refuses_unknown_plain_mechanism_and_anonymous_fallback() {
        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        s.begin().unwrap();
        assert_eq!(
            feed(&mut s, "CAP * LS :sasl=EXTERNAL\r\n"),
            Err(SaslError::MissingSaslPlain)
        );
        assert_eq!(s.stage(), SaslStage::Failed);
    }

    #[test]
    fn rejects_early_numeric_and_forged_ack() {
        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        s.begin().unwrap();
        assert_eq!(
            feed(&mut s, ":irc 001 tester :Too early\r\n"),
            Err(SaslError::PrematureWelcome)
        );
        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        s.begin().unwrap();
        feed(&mut s, "CAP * LS :sasl=PLAIN\r\n").unwrap();
        assert_eq!(
            feed(&mut s, "CAP tester ACK :sasl\r\n"),
            Err(SaslError::UnexpectedFrame)
        );
    }

    #[test]
    fn sasl_failure_and_revocation_never_downgrade_to_irc_chat() {
        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        s.begin().unwrap();
        feed(&mut s, "CAP * LS :sasl=PLAIN\r\n").unwrap();
        s.cap_request_written().unwrap();
        feed(&mut s, "CAP tester ACK :sasl\r\n").unwrap();
        s.mechanism_written().unwrap();
        feed(&mut s, "AUTHENTICATE +\r\n").unwrap();
        s.payload_written().unwrap();
        assert_eq!(
            feed(&mut s, ":irc 904 tester :Invalid credentials\r\n"),
            Err(SaslError::ServerRejected)
        );
        assert!(!s.registered());

        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        s.begin().unwrap();
        feed(&mut s, "CAP * LS :sasl=PLAIN\r\n").unwrap();
        s.cap_request_written().unwrap();
        feed(&mut s, "CAP tester ACK :sasl\r\n").unwrap();
        s.mechanism_written().unwrap();
        feed(&mut s, "AUTHENTICATE +\r\n").unwrap();
        s.payload_written().unwrap();
        feed(&mut s, ":irc 903 tester :Success\r\n").unwrap();
        s.cap_end_written().unwrap();
        feed(&mut s, ":irc 001 tester :Welcome\r\n").unwrap();
        assert!(s.registered());
        assert_eq!(
            feed(&mut s, ":irc CAP tester DEL :sasl\r\n"),
            Err(SaslError::CapabilityRevoked)
        );
        assert!(!s.registered());
    }

    #[test]
    fn sasl_pre_registration_903_wildcard_is_allowed_but_welcome_star_is_not() {
        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        s.begin().unwrap();
        feed(&mut s, "CAP * LS :sasl=PLAIN\r\n").unwrap();
        s.cap_request_written().unwrap();
        feed(&mut s, "CAP tester ACK :sasl\r\n").unwrap();
        s.mechanism_written().unwrap();
        feed(&mut s, "AUTHENTICATE +\r\n").unwrap();
        s.payload_written().unwrap();
        assert_eq!(
            feed(&mut s, ":irc 903 * :SASL authentication successful\r\n"),
            Ok(SaslAction::Send(CAP_END))
        );
        s.cap_end_written().unwrap();
        assert_eq!(
            feed(&mut s, ":irc 001 * :wrong welcome target\r\n"),
            Err(SaslError::InvalidServerTarget)
        );
        assert!(!s.registered());
    }

    #[test]
    fn sasl_pre_registration_903_to_different_named_user_is_rejected() {
        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        s.begin().unwrap();
        feed(&mut s, "CAP * LS :sasl=PLAIN\r\n").unwrap();
        s.cap_request_written().unwrap();
        feed(&mut s, "CAP tester ACK :sasl\r\n").unwrap();
        s.mechanism_written().unwrap();
        feed(&mut s, "AUTHENTICATE +\r\n").unwrap();
        s.payload_written().unwrap();
        assert_eq!(
            feed(&mut s, ":irc 903 another_user :SASL complete\r\n"),
            Err(SaslError::UnexpectedFrame)
        );
        assert!(!s.registered());
    }

    #[test]
    fn malformed_challenge_and_unexpected_server_target_fail() {
        let mut s = SaslPlainFlow::new("tester", "tester").unwrap();
        s.begin().unwrap();
        feed(&mut s, "CAP * LS :sasl=PLAIN\r\n").unwrap();
        s.cap_request_written().unwrap();
        assert_eq!(
            feed(&mut s, "CAP other ACK :sasl\r\n"),
            Err(SaslError::InvalidServerTarget)
        );
    }
}

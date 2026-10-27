//! Pure-data IRCv3 CAP 302 negotiation planner.
//!
//! This planner does not open sockets or authenticate an IRC server. It does
//! not enable SASL or credential-bearing capabilities; those require G2.
//! It emits a small allowlist only after explicit caller invocation.
#![forbid(unsafe_code)]

use crate::ParsedMessage;

pub const CAP_LS_302: &str = "CAP LS 302\r\n";
const ALLOWED: &[&str] = &["message-tags", "server-time", "multi-prefix"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapState {
    Idle,
    Listing,
    AwaitingAck,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    InvalidPolicy,
    UnsupportedRequestedCapability,
    UnexpectedReply,
    InvalidReply,
    MissingRequired,
    Rejected,
    BadAcknowledgement,
    RequiredCapabilityRemoved,
}

/// Contains only small, allowlisted capability names, not credentials or
/// trusted device identities.
#[derive(Debug, Clone)]
pub struct CapNegotiator {
    state: CapState,
    required: Vec<String>,
    optional: Vec<String>,
    advertised: Vec<String>,
    requested: Vec<String>,
    enabled: Vec<String>,
}

fn unique_push(values: &mut Vec<String>, name: &str) {
    if !values.iter().any(|v| v == name) {
        values.push(name.to_string());
    }
}

fn known_name(name: &str) -> bool {
    ALLOWED.contains(&name)
}

impl CapNegotiator {
    /// Refuse unreviewed capabilities (including SASL), duplicate policy
    /// entries, or dependencies of server-time on message-tags.
    pub fn new(required: &[&str], optional: &[&str]) -> Result<Self, CapError> {
        if required.len() + optional.len() > ALLOWED.len() {
            return Err(CapError::InvalidPolicy);
        }
        let mut names = Vec::new();
        for &name in required.iter().chain(optional.iter()) {
            if !known_name(name) {
                return Err(CapError::UnsupportedRequestedCapability);
            }
            if names.contains(&name) {
                return Err(CapError::InvalidPolicy);
            }
            names.push(name);
        }
        let has_tags = names.contains(&"message-tags");
        let requires_time = required.contains(&"server-time");
        if (names.contains(&"server-time") && !has_tags)
            || (requires_time && !required.contains(&"message-tags"))
        {
            return Err(CapError::InvalidPolicy);
        }

        Ok(Self {
            state: CapState::Idle,
            required: required.iter().map(|s| (*s).to_string()).collect(),
            optional: optional.iter().map(|s| (*s).to_string()).collect(),
            advertised: Vec::new(),
            requested: Vec::new(),
            enabled: Vec::new(),
        })
    }

    pub fn state(&self) -> CapState {
        self.state
    }

    pub fn enabled(&self) -> &[String] {
        &self.enabled
    }

    pub fn begin(&mut self) -> Result<&'static str, CapError> {
        if self.state != CapState::Idle {
            return Err(CapError::UnexpectedReply);
        }
        self.state = CapState::Listing;
        Ok(CAP_LS_302)
    }

    /// Process a *server* CAP reply. The returned string, when present, is a
    /// frame proposal that a separate authenticated transport may send.
    /// Until G2 this cannot be used as a production network handshake.
    pub fn observe(&mut self, message: &ParsedMessage<'_>) -> Result<Option<String>, CapError> {
        if !message.command.eq_ignore_ascii_case("CAP") {
            return Ok(None);
        }
        let params = message.params();
        if params.len() < 3 {
            return Err(CapError::InvalidReply);
        }
        match params[1] {
            "LS" => {
                if self.state != CapState::Listing {
                    return Err(CapError::UnexpectedReply);
                }
                let (more, caps) = match params {
                    [_, _, offered] => (false, *offered),
                    [_, _, "*", offered] => (true, *offered),
                    _ => return Err(CapError::InvalidReply),
                };
                for offered in caps.split_whitespace() {
                    let key = offered.split_once('=').map(|p| p.0).unwrap_or(offered);
                    if known_name(key) {
                        unique_push(&mut self.advertised, key);
                    }
                }
                if more {
                    return Ok(None);
                }
                if self
                    .required
                    .iter()
                    .any(|name| !self.advertised.contains(name))
                {
                    self.state = CapState::Failed;
                    return Err(CapError::MissingRequired);
                }

                let mut selected = self.required.clone();
                for name in &self.optional {
                    if self.advertised.contains(name)
                        && (name != "server-time" || selected.iter().any(|n| n == "message-tags"))
                    {
                        unique_push(&mut selected, name);
                    }
                }
                self.requested = selected;
                if self.requested.is_empty() {
                    self.state = CapState::Complete;
                    return Ok(Some("CAP END\r\n".to_owned()));
                }
                self.state = CapState::AwaitingAck;
                Ok(Some(format!("CAP REQ :{}\r\n", self.requested.join(" "))))
            }
            "ACK" => {
                if self.state != CapState::AwaitingAck || params.len() != 3 {
                    return Err(CapError::UnexpectedReply);
                }
                let acknowledged: Vec<&str> = params[2].split_whitespace().collect();
                let same = acknowledged.len() == self.requested.len()
                    && acknowledged
                        .iter()
                        .all(|cap| self.requested.iter().any(|r| r.as_str() == *cap))
                    && self
                        .requested
                        .iter()
                        .all(|cap| acknowledged.contains(&cap.as_str()));
                if !same {
                    self.state = CapState::Failed;
                    return Err(CapError::BadAcknowledgement);
                }
                self.enabled = self.requested.clone();
                self.state = CapState::Complete;
                Ok(Some("CAP END\r\n".to_owned()))
            }
            "NAK" => {
                if self.state != CapState::AwaitingAck {
                    return Err(CapError::UnexpectedReply);
                }
                self.state = CapState::Failed;
                Err(CapError::Rejected)
            }
            "DEL" => {
                // A server may revoke capabilities mid-session. Never keep a
                // removed capability optimistically marked as enabled.
                if self.state != CapState::Complete || params.len() != 3 {
                    return Err(CapError::UnexpectedReply);
                }
                for name in params[2].split_whitespace() {
                    self.enabled.retain(|cap| cap != name);
                    if name == "message-tags" {
                        self.enabled.retain(|cap| cap != "server-time");
                    }
                    if self.required.iter().any(|cap| cap == name) {
                        self.state = CapState::Failed;
                        return Err(CapError::RequiredCapabilityRemoved);
                    }
                }
                Ok(None)
            }
            // NEW does not grant anything. LIST is not a request ACK.
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_frame;

    fn observe(cap: &mut CapNegotiator, wire: &str) -> Result<Option<String>, CapError> {
        cap.observe(&parse_frame(wire).expect("valid synthetic IRC line"))
    }

    #[test]
    fn cap302_multiline_listing_ack_and_end() {
        let mut cap = CapNegotiator::new(&["message-tags"], &["server-time"]).unwrap();
        assert_eq!(cap.state(), CapState::Idle);
        assert_eq!(cap.begin(), Ok("CAP LS 302\r\n"));
        assert_eq!(observe(&mut cap, "CAP * LS * :multi-prefix\r\n"), Ok(None));
        assert_eq!(
            observe(&mut cap, "CAP * LS :message-tags server-time=2026\r\n"),
            Ok(Some("CAP REQ :message-tags server-time\r\n".into()))
        );
        assert_eq!(cap.state(), CapState::AwaitingAck);
        assert_eq!(
            observe(&mut cap, "CAP tester ACK :server-time message-tags\r\n"),
            Ok(Some("CAP END\r\n".into()))
        );
        assert_eq!(cap.state(), CapState::Complete);
        assert_eq!(
            cap.enabled().iter().map(String::as_str).collect::<Vec<_>>(),
            vec!["message-tags", "server-time"]
        );
    }

    #[test]
    fn fail_closed_for_missing_required_or_spurious_ack() {
        let mut cap = CapNegotiator::new(&["message-tags"], &[]).unwrap();
        cap.begin().unwrap();
        assert_eq!(
            observe(&mut cap, "CAP * LS :multi-prefix\r\n"),
            Err(CapError::MissingRequired)
        );
        assert_eq!(cap.state(), CapState::Failed);
        assert_eq!(
            observe(&mut cap, "CAP * ACK :message-tags\r\n"),
            Err(CapError::UnexpectedReply)
        );
    }

    #[test]
    fn malformed_ack_refuses_silent_capability_change() {
        let mut cap = CapNegotiator::new(&["message-tags"], &[]).unwrap();
        cap.begin().unwrap();
        observe(&mut cap, "CAP * LS :message-tags\r\n").unwrap();
        assert_eq!(
            observe(&mut cap, "CAP * ACK :multi-prefix\r\n"),
            Err(CapError::BadAcknowledgement)
        );
        assert_eq!(cap.state(), CapState::Failed);
    }

    #[test]
    fn revocation_of_required_capability_is_terminal() {
        let mut cap = CapNegotiator::new(&["message-tags"], &["server-time"]).unwrap();
        cap.begin().unwrap();
        observe(&mut cap, "CAP * LS :message-tags server-time\r\n").unwrap();
        observe(&mut cap, "CAP * ACK :message-tags server-time\r\n").unwrap();
        assert_eq!(
            observe(&mut cap, "CAP * DEL :message-tags\r\n"),
            Err(CapError::RequiredCapabilityRemoved)
        );
        assert_eq!(cap.state(), CapState::Failed);
    }

    #[test]
    fn never_auto_enables_sasl() {
        assert_eq!(
            CapNegotiator::new(&["sasl"], &[]).unwrap_err(),
            CapError::UnsupportedRequestedCapability
        );
        let mut cap = CapNegotiator::new(&[], &["multi-prefix"]).unwrap();
        cap.begin().unwrap();
        assert_eq!(
            observe(&mut cap, "CAP * LS :sasl=PLAIN multi-prefix\r\n"),
            Ok(Some("CAP REQ :multi-prefix\r\n".into()))
        );
    }

    #[test]
    fn server_time_depends_on_message_tags() {
        assert_eq!(
            CapNegotiator::new(&[], &["server-time"]).unwrap_err(),
            CapError::InvalidPolicy
        );
        let mut cap = CapNegotiator::new(&[], &["message-tags", "server-time"]).unwrap();
        cap.begin().unwrap();
        assert_eq!(
            observe(&mut cap, "CAP * LS :server-time\r\n"),
            Ok(Some("CAP END\r\n".into()))
        );
    }
}

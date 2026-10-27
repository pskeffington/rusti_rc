//! Synthetic, deterministic IRC wire fixtures for portable offline tests.
//!
//! No network connections, live identities, credentials, or operational data.
#![forbid(unsafe_code)]

pub const PING_FRAME: &str = "PING :irc.test.invalid\r\n";
pub const CHANNEL_FRAME: &str = ":alice!user@host PRIVMSG #lab :hello\r\n";
pub const INVALID_INJECTION: &str = "PRIVMSG #lab :hello\r\nOPER root\r\n";

pub fn check_baseline_fixtures() -> bool {
    rusti_proto::parse_frame(PING_FRAME).is_ok()
        && rusti_proto::parse_frame(CHANNEL_FRAME).is_ok()
        && rusti_proto::parse_frame(INVALID_INJECTION).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_deterministic_and_offline() {
        assert!(check_baseline_fixtures());
    }
}

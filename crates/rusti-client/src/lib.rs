//! Rust IRC client policy boundary; no socket implementation in this scaffold.
#![forbid(unsafe_code)]

pub mod recovery;

use std::net::IpAddr;

pub use rusti_proto::FrameError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    Disabled,
    InvalidHost,
    InvalidPort,
    InsecureTransportForbidden,
    NetworkingNotImplemented,
    InvalidFrame(FrameError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// An explicit operator action must enable this; importing is inert.
    pub enabled: bool,
    pub server_host: String,
    pub server_port: u16,
    /// Always true for any operational deployment. No downgrade is supported.
    pub tls_required: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_host: String::new(),
            server_port: 6697,
            tls_required: true,
        }
    }
}

fn valid_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl ClientConfig {
    pub fn validate(&self) -> Result<(), ClientError> {
        if !self.enabled {
            return Err(ClientError::Disabled);
        }
        if !self.tls_required {
            return Err(ClientError::InsecureTransportForbidden);
        }
        if !valid_host(&self.server_host) {
            return Err(ClientError::InvalidHost);
        }
        if self.server_port == 0 {
            return Err(ClientError::InvalidPort);
        }
        Ok(())
    }

    /// Cannot connect yet: no implementation opens a socket or negotiates TLS.
    pub fn request_connect(&self) -> Result<(), ClientError> {
        self.validate()?;
        Err(ClientError::NetworkingNotImplemented)
    }
}

/// Safe local wire encoding for a lab fixture; not an authorization or send.
pub fn preview_privmsg(target: &str, body: &str) -> Result<String, ClientError> {
    rusti_proto::encode_privmsg(target, body).map_err(ClientError::InvalidFrame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_import_and_defaults_do_not_connect() {
        assert_eq!(ClientConfig::default().request_connect(), Err(ClientError::Disabled));
    }

    #[test]
    fn tls_downgrade_never_passes_validation() {
        let mut config = ClientConfig {
            enabled: true,
            server_host: "irc.example.org".into(),
            ..ClientConfig::default()
        };
        config.tls_required = false;
        assert_eq!(config.request_connect(), Err(ClientError::InsecureTransportForbidden));
    }

    #[test]
    fn valid_configuration_is_not_a_working_connection() {
        let config = ClientConfig {
            enabled: true,
            server_host: "192.168.0.5".into(),
            ..ClientConfig::default()
        };
        assert_eq!(config.request_connect(), Err(ClientError::NetworkingNotImplemented));
    }

    #[test]
    fn rejects_host_injection() {
        let config = ClientConfig {
            enabled: true,
            server_host: "irc.example.org:6667\nOPER".into(),
            ..ClientConfig::default()
        };
        assert_eq!(config.validate(), Err(ClientError::InvalidHost));
    }
}

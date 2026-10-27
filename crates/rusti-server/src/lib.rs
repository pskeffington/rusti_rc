//! Server policy scaffold; no IRC listener or server runtime is implemented.
//!
//! Default-off, loopback-only binding and TLS/limit validation are preparation
//! for a future LAN server. No port is opened when this crate is imported.
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerError {
    Disabled,
    PublicBindForbidden,
    InsecureTransportForbidden,
    InvalidLimits,
    ListenerNotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    pub tls_required: bool,
    pub max_clients: usize,
    pub max_channels: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6697),
            tls_required: true,
            max_clients: 16,
            max_channels: 8,
        }
    }
}

impl ServerConfig {
    pub fn validate(&self) -> Result<(), ServerError> {
        if !self.enabled {
            return Err(ServerError::Disabled);
        }
        if !self.bind.ip().is_loopback() {
            return Err(ServerError::PublicBindForbidden);
        }
        if !self.tls_required {
            return Err(ServerError::InsecureTransportForbidden);
        }
        if self.max_clients == 0
            || self.max_clients > 64
            || self.max_channels == 0
            || self.max_channels > 32
        {
            return Err(ServerError::InvalidLimits);
        }
        Ok(())
    }

    pub fn request_start(&self) -> Result<(), ServerError> {
        self.validate()?;
        Err(ServerError::ListenerNotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_is_disabled_on_import() {
        assert_eq!(
            ServerConfig::default().request_start(),
            Err(ServerError::Disabled)
        );
    }

    #[test]
    fn never_listens_on_wildcard() {
        let mut cfg = ServerConfig {
            enabled: true,
            ..ServerConfig::default()
        };
        cfg.bind = "0.0.0.0:6697".parse().unwrap();
        assert_eq!(cfg.request_start(), Err(ServerError::PublicBindForbidden));
    }

    #[test]
    fn no_plaintext_listener() {
        let cfg = ServerConfig {
            enabled: true,
            tls_required: false,
            ..ServerConfig::default()
        };
        assert_eq!(
            cfg.request_start(),
            Err(ServerError::InsecureTransportForbidden)
        );
    }

    #[test]
    fn loopback_is_still_unimplemented() {
        let cfg = ServerConfig {
            enabled: true,
            ..ServerConfig::default()
        };
        assert_eq!(
            cfg.request_start(),
            Err(ServerError::ListenerNotImplemented)
        );
    }
}

//! Opaque references to operator-provisioned credentials.
//!
//! A reference is not a password or a trust-root grant. It must only be
//! resolved by a separately reviewed OS-backed secret store. Importing,
//! constructing, or inspecting this type does not read secrets or contact
//! an IRC server.
#![forbid(unsafe_code)]

use std::fmt;

use crate::ClientConfig;

const MAX_ID_BYTES: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPurpose {
    SaslPassword,
    ClientCertificate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRefError {
    InvalidItemId,
    InvalidServerIdentity,
    InvalidPort,
    ServerMismatch,
    InsecureClient,
}

/// Debug is intentionally redacted: even opaque keychain item identifiers
/// may leak operational account naming or organizational membership.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRef {
    item_id: String,
    server_identity: String,
    server_port: u16,
    purpose: CredentialPurpose,
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialRef(<redacted>)")
    }
}

impl CredentialRef {
    pub fn new(
        item_id: &str,
        server_identity: &str,
        server_port: u16,
        purpose: CredentialPurpose,
    ) -> Result<Self, CredentialRefError> {
        // Store keys are opaque identifiers, not paths, URLs, command lines,
        // user names, environment variable names, or embedded secret bytes.
        if item_id.is_empty()
            || item_id.len() > MAX_ID_BYTES
            || !item_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(CredentialRefError::InvalidItemId);
        }
        if server_port == 0 {
            return Err(CredentialRefError::InvalidPort);
        }
        // Reuse the same host/port validation policy as the live TLS client.
        // This checks syntax only; it does not load a secret or open a socket.
        let expected = ClientConfig {
            enabled: true,
            server_host: server_identity.to_string(),
            server_port,
            tls_required: true,
        };
        if expected.validate().is_err() {
            return Err(CredentialRefError::InvalidServerIdentity);
        }
        Ok(Self {
            item_id: item_id.to_string(),
            server_identity: server_identity.to_ascii_lowercase(),
            server_port,
            purpose,
        })
    }

    /// Used only by a trusted credential-store adapter. Never log the return.
    pub fn store_item_id(&self) -> &str {
        &self.item_id
    }

    pub fn purpose(&self) -> CredentialPurpose {
        self.purpose
    }
    /// For constructing the OS keychain service name; never log the value.
    pub fn server_identity(&self) -> &str {
        &self.server_identity
    }

    /// Credential references are unique to a server TLS identity + port.
    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    /// Bind each credential reference to the exact TLS server identity before
    /// a future authentication handler may access the OS keychain.
    pub fn authorize_for(&self, client: &ClientConfig) -> Result<(), CredentialRefError> {
        client
            .validate()
            .map_err(|_| CredentialRefError::InsecureClient)?;
        if self.server_port != client.server_port
            || !self
                .server_identity
                .eq_ignore_ascii_case(&client.server_host)
        {
            return Err(CredentialRefError::ServerMismatch);
        }
        Ok(())
    }
}

/// Platform adapters must implement a protected, interactive or already
/// authorized credential lookup. The *separate* modern `net/` workspace has
/// an opt-in native macOS/Windows keychain adapter; this portable crate only
/// defines the no-I/O policy and interface. The callback design avoids
/// returning a long-lived secret, but by itself does not guarantee memory
/// zeroization or OS protection.
///
/// No environment-variable, plaintext-file or CLI-argument store should be
/// shipped as a production implementation of this trait.
pub trait ProtectedCredentialStore {
    type Error;

    fn with_secret<R, F>(&self, reference: &CredentialRef, use_secret: F) -> Result<R, Self::Error>
    where
        F: FnOnce(&[u8]) -> R;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(host: &str) -> ClientConfig {
        ClientConfig {
            enabled: true,
            server_host: host.into(),
            server_port: 6697,
            tls_required: true,
        }
    }

    #[test]
    fn secret_reference_never_debug_prints_operational_identifier() {
        let reference = CredentialRef::new(
            "org_a_private_123",
            "irc.example.org",
            6697,
            CredentialPurpose::SaslPassword,
        )
        .unwrap();
        let output = format!("{reference:?}");
        assert_eq!(output, "CredentialRef(<redacted>)");
        assert!(!output.contains("org_a"));
        assert!(!output.contains("private"));
    }

    #[test]
    fn credential_reference_rejects_path_and_injection() {
        for item in [
            "../secrets",
            "key:root",
            "x\nOPER",
            "",
            "a b",
            "/etc/passwd",
        ] {
            assert_eq!(
                CredentialRef::new(
                    item,
                    "irc.example.org",
                    6697,
                    CredentialPurpose::SaslPassword
                )
                .unwrap_err(),
                CredentialRefError::InvalidItemId
            );
        }
        assert_eq!(
            CredentialRef::new("id", "bad host\n", 6697, CredentialPurpose::SaslPassword)
                .unwrap_err(),
            CredentialRefError::InvalidServerIdentity
        );
        assert_eq!(
            CredentialRef::new("id", "irc.example.org", 0, CredentialPurpose::SaslPassword)
                .unwrap_err(),
            CredentialRefError::InvalidPort
        );
    }

    #[test]
    fn credential_is_bound_to_explicit_secure_server_identity() {
        let reference = CredentialRef::new(
            "team_irc",
            "irc.example.org",
            6697,
            CredentialPurpose::SaslPassword,
        )
        .unwrap();
        assert_eq!(reference.authorize_for(&client("IRC.EXAMPLE.ORG")), Ok(()));
        let mut other_port = client("irc.example.org");
        other_port.server_port = 7000;
        assert_eq!(
            reference.authorize_for(&other_port),
            Err(CredentialRefError::ServerMismatch)
        );
        assert_eq!(
            reference.authorize_for(&client("another.example.org")),
            Err(CredentialRefError::ServerMismatch)
        );
        let mut insecure = client("irc.example.org");
        insecure.tls_required = false;
        assert_eq!(
            reference.authorize_for(&insecure),
            Err(CredentialRefError::InsecureClient)
        );
    }

    #[test]
    fn disabled_client_cannot_request_credential_use() {
        let reference = CredentialRef::new(
            "team_irc",
            "irc.example.org",
            6697,
            CredentialPurpose::ClientCertificate,
        )
        .unwrap();
        let mut config = client("irc.example.org");
        config.enabled = false;
        assert_eq!(
            reference.authorize_for(&config),
            Err(CredentialRefError::InsecureClient)
        );
    }
}

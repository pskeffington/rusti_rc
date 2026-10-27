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
    ServerMismatch,
    InsecureClient,
}

/// Debug is intentionally redacted: even opaque keychain item identifiers
/// may leak operational account naming or organizational membership.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRef {
    item_id: String,
    server_identity: String,
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
        let server_ok = !server_identity.is_empty()
            && server_identity.len() <= 253
            && server_identity
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
        if !server_ok {
            return Err(CredentialRefError::InvalidServerIdentity);
        }
        Ok(Self {
            item_id: item_id.to_string(),
            server_identity: server_identity.to_ascii_lowercase(),
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

    /// Bind each credential reference to the exact TLS server identity before
    /// a future authentication handler may access the OS keychain.
    pub fn authorize_for(&self, client: &ClientConfig) -> Result<(), CredentialRefError> {
        client.validate().map_err(|_| CredentialRefError::InsecureClient)?;
        if !self.server_identity.eq_ignore_ascii_case(&client.server_host) {
            return Err(CredentialRefError::ServerMismatch);
        }
        Ok(())
    }
}

/// Platform adapters must implement a protected, interactive or already
/// authorized credential lookup. This **does not** have an implementation in
/// rusti_rc yet. The callback design avoids returning a long-lived secret
/// value, but it does not by itself guarantee zeroization or OS protection.
///
/// No environment-variable, plaintext-file or CLI-argument store should be
/// shipped as a production implementation of this trait.
pub trait ProtectedCredentialStore {
    type Error;

    fn with_secret<R, F>(
        &self,
        reference: &CredentialRef,
        use_secret: F,
    ) -> Result<R, Self::Error>
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
            "org_a_private_123", "irc.example.org", CredentialPurpose::SaslPassword,
        )
        .unwrap();
        let output = format!("{reference:?}");
        assert_eq!(output, "CredentialRef(<redacted>)");
        assert!(!output.contains("org_a"));
        assert!(!output.contains("private"));
    }

    #[test]
    fn credential_reference_rejects_path_and_injection() {
        for item in ["../secrets", "key:root", "x\nOPER", "", "a b", "/etc/passwd"] {
            assert_eq!(
                CredentialRef::new(item, "irc.example.org", CredentialPurpose::SaslPassword)
                    .unwrap_err(),
                CredentialRefError::InvalidItemId
            );
        }
        assert_eq!(
            CredentialRef::new("id", "bad host\n", CredentialPurpose::SaslPassword).unwrap_err(),
            CredentialRefError::InvalidServerIdentity
        );
    }

    #[test]
    fn credential_is_bound_to_explicit_secure_server_identity() {
        let reference = CredentialRef::new(
            "team_irc", "irc.example.org", CredentialPurpose::SaslPassword,
        )
        .unwrap();
        assert_eq!(reference.authorize_for(&client("IRC.EXAMPLE.ORG")), Ok(()));
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
            "team_irc", "irc.example.org", CredentialPurpose::ClientCertificate,
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

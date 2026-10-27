//! Independent Ergo IRCd SASL account tests over real verified TLS.
//!
//! Ignored in ordinary Cargo runs. Only the localhost-bound ephemeral CI
//! server may create a synthetic account; there are no real usernames or
//! passwords, field network connections, or credential-store assumptions.
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rusti_client::credential_ref::{CredentialPurpose, CredentialRef, ProtectedCredentialStore};
use rusti_client::ClientConfig;
use rusti_transport_tls::{Submission, Timeouts, TlsIrcSession, TransportError};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

const ACCOUNT: &str = "rustisynacct";
const SECRET: &[u8] = b"synthetic-ci-credential-2026";
const BAD_SECRET: &[u8] = b"invalid-ci-credential-2026";

struct SyntheticAccountStore<'a> {
    password: &'a [u8],
    calls: AtomicUsize,
}

impl<'a> SyntheticAccountStore<'a> {
    fn new(password: &'a [u8]) -> Self {
        Self {
            password,
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ProtectedCredentialStore for SyntheticAccountStore<'_> {
    type Error = ();
    fn with_secret<R, F>(&self, _reference: &CredentialRef, f: F) -> Result<R, Self::Error>
    where
        F: FnOnce(&[u8]) -> R,
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(f(self.password))
    }
}

fn test_session() -> (TlsIrcSession, SocketAddr) {
    let address: SocketAddr = env::var("RUSTI_ERGO_ADDR")
        .expect("isolated Ergo address required")
        .parse()
        .expect("valid CI loopback socket address");
    assert_eq!(address.ip().to_string(), "127.0.0.1");
    let root_path = env::var("RUSTI_ERGO_CA_DER").expect("isolated Ergo CA path required");
    let der = fs::read(root_path).expect("synthetic root CA file");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(der))
        .expect("trusted synthetic CA");

    let client = TlsIrcSession::connect_tls(
        &ClientConfig {
            enabled: true,
            server_host: "localhost".to_string(),
            server_port: address.port(),
            tls_required: true,
        },
        address,
        roots,
        Timeouts {
            io: Duration::from_millis(500),
            ..Timeouts::default()
        },
    )
    .expect("independent server TLS must verify synthetic CA + SAN");
    (client, address)
}

fn credential(port: u16, hostname: &str) -> CredentialRef {
    CredentialRef::new(
        "synthetic_sasl_fixture",
        hostname,
        port,
        CredentialPurpose::SaslPassword,
    )
    .unwrap()
}

#[test]
#[ignore = "requires isolated Ergo IRCd with an ephemeral, registered synthetic account"]
fn account_sasl_plain_success_then_channel_submission() {
    let (mut client, address) = test_session();
    let store = SyntheticAccountStore::new(SECRET);

    client
        .register_sasl_plain(
            ACCOUNT,
            ACCOUNT,
            ACCOUNT,
            &credential(address.port(), "localhost"),
            &store,
            Duration::from_secs(12),
        )
        .expect("real Ergo must accept account credentials over verified TLS");
    assert!(
        client.is_registered(),
        "SASL 903 and numeric 001 are both required"
    );
    assert_eq!(
        store.calls(),
        1,
        "fetch account credential only at SASL challenge"
    );
    assert_eq!(
        client.join("#rusti-sasl-check").unwrap(),
        Submission::SubmittedUnconfirmed
    );
    assert_eq!(
        client
            .send_privmsg("#rusti-sasl-check", "synthetic account test")
            .unwrap(),
        Submission::SubmittedUnconfirmed
    );
    // No receipt or Rust Boy authorization is implied by submission.
}

#[test]
#[ignore = "requires isolated Ergo IRCd with an ephemeral, registered synthetic account"]
fn rejected_sasl_password_fails_without_anonymous_downgrade() {
    let (mut client, address) = test_session();
    let store = SyntheticAccountStore::new(BAD_SECRET);

    let rejected = client.register_sasl_plain(
        "rustibadtest",
        "rustibadtest",
        ACCOUNT,
        &credential(address.port(), "localhost"),
        &store,
        Duration::from_secs(12),
    );
    assert!(
        matches!(rejected, Err(TransportError::Sasl(_)) | Err(TransportError::SaslPhase(_, _, _))),
        "a wrong password must produce a SASL protocol rejection, not a successful anonymous login: {rejected:?}"
    );
    assert_eq!(store.calls(), 1);
    assert!(!client.is_registered());
    assert!(matches!(
        client.send_privmsg("#rusti-sasl-check", "must not send"),
        Err(TransportError::NotRegistered)
    ));
}

#[test]
#[ignore = "requires isolated Ergo IRCd with an ephemeral, registered synthetic account"]
fn credential_bound_to_different_tls_name_is_not_loaded() {
    let (mut client, address) = test_session();
    let store = SyntheticAccountStore::new(SECRET);

    let result = client.register_sasl_plain(
        "rustimismatch",
        "rustimismatch",
        ACCOUNT,
        &credential(address.port(), "other.invalid"),
        &store,
        Duration::from_secs(12),
    );
    assert!(matches!(result, Err(TransportError::CredentialPolicy)));
    assert_eq!(store.calls(), 0);
    assert!(!client.is_registered());
}

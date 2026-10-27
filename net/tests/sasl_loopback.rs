//! Synthetic localhost TLS/SASL exchange. Does NOT use OS credentials,
//! real accounts, organization trust, public Internet, or live IRC servers.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rusti_client::credential_ref::{
    CredentialPurpose, CredentialRef, ProtectedCredentialStore,
};
use rusti_client::ClientConfig;
use rusti_transport_tls::{Submission, Timeouts, TlsIrcSession, TransportError};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

struct SyntheticStore;
impl ProtectedCredentialStore for SyntheticStore {
    type Error = ();
    fn with_secret<R, F>(&self, _: &CredentialRef, f: F) -> Result<R, Self::Error>
    where
        F: FnOnce(&[u8]) -> R,
    {
        // Test-only fixture, not a production implementation of this trait.
        Ok(f(b"synthetic-test-password"))
    }
}

enum Mode {
    Success,
    Reject,
    NoPlain,
    PrematureWelcome,
}

fn read_line(tls: &mut StreamOwned<ServerConnection, std::net::TcpStream>) -> Option<String> {
    let mut result = Vec::new();
    loop {
        let mut one = [0u8; 1];
        if tls.read(&mut one).ok()? == 0 {
            return None;
        }
        result.push(one[0]);
        if result.len() > 512 {
            return None;
        }
        if one[0] == b'\n' {
            return String::from_utf8(result).ok();
        }
    }
}

fn lab(
    mode: Mode,
) -> (SocketAddr, RootCertStore, thread::JoinHandle<bool>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut root = RootCertStore::empty();
    root.add(cert.der().clone()).unwrap();
    let cfg = ServerConfig::builder_with_provider(
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let Ok((tcp, _)) = listener.accept() else { return false };
        tcp.set_read_timeout(Some(Duration::from_secs(3))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(3))).ok();
        let Ok(conn) = ServerConnection::new(Arc::new(cfg)) else { return false };
        let mut tls = StreamOwned::new(conn, tcp);

        for expected in [
            "CAP LS 302\r\n",
            "NICK tester\r\n",
            "USER tester 0 * :rusti_rc\r\n",
        ] {
            if read_line(&mut tls).as_deref() != Some(expected) {
                return false;
            }
        }

        if matches!(mode, Mode::NoPlain) {
            return tls.write_all(b":irc CAP * LS :sasl=EXTERNAL\r\n").is_ok();
        }

        if tls.write_all(b":irc CAP * LS :sasl=EXTERNAL,PLAIN\r\n").is_err() {
            return false;
        }
        if read_line(&mut tls).as_deref() != Some("CAP REQ :sasl\r\n") {
            return false;
        }
        if tls.write_all(b":irc CAP tester ACK :sasl\r\n").is_err() {
            return false;
        }
        if read_line(&mut tls).as_deref() != Some("AUTHENTICATE PLAIN\r\n") {
            return false;
        }
        if matches!(mode, Mode::PrematureWelcome) {
            return tls.write_all(b":irc 001 tester :Welcome early\r\n").is_ok();
        }

        if tls.write_all(b"AUTHENTICATE +\r\n").is_err() {
            return false;
        }
        // Read and check the sensitive command without returning it or
        // recording it in a test artifact or failure message.
        let Some(encoded) = read_line(&mut tls) else { return false };
        // Test fixture generated offline; expected value is not a real secret.
        if encoded != "AUTHENTICATE AHRlc3RlcgBzeW50aGV0aWMtdGVzdC1wYXNzd29yZA==\r\n" {
            return false;
        }

        if matches!(mode, Mode::Reject) {
            return tls.write_all(b":irc 904 tester :Invalid account\r\n").is_ok();
        }
        if tls.write_all(b":irc 903 tester :SASL success\r\n").is_err() {
            return false;
        }
        if read_line(&mut tls).as_deref() != Some("CAP END\r\n") {
            return false;
        }
        if tls.write_all(b":irc 001 tester :Welcome\r\n").is_err() {
            return false;
        }
        read_line(&mut tls).as_deref() == Some("JOIN #lab\r\n")
            && read_line(&mut tls).as_deref() == Some("PRIVMSG #lab :hello\r\n")
    });
    (addr, root, worker)
}

fn session(addr: SocketAddr, roots: RootCertStore) -> TlsIrcSession {
    TlsIrcSession::connect_tls(
        &ClientConfig {
            enabled: true,
            server_host: "localhost".to_owned(),
            server_port: addr.port(),
            tls_required: true,
        },
        addr,
        roots,
        Timeouts::default(),
    )
    .unwrap()
}

fn reference(port: u16) -> CredentialRef {
    CredentialRef::new("test_op", "localhost", port, CredentialPurpose::SaslPassword).unwrap()
}

#[test]
fn verified_tls_sasl_then_irc_registration_and_channel_send() {
    let (addr, roots, server) = lab(Mode::Success);
    let mut tls = session(addr, roots);
    let result = tls.register_sasl_plain(
        "tester", "tester", "tester",
        &reference(addr.port()),
        &SyntheticStore,
        Duration::from_secs(5),
    );
    assert!(result.is_ok(), "secure test login should complete: {result:?}");
    assert!(tls.is_registered());
    assert_eq!(tls.join("#lab").unwrap(), Submission::SubmittedUnconfirmed);
    assert_eq!(tls.send_privmsg("#lab", "hello").unwrap(), Submission::SubmittedUnconfirmed);
    assert!(server.join().unwrap());
}

#[test]
fn missing_plain_mechanism_fails_without_secret_transmission() {
    let (addr, roots, server) = lab(Mode::NoPlain);
    let mut tls = session(addr, roots);
    let err = tls.register_sasl_plain(
        "tester", "tester", "tester",
        &reference(addr.port()),
        &SyntheticStore,
        Duration::from_secs(5),
    );
    assert!(err.is_err());
    assert!(!tls.is_registered());
    assert!(server.join().unwrap());
}

#[test]
fn failed_sasl_never_registers_anonymously() {
    let (addr, roots, server) = lab(Mode::Reject);
    let mut tls = session(addr, roots);
    let err = tls.register_sasl_plain(
        "tester", "tester", "tester",
        &reference(addr.port()),
        &SyntheticStore,
        Duration::from_secs(5),
    );
    assert!(err.is_err());
    assert!(!tls.is_registered());
    assert!(matches!(
        tls.send_privmsg("#lab", "not sent"), Err(TransportError::NotRegistered)
    ));
    assert!(server.join().unwrap());
}

#[test]
fn premature_welcome_is_not_sasl_success() {
    let (addr, roots, server) = lab(Mode::PrematureWelcome);
    let mut tls = session(addr, roots);
    assert!(tls.register_sasl_plain(
        "tester", "tester", "tester",
        &reference(addr.port()), &SyntheticStore, Duration::from_secs(5),
    ).is_err());
    assert!(!tls.is_registered());
    assert!(server.join().unwrap());
}

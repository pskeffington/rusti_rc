//! G2f real localhost TLS interruption/cancellation tests; no Internet,
//! credentials, background reconnect loop or production IRC server.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rusti_client::credential_ref::{CredentialPurpose, CredentialRef, ProtectedCredentialStore};
use rusti_client::ClientConfig;
use rusti_transport_tls::cancel::RegistrationCancellation;
use rusti_transport_tls::{Timeouts, TlsIrcSession, TransportError};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

#[derive(Clone, Copy)]
enum Peer {
    Silent,
    Trickle,
}

fn read_line(tls: &mut StreamOwned<ServerConnection, std::net::TcpStream>) -> bool {
    let mut len = 0;
    loop {
        let mut byte = [0];
        match tls.read(&mut byte) {
            Ok(1) => {
                len += 1;
                if len > 512 {
                    return false;
                }
                if byte[0] == b'\n' {
                    return true;
                }
            }
            _ => return false,
        }
    }
}

fn lab(peer: Peer) -> (SocketAddr, RootCertStore, thread::JoinHandle<bool>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();

    let cfg =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let Ok((tcp, _)) = listener.accept() else {
            return false;
        };
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(2)));
        let Ok(conn) = ServerConnection::new(Arc::new(cfg)) else {
            return false;
        };
        let mut tls = StreamOwned::new(conn, tcp);

        // Both ordinary and SASL registration send three initial lines.
        if !(read_line(&mut tls) && read_line(&mut tls) && read_line(&mut tls)) {
            return false;
        }
        match peer {
            Peer::Silent => thread::sleep(Duration::from_millis(650)),
            Peer::Trickle => {
                // An IRC server sending a slow, unfinished frame must not
                // extend the client's absolute registration deadline.
                for byte in b":irc CAP * LS :sasl=PLAIN" {
                    if tls.write_all(&[*byte]).is_err() || tls.flush().is_err() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(35));
                }
                thread::sleep(Duration::from_millis(150));
            }
        }
        true
    });
    (address, roots, server)
}

fn connect(address: SocketAddr, roots: RootCertStore) -> TlsIrcSession {
    TlsIrcSession::connect_tls(
        &ClientConfig {
            enabled: true,
            server_host: "localhost".to_string(),
            server_port: address.port(),
            tls_required: true,
        },
        address,
        roots,
        Timeouts {
            io: Duration::from_secs(3),
            ..Timeouts::default()
        },
    )
    .expect("synthetic localhost TLS must be valid")
}

struct NeverReadStore(AtomicUsize);
impl ProtectedCredentialStore for NeverReadStore {
    type Error = ();
    fn with_secret<R, F>(&self, _: &CredentialRef, _: F) -> Result<R, Self::Error>
    where
        F: FnOnce(&[u8]) -> R,
    {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("never resolve credentials before a verified SASL challenge")
    }
}

fn credential(port: u16) -> CredentialRef {
    CredentialRef::new(
        "lab_only",
        "localhost",
        port,
        CredentialPurpose::SaslPassword,
    )
    .unwrap()
}

#[test]
fn sasl_silent_peer_times_out_before_three_second_io_limit() {
    let (address, roots, server) = lab(Peer::Silent);
    let mut client = connect(address, roots);
    let store = NeverReadStore(AtomicUsize::new(0));
    let start = Instant::now();
    let result = client.register_sasl_plain(
        "tester",
        "tester",
        "tester",
        &credential(address.port()),
        &store,
        Duration::from_millis(230),
    );
    assert!(
        matches!(result, Err(TransportError::RegistrationTimedOut)),
        "{result:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
    assert!(!client.is_registered());
    assert!(matches!(
        client.send_privmsg("#ops", "no"),
        Err(TransportError::NotRegistered)
    ));
    assert!(server.join().unwrap());
}

#[test]
fn sasl_trickled_partial_frame_cannot_extend_deadline() {
    let (address, roots, server) = lab(Peer::Trickle);
    let mut client = connect(address, roots);
    let store = NeverReadStore(AtomicUsize::new(0));
    let result = client.register_sasl_plain(
        "tester",
        "tester",
        "tester",
        &credential(address.port()),
        &store,
        Duration::from_millis(260),
    );
    assert!(
        matches!(result, Err(TransportError::RegistrationTimedOut)),
        "{result:?}"
    );
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
    assert!(!client.is_registered());
    assert!(server.join().unwrap());
}

#[test]
fn cancelled_sasl_wait_terminates_socket_and_disables_retry() {
    let (address, roots, server) = lab(Peer::Silent);
    let mut client = connect(address, roots);
    let cancel = Arc::new(RegistrationCancellation::new());
    let signal = Arc::clone(&cancel);
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(90));
        signal.cancel();
    });
    let store = NeverReadStore(AtomicUsize::new(0));
    let start = Instant::now();
    let result = client.register_sasl_plain_cancellable(
        "tester",
        "tester",
        "tester",
        &credential(address.port()),
        &store,
        Duration::from_secs(2),
        &cancel,
    );
    worker.join().unwrap();
    assert!(
        matches!(result, Err(TransportError::RegistrationCancelled)),
        "{result:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(store.0.load(Ordering::SeqCst), 0);
    assert!(!client.is_registered());
    assert!(matches!(
        client.register_sasl_plain(
            "tester",
            "tester",
            "tester",
            &credential(address.port()),
            &store,
            Duration::from_secs(1)
        ),
        Err(TransportError::RegistrationAlreadyAttempted)
    ));
    assert!(server.join().unwrap());
}

#[test]
fn ordinary_cap_registration_obeys_same_absolute_deadline() {
    let (address, roots, server) = lab(Peer::Silent);
    let mut client = connect(address, roots);
    let result = client.register_with_capabilities(
        "tester",
        "tester",
        &["message-tags"],
        &[],
        Duration::from_millis(220),
    );
    assert!(
        matches!(result, Err(TransportError::RegistrationTimedOut)),
        "{result:?}"
    );
    assert!(!client.is_registered());
    assert!(matches!(
        client.join("#ops"),
        Err(TransportError::NotRegistered)
    ));
    assert!(server.join().unwrap());
}

#[test]
fn cancelled_ordinary_registration_never_falls_back() {
    let (address, roots, server) = lab(Peer::Silent);
    let mut client = connect(address, roots);
    let cancel = Arc::new(RegistrationCancellation::new());
    let signal = Arc::clone(&cancel);
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(90));
        signal.cancel();
    });
    let result = client.register_with_capabilities_cancellable(
        "tester",
        "tester",
        &[],
        &[],
        Duration::from_secs(2),
        &cancel,
    );
    worker.join().unwrap();
    assert!(
        matches!(result, Err(TransportError::RegistrationCancelled)),
        "{result:?}"
    );
    assert!(!client.is_registered());
    assert!(matches!(
        client.send_privmsg("#ops", "no"),
        Err(TransportError::NotRegistered)
    ));
    assert!(server.join().unwrap());
}

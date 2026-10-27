//! Localhost TLS interoperability only; no Internet, credentials, stored
//! private keys, external IRC servers or production trust roots are contacted.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rusti_client::{ClientConfig, ClientError};
use rusti_proto::FrameError;
use rusti_transport_tls::{Receive, Submission, Timeouts, TlsIrcSession, TransportError};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

fn launch_lab_server(
    sent_data: &'static [u8],
) -> (SocketAddr, RootCertStore, JoinHandle<Option<String>>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).expect("lab certificate");
    let mut trust = RootCertStore::empty();
    trust.add(cert.der().clone()).expect("synthetic trust anchor");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .expect("synthetic server config");
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback");
    let address = listener.local_addr().expect("bound port");
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().ok()?;
        tcp.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
        tcp.set_write_timeout(Some(Duration::from_secs(3))).ok()?;
        let conn = ServerConnection::new(Arc::new(server_config)).ok()?;
        let mut tls = StreamOwned::new(conn, tcp);
        // Sending the synthetic frame also drives the TLS handshake.
        tls.write_all(sent_data).ok()?;
        let mut buf = [0u8; 512];
        let n = tls.read(&mut buf).ok()?;
        String::from_utf8(buf[..n].to_vec()).ok()
    });
    (address, trust, handle)
}

fn cfg(endpoint: SocketAddr, server_host: &str) -> ClientConfig {
    ClientConfig {
        enabled: true,
        server_host: server_host.to_owned(),
        server_port: endpoint.port(),
        tls_required: true,
    }
}

#[test]
fn authenticated_local_tls_supports_bounded_ping_reply_without_registration() {
    let (addr, roots, server) = launch_lab_server(b"PING :synthetic\r\n");
    let mut client =
        TlsIrcSession::connect_tls(&cfg(addr, "localhost"), addr, roots, Timeouts::default())
            .expect("matching certificate trust and name");
    let mut received = Vec::new();
    for _ in 0..6 {
        let outcome = client
            .read_once(|frame| {
                received.push(frame.map(|msg| {
                    (msg.command.to_owned(), msg.params().first().unwrap_or(&"").to_string())
                }));
            })
            .expect("synthetic receive");
        if !received.is_empty() || matches!(outcome, Receive::Closed) {
            break;
        }
    }
    assert_eq!(received, vec![Ok(("PING".into(), "synthetic".into()))]);
    assert!(matches!(
        client.pong("synthetic"),
        Ok(Submission::SubmittedUnconfirmed)
    ));
    let sent = server.join().expect("server completes").expect("server saw line");
    assert!(sent.contains("PONG :synthetic\r\n"));
}

#[test]
fn wrong_certificate_name_fails_closed_before_irc_is_sent() {
    let (addr, roots, server) = launch_lab_server(b"PING :synthetic\r\n");
    let result =
        TlsIrcSession::connect_tls(&cfg(addr, "irc.invalid"), addr, roots, Timeouts::default());
    assert!(result.is_err(), "certificate with only localhost SAN must not authenticate irc.invalid");
    let _ = server.join();
}

#[test]
fn untrusted_certificate_fails_closed() {
    let (addr, _roots, server) = launch_lab_server(b"PING :synthetic\r\n");
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut unrelated = RootCertStore::empty();
    unrelated.add(cert.der().clone()).unwrap();
    let result = TlsIrcSession::connect_tls(
        &cfg(addr, "localhost"), addr, unrelated, Timeouts::default(),
    );
    assert!(result.is_err(), "a different trust root must not authenticate localhost");
    let _ = server.join();
}

#[test]
fn disabled_transport_and_plaintext_downgrade_never_open_a_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let disabled = ClientConfig {
        enabled: false, ..cfg(addr, "localhost")
    };
    assert!(matches!(
        TlsIrcSession::connect_tls(&disabled, addr, RootCertStore::empty(), Timeouts::default()),
        Err(TransportError::Policy(ClientError::Disabled))
    ));
    let plaintext = ClientConfig {
        tls_required: false, ..cfg(addr, "localhost")
    };
    assert!(matches!(
        TlsIrcSession::connect_tls(&plaintext, addr, RootCertStore::empty(), Timeouts::default()),
        Err(TransportError::Policy(ClientError::InsecureTransportForbidden))
    ));
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
fn injection_does_not_enter_tls_output() {
    let (addr, roots, server) = launch_lab_server(b"PING :synthetic\r\n");
    let mut client =
        TlsIrcSession::connect_tls(&cfg(addr, "localhost"), addr, roots, Timeouts::default())
            .unwrap();
    assert!(matches!(
        client.send_privmsg("#lab", "message\r\nOPER root"),
        Err(TransportError::Frame(FrameError::ForbiddenControl))
    ));
    assert!(matches!(
        client.join("#invalid name"),
        Err(TransportError::InvalidIdentifier)
    ));
    assert!(matches!(
        client.send_privmsg("#lab", "safe"),
        Err(TransportError::NotRegistered)
    ));
    // PONG is a safe pre-registration response; regular channel sends are not.
    client.pong("safe").unwrap();
    let sent = server.join().unwrap().unwrap();
    assert_eq!(sent, "PONG :safe\r\n");
}

#[test]
fn wrong_port_or_invalid_timeout_fails_before_socket() {
    let addr: SocketAddr = "127.0.0.1:6697".parse().unwrap();
    let mismatch = cfg("127.0.0.1:7000".parse().unwrap(), "localhost");
    assert!(matches!(
        TlsIrcSession::connect_tls(&mismatch, addr, RootCertStore::empty(), Timeouts::default()),
        Err(TransportError::WrongPort)
    ));
    let bad_time = Timeouts {
        tls_handshake: Duration::from_secs(45),
        ..Timeouts::default()
    };
    assert!(matches!(
        TlsIrcSession::connect_tls(&cfg(addr, "localhost"), addr, RootCertStore::empty(), bad_time),
        Err(TransportError::InvalidTimeouts)
    ));
}

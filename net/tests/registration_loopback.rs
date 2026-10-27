//! In-memory synthetic IRCd protocol script running behind real localhost TLS.
//! No Internet, stored credentials, field devices or outside server contacted.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rcgen::{
    date_time_ymd, CertificateParams, KeyPair,
};
use rusti_client::ClientConfig;
use rusti_proto::cap::CapError;
use rusti_proto::registration::RegistrationError;
use rusti_transport_tls::{Submission, Timeouts, TlsIrcSession, TransportError};
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

#[derive(Clone, Copy)]
enum Script {
    Happy,
    MissingRequired,
    NoCapLegacy,
    PrematureWelcome,
    Revoke,
    Expired,
    Future,
}

fn certificate(
    script: Script,
) -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::CertificateDer<'static>,
    Vec<u8>,
) {
    // A long-lived local CA anchors an individually dated leaf. Trusting an
    // expired self-signed root directly is not a reliable expiry regression.
    let mut ca = CertificateParams::new(vec!["rusti-test-ca.invalid".into()]).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().unwrap();
    let issuer = rcgen::CertifiedIssuer::self_signed(ca, ca_key).unwrap();

    let mut leaf = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    if matches!(script, Script::Expired) {
        leaf.not_before = date_time_ymd(2015, 1, 1);
        leaf.not_after = date_time_ymd(2016, 1, 1);
    }
    if matches!(script, Script::Future) {
        leaf.not_before = date_time_ymd(2099, 1, 1);
        leaf.not_after = date_time_ymd(2100, 1, 1);
    }
    let leaf_key = KeyPair::generate().unwrap();
    let signed = leaf.signed_by(&leaf_key, &issuer).unwrap();
    (
        vec![signed.der().clone(), issuer.der().clone()],
        issuer.der().clone(),
        leaf_key.serialize_der(),
    )
}
fn read_line(tls: &mut StreamOwned<ServerConnection, std::net::TcpStream>) -> Option<String> {
    let mut line = Vec::new();
    loop {
        let mut one = [0u8; 1];
        if tls.read(&mut one).ok()? == 0 {
            return None;
        }
        line.push(one[0]);
        if line.len() > 512 {
            return None;
        }
        if one[0] == b'\n' {
            return String::from_utf8(line).ok();
        }
    }
}

fn start_server(script: Script) -> (SocketAddr, RootCertStore, JoinHandle<Vec<String>>) {
    let (chain, anchor, key) = certificate(script);
    let mut trust = RootCertStore::empty();
    trust.add(anchor).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, PrivatePkcs8KeyDer::from(key).into())
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let mut observed = Vec::new();
        let Ok((tcp, _)) = listener.accept() else { return observed };
        let _ = tcp.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = tcp.set_write_timeout(Some(Duration::from_secs(3)));
        let Ok(server) = ServerConnection::new(Arc::new(cfg)) else { return observed };
        let mut tls = StreamOwned::new(server, tcp);

        // Expired/future certificate is rejected by the client handshake.
        if matches!(script, Script::Expired | Script::Future) {
            let _ = tls.write_all(b"PING :lab\r\n");
            return observed;
        }

        for _ in 0..3 {
            if let Some(line) = read_line(&mut tls) {
                observed.push(line);
            } else {
                return observed;
            }
        }
        if observed[0] != "CAP LS 302\r\n"
            || observed[1] != "NICK tester\r\n"
            || observed[2] != "USER tester 0 * :rusti_rc\r\n"
        {
            return observed;
        }

        match script {
            Script::MissingRequired => {
                let _ = tls.write_all(b":irc CAP * LS :multi-prefix\r\n");
                return observed;
            }
            Script::NoCapLegacy => {
                let _ = tls.write_all(
                    b":irc 421 tester CAP :Unknown command\r\n:irc 001 tester :Welcome\r\n",
                );
                return observed;
            }
            _ => {}
        }

        // Exercise genuine CAP 302 multiline LS handling.
        if tls.write_all(b":irc CAP * LS * :multi-prefix\r\n").is_err()
            || tls.write_all(b":irc CAP * LS :message-tags server-time\r\n").is_err()
        {
            return observed;
        }

        let Some(req) = read_line(&mut tls) else { return observed };
        observed.push(req);
        if observed[3] != "CAP REQ :message-tags server-time\r\n" {
            return observed;
        }

        if matches!(script, Script::PrematureWelcome) {
            let _ = tls.write_all(
                b":irc CAP tester ACK :server-time message-tags\r\n:irc 001 tester :Early\r\n",
            );
            return observed;
        }

        if tls.write_all(b":irc CAP tester ACK :server-time message-tags\r\n").is_err() {
            return observed;
        }
        let Some(end) = read_line(&mut tls) else { return observed };
        observed.push(end);
        if observed[4] != "CAP END\r\n" {
            return observed;
        }
        if tls.write_all(b":irc 001 tester :Welcome\r\n").is_err() {
            return observed;
        }

        if matches!(script, Script::Revoke) {
            let Some(join) = read_line(&mut tls) else { return observed };
            observed.push(join);
            let _ = tls.write_all(b":irc CAP tester DEL :message-tags\r\n");
            // Give client an opportunity to read before dropping connection.
            let _ = tls.flush();
            thread::sleep(Duration::from_millis(200));
            return observed;
        }

        for _ in 0..2 {
            let Some(line) = read_line(&mut tls) else { return observed };
            observed.push(line);
        }
        observed
    });
    (addr, trust, worker)
}

fn connect(addr: SocketAddr, trust: RootCertStore) -> TlsIrcSession {
    TlsIrcSession::connect_tls(
        &ClientConfig {
            enabled: true,
            server_host: "localhost".into(),
            server_port: addr.port(),
            tls_required: true,
        },
        addr,
        trust,
        Timeouts::default(),
    )
    .expect("valid localhost TLS identity")
}

#[test]
fn full_cap_and_welcome_then_join_and_channel_text() {
    let (addr, trust, server) = start_server(Script::Happy);
    let mut client = connect(addr, trust);
    assert!(!client.is_registered());
    assert!(matches!(client.send_privmsg("#lab", "premature"), Err(TransportError::NotRegistered)));

    client
        .register_with_capabilities(
            "tester",
            "tester",
            &["message-tags"],
            &["server-time"],
            Duration::from_secs(4),
        )
        .expect("CAP and numeric 001 registration");
    assert!(client.is_registered());
    assert!(matches!(client.join("#lab"), Ok(Submission::SubmittedUnconfirmed)));
    assert!(matches!(
        client.send_privmsg("#lab", "hello"),
        Ok(Submission::SubmittedUnconfirmed)
    ));
    let lines = server.join().unwrap();
    assert_eq!(
        lines,
        vec![
            "CAP LS 302\r\n", "NICK tester\r\n",
            "USER tester 0 * :rusti_rc\r\n",
            "CAP REQ :message-tags server-time\r\n", "CAP END\r\n",
            "JOIN #lab\r\n", "PRIVMSG #lab :hello\r\n",
        ]
    );
}

#[test]
fn missing_required_cap_fails_closed() {
    let (addr, trust, server) = start_server(Script::MissingRequired);
    let mut client = connect(addr, trust);
    let error = client.register_with_capabilities(
        "tester", "tester", &["message-tags"], &[],
        Duration::from_secs(4),
    );
    assert!(matches!(
        error,
        Err(TransportError::Registration(RegistrationError::Capability(CapError::MissingRequired)))
    ));
    assert!(!client.is_registered());
    assert!(matches!(client.send_privmsg("#lab", "x"), Err(TransportError::NotRegistered)));
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn legacy_server_only_when_no_required_capability() {
    let (addr, trust, server) = start_server(Script::NoCapLegacy);
    let mut client = connect(addr, trust);
    client.register_with_capabilities(
        "tester", "tester", &[], &["multi-prefix"], Duration::from_secs(4),
    ).expect("explicit legacy IRC fallback without mandatory capability");
    assert!(client.is_registered());
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn premature_welcome_does_not_skip_cap_end() {
    let (addr, trust, server) = start_server(Script::PrematureWelcome);
    let mut client = connect(addr, trust);
    let error = client.register_with_capabilities(
        "tester", "tester", &["message-tags"], &["server-time"],
        Duration::from_secs(4),
    );
    assert!(matches!(
        error,
        Err(TransportError::Registration(RegistrationError::UnexpectedWelcome))
    ));
    assert!(!client.is_registered());
    assert_eq!(server.join().unwrap().len(), 4);
}

#[test]
fn mandatory_capability_revocation_blocks_further_channel_sends() {
    let (addr, trust, server) = start_server(Script::Revoke);
    let mut client = connect(addr, trust);
    client.register_with_capabilities(
        "tester", "tester", &["message-tags"], &["server-time"],
        Duration::from_secs(4),
    ).unwrap();
    client.join("#lab").unwrap();

    let mut revocation_seen = false;
    for _ in 0..6 {
        match client.read_once(|_| {}) {
            Err(TransportError::Registration(RegistrationError::Capability(
                CapError::RequiredCapabilityRemoved,
            ))) => {
                revocation_seen = true;
                break;
            }
            Ok(_) => {}
            Err(err) => panic!("unexpected error: {err:?}"),
        }
    }
    assert!(revocation_seen, "required CAP DEL must be treated as revocation");
    assert!(!client.is_registered());
    assert!(matches!(
        client.send_privmsg("#lab", "should not send"),
        Err(TransportError::NotRegistered)
    ));
    assert_eq!(server.join().unwrap().len(), 6);
}

#[test]
fn expired_tls_certificate_is_rejected_before_irc_registration() {
    let (addr, trust, server) = start_server(Script::Expired);
    let result = TlsIrcSession::connect_tls(
        &ClientConfig {
            enabled: true,
            server_host: "localhost".into(),
            server_port: addr.port(),
            tls_required: true,
        },
        addr,
        trust,
        Timeouts::default(),
    );
    assert!(result.is_err(), "expired chain must not authenticate");
    assert!(server.join().unwrap().is_empty());
}

#[test]
fn future_tls_certificate_is_rejected_before_irc_registration() {
    let (addr, trust, server) = start_server(Script::Future);
    let result = TlsIrcSession::connect_tls(
        &ClientConfig {
            enabled: true,
            server_host: "localhost".into(),
            server_port: addr.port(),
            tls_required: true,
        },
        addr,
        trust,
        Timeouts::default(),
    );
    assert!(result.is_err(), "not-yet-valid chain must not authenticate");
    assert!(server.join().unwrap().is_empty());
}

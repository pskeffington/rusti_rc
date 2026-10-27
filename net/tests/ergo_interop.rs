//! Opt-in interoperability test against independently implemented Ergo IRCd.
//!
//! This test is ignored during ordinary Cargo test runs. CI explicitly
//! provisions a throwaway local Docker IRCd and a locally generated TLS CA.
//! Do not point it at a production server or use real operator credentials.
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::net::SocketAddr;
use std::time::Duration;

use rusti_client::ClientConfig;
use rusti_proto::ParsedMessage;
use rusti_transport_tls::{Receive, Submission, Timeouts, TlsIrcSession};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;

const CHANNEL: &str = "#rusti-interop";
const SENTENCE: &str = "rusti_rc independent ircd interop synthetic hello";

fn test_connection(nickname: &str) -> TlsIrcSession {
    let addr: SocketAddr = env::var("RUSTI_ERGO_ADDR")
        .expect("RUSTI_ERGO_ADDR is required in the isolated CI job")
        .parse()
        .expect("valid endpoint");
    let cert_path = env::var("RUSTI_ERGO_CA_DER")
        .expect("RUSTI_ERGO_CA_DER must point to a throwaway test CA");
    let cert = fs::read(cert_path).expect("read explicit test-only CA DER");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert))
        .expect("test CA must parse");

    let mut connection = TlsIrcSession::connect_tls(
        &ClientConfig {
            enabled: true,
            server_host: "localhost".into(),
            server_port: addr.port(),
            tls_required: true,
        },
        addr,
        roots,
        Timeouts {
            io: Duration::from_millis(400),
            ..Timeouts::default()
        },
    )
    .expect("exact TLS root and hostname must authenticate");

    connection
        .register_with_capabilities(
            nickname,
            nickname,
            &["message-tags"],
            &["server-time"],
            Duration::from_secs(10),
        )
        .expect("independent IRCd must complete CAP 302 and welcome");
    assert!(connection.is_registered());
    connection
}

fn until<F>(connection: &mut TlsIrcSession, mut predicate: F) -> bool
where
    F: FnMut(&ParsedMessage<'_>) -> bool,
{
    for _ in 0..30 {
        let mut found = false;
        let status = connection
            .read_once(|event| {
                if let Ok(message) = event {
                    if predicate(&message) {
                        found = true;
                    }
                }
            })
            .expect("server must not send invalid IRC frames or fail transport");
        if found {
            return true;
        }
        if status == Receive::Closed {
            panic!("independent server closed the authenticated session");
        }
    }
    false
}

fn joined_channel(connection: &mut TlsIrcSession) -> bool {
    until(connection, |message| {
        message.command == "366" && message.params().contains(&CHANNEL)
    })
}

#[test]
#[ignore = "requires explicit throwaway local Ergo IRCd with signed test TLS certificate"]
fn registered_clients_join_and_exchange_plain_channel_text() {
    let mut alice = test_connection("rustialice");
    let mut bob = test_connection("rustibob");

    assert_eq!(
        alice.join(CHANNEL).unwrap(),
        Submission::SubmittedUnconfirmed
    );
    assert!(joined_channel(&mut alice), "Alice never received end-of-NAMES");
    assert_eq!(bob.join(CHANNEL).unwrap(), Submission::SubmittedUnconfirmed);
    assert!(joined_channel(&mut bob), "Bob never received end-of-NAMES");

    assert_eq!(
        alice.send_privmsg(CHANNEL, SENTENCE).unwrap(),
        Submission::SubmittedUnconfirmed
    );
    assert!(
        until(&mut bob, |message| {
            message.command.eq_ignore_ascii_case("PRIVMSG")
                && message.params().len() == 2
                && message.params()[0] == CHANNEL
                && message.params()[1] == SENTENCE
                && message
                    .prefix
                    .map(|prefix| prefix.starts_with("rustialice!"))
                    .unwrap_or(false)
        }),
        "Independent IRCd did not route the expected synthetic PRIVMSG"
    );
}

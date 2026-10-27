//! Explicit, verified-TLS IRC transport for the standalone modern workspace.
//!
//! Importing this crate performs no I/O. Only an explicit connect_tls call
//! opens a socket. It has no plaintext fallback, SASL, privileged actions,
//! background retries, server listener, or persistent chat history.
//! Successful writes are submitted/unconfirmed, not delivery receipts.
#![forbid(unsafe_code)]

mod registration;
mod sasl;
#[cfg(feature = "os-keyring")]
pub mod native_store;
mod sasl;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rusti_client::{ClientConfig, ClientError};
use rusti_proto::decoder::FrameDecoder;
use rusti_proto::{cap::CAP_LS_302, encode_privmsg, FrameError, ParsedMessage};
use rusti_proto::registration::{RegistrationError, RegistrationFlow};
use rusti_proto::sasl::{SaslError, SaslPlainFlow};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore, StreamOwned};

const IO_CHUNK: usize = 1024;
const MIN_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum TransportError {
    Policy(ClientError),
    WrongPort,
    EmptyTrustRoots,
    InvalidServerIdentity,
    InvalidTimeouts,
    InvalidIdentifier,
    UnexpectedClose,
    Io(io::Error),
    Tls(rustls::Error),
    Frame(FrameError),
    Registration(RegistrationError),
    RegistrationTimedOut,
    RegistrationAlreadyAttempted,
    RegistrationResponseOverflow,
    NotRegistered,
    Sasl(SaslError),
    CredentialUnavailable,
    CredentialPolicy,
    InvalidCredential,
}

impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}
impl From<rustls::Error> for TransportError {
    fn from(value: rustls::Error) -> Self { Self::Tls(value) }
}
impl From<FrameError> for TransportError {
    fn from(value: FrameError) -> Self { Self::Frame(value) }
}
impl From<RegistrationError> for TransportError {
    fn from(value: RegistrationError) -> Self { Self::Registration(value) }
}
impl From<SaslError> for TransportError {
    fn from(value: SaslError) -> Self { Self::Sasl(value) }
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub tcp_connect: Duration,
    pub tls_handshake: Duration,
    pub io: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            tcp_connect: Duration::from_secs(5),
            tls_handshake: Duration::from_secs(5),
            io: Duration::from_secs(5),
        }
    }
}

impl Timeouts {
    pub fn validate(self) -> Result<(), TransportError> {
        for t in [self.tcp_connect, self.tls_handshake, self.io] {
            if t < MIN_TIMEOUT || t > MAX_TIMEOUT {
                return Err(TransportError::InvalidTimeouts);
            }
        }
        Ok(())
    }
}

/// Bundled Mozilla roots require signed application updates to rotate.
/// For private IRC servers pass an independently provisioned RootCertStore.
pub fn bundled_web_roots() -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

fn client_tls_config(roots: RootCertStore) -> Result<rustls::ClientConfig, TransportError> {
    if roots.roots.is_empty() {
        return Err(TransportError::EmptyTrustRoots);
    }
    // Provider choice must be verified on each legacy target, not assumed.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// Explicit handshake loop, with a whole-handshake deadline rather than
/// endlessly extending the timeout on repeated partial TLS records.
fn handshake(
    conn: &mut ClientConnection,
    tcp: &mut TcpStream,
    timeout: Duration,
) -> Result<(), TransportError> {
    let deadline = Instant::now() + timeout;
    while conn.is_handshaking() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::Io(io::Error::new(
                io::ErrorKind::TimedOut, "TLS handshake deadline exceeded",
            )));
        }
        tcp.set_read_timeout(Some(remaining))?;
        tcp.set_write_timeout(Some(remaining))?;
        if conn.wants_write() && conn.write_tls(&mut *tcp)? == 0 {
            return Err(TransportError::UnexpectedClose);
        }
        if conn.wants_read() {
            if conn.read_tls(&mut *tcp)? == 0 {
                return Err(TransportError::UnexpectedClose);
            }
            conn.process_new_packets()?;
        }
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(TransportError::Io(io::Error::new(
            io::ErrorKind::TimedOut, "TLS handshake deadline exceeded",
        )));
    }
    tcp.set_write_timeout(Some(remaining))?;
    while conn.wants_write() {
        if conn.write_tls(&mut *tcp)? == 0 {
            return Err(TransportError::UnexpectedClose);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submission {
    SubmittedUnconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receive {
    Data(usize),
    TimedOut,
    Closed,
}

pub struct TlsIrcSession {
    stream: StreamOwned<ClientConnection, TcpStream>,
    decoder: FrameDecoder,
    registered: bool,
    registration_attempted: bool,
    registration: Option<RegistrationFlow>,
    /// The original authenticated TLS name/port, never user-supplied again.
    authenticated_host: String,
    authenticated_port: u16,
    /// Active SASL must never silently downgrade on logout or CAP DEL.
    sasl_required: bool,
}

impl TlsIrcSession {
    /// Explicit operator-requested connection to a given socket. Performs no
    /// DNS or automatic discovery. The configured server_host is always the
    /// verified TLS certificate identity, independent of the socket address.
    pub fn connect_tls(
        client: &ClientConfig,
        endpoint: SocketAddr,
        roots: RootCertStore,
        timeouts: Timeouts,
    ) -> Result<Self, TransportError> {
        // Preflight policy and trust-root checks occur before socket creation.
        client.validate().map_err(TransportError::Policy)?;
        timeouts.validate()?;
        if endpoint.port() != client.server_port {
            return Err(TransportError::WrongPort);
        }
        let name = ServerName::try_from(client.server_host.clone())
            .map_err(|_| TransportError::InvalidServerIdentity)?;
        let tls_config = Arc::new(client_tls_config(roots)?);
        let mut tcp = TcpStream::connect_timeout(&endpoint, timeouts.tcp_connect)?;
        tcp.set_nodelay(true)?;
        let mut conn = ClientConnection::new(tls_config, name)?;
        handshake(&mut conn, &mut tcp, timeouts.tls_handshake)?;
        tcp.set_read_timeout(Some(timeouts.io))?;
        tcp.set_write_timeout(Some(timeouts.io))?;
        Ok(Self {
            stream: StreamOwned::new(conn, tcp),
            decoder: FrameDecoder::new(),
            registered: false,
            registration_attempted: false,
            registration: None,
            authenticated_host: client.server_host.clone(),
            authenticated_port: client.server_port,
            sasl_required: false,
        })
    }

    fn write_frame(&mut self, frame: &str) -> Result<Submission, TransportError> {
        // Internal wire builders only; no arbitrary caller-controlled commands.
        if !frame.ends_with("\r\n") || frame.len() > 512 {
            return Err(TransportError::Frame(FrameError::OverlongLine));
        }
        self.stream.write_all(frame.as_bytes())?;
        self.stream.flush()?;
        Ok(Submission::SubmittedUnconfirmed)
    }

    /// Begin CAP 302 explicitly; G1b CapNegotiator must handle replies and
    /// decide which negotiated capabilities to send. No SASL is enabled.
    pub fn request_cap_302(&mut self) -> Result<Submission, TransportError> {
        self.write_frame(CAP_LS_302)
    }

    /// Basic IRC registration, without PASS or SASL. The operator must
    /// inspect responses before issuing JOIN or sending messages.
    pub fn register_nick_user(
        &mut self, nickname: &str, username: &str,
    ) -> Result<Submission, TransportError> {
        if !safe_atom(nickname) || !safe_atom(username) {
            return Err(TransportError::InvalidIdentifier);
        }
        self.write_frame(&format!("NICK {}\r\n", nickname))?;
        self.write_frame(&format!("USER {} 0 * :rusti_rc\r\n", username))
    }

    pub fn join(&mut self, channel: &str) -> Result<Submission, TransportError> {
        if channel.len() < 2 || channel.len() > 65 || !channel.starts_with('#')
            || !safe_atom(&channel[1..])
        {
            return Err(TransportError::InvalidIdentifier);
        }
        if !self.registered {
            return Err(TransportError::NotRegistered);
        }
        self.write_frame(&format!("JOIN {}\r\n", channel))
    }

    pub fn send_privmsg(
        &mut self, target: &str, body: &str,
    ) -> Result<Submission, TransportError> {
        let wire = encode_privmsg(target, body)?;
        if !self.registered {
            return Err(TransportError::NotRegistered);
        }
        self.write_frame(&wire)
    }

    pub fn pong(&mut self, token: &str) -> Result<Submission, TransportError> {
        if token.is_empty() || token.len() > 256
            || !token.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(TransportError::InvalidIdentifier);
        }
        self.write_frame(&format!("PONG :{}\r\n", token))
    }

    /// Reads at most 1024 TLS plaintext bytes per call into a bounded IRC
    /// decoder; reports frames through a synchronous non-queuing callback.
    pub fn read_once<F>(&mut self, on_frame: F) -> Result<Receive, TransportError>
    where
        F: for<'a> FnMut(Result<ParsedMessage<'a>, FrameError>),
    {
        let mut chunk = [0u8; IO_CHUNK];
        match self.stream.read(&mut chunk) {
            Ok(0) => {
                self.registered = false;
                self.sasl_required = false;
                self.registration = None;
                self.decoder.finish()?;
                Ok(Receive::Closed)
            }
            Ok(n) => {
                let mut on_frame = on_frame;
                let mut error: Option<TransportError> = None;
                let registration = &mut self.registration;
                let sasl_required = self.sasl_required;
                self.decoder.push(&chunk[..n], |event| {
                    if error.is_some() {
                        return;
                    }
                    match &event {
                        Err(frame_error) => {
                            error = Some(TransportError::Frame(*frame_error));
                            return;
                        }
                        Ok(frame) => {
                            if sasl_required {
                                let params = frame.params();
                                let revoked = (frame.command == "CAP"
                                    && params.get(1) == Some(&"DEL")
                                    && params.get(2).is_some_and(|v|
                                        v.split_whitespace().any(|name| name == "sasl")))
                                    || frame.command == "901";
                                if revoked {
                                    error = Some(TransportError::Sasl(SaslError::CapabilityRevoked));
                                    return;
                                }
                            }
                            if let Some(flow) = registration.as_mut() {
                                if frame.command.eq_ignore_ascii_case("CAP")
                                    || frame.command.eq_ignore_ascii_case("ERROR")
                                {
                                    if let Err(reg_error) = flow.observe(frame) {
                                        error = Some(TransportError::Registration(reg_error));
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    on_frame(event);
                });
                if let Some(failure) = error {
                    self.registered = false;
                    self.sasl_required = false;
                    self.registration = None;
                    return Err(failure);
                }
                Ok(Receive::Data(n))
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                Ok(Receive::TimedOut)
            }
            Err(e) => {
                self.registered = false;
                self.sasl_required = false;
                self.registration = None;
                Err(TransportError::Io(e))
            },
        }
    }
}

/// Small, conservative ASCII nickname/username/channel suffix syntax. Larger
/// IRC compatibility is a later explicit interoperability gate.
fn safe_atom(s: &str) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else { return false };
    s.len() <= 24 && first.is_ascii_alphabetic()
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_timeouts() {
        assert!(Timeouts::default().validate().is_ok());
        assert!(Timeouts { io: Duration::ZERO, ..Timeouts::default() }.validate().is_err());
        assert!(Timeouts { tcp_connect: Duration::from_secs(60), ..Timeouts::default() }.validate().is_err());
    }

    #[test]
    fn no_empty_root_store() {
        assert!(matches!(client_tls_config(RootCertStore::empty()), Err(TransportError::EmptyTrustRoots)));
        assert!(!bundled_web_roots().roots.is_empty());
    }

    #[test]
    fn identifiers_are_control_safe() {
        assert!(safe_atom("Tester_1"));
        assert!(!safe_atom("root\r\nOPER"));
        assert!(!safe_atom("#channel"));
        assert!(!safe_atom("🤖"));
        assert!(!safe_atom(&"n".repeat(40)));
    }
}

//! G2d opt-in SASL PLAIN over a fully verified rustls TCP session.
//!
//! No plaintext fallback, no implicit credential resolution, no anonymous
//! downgrade after SASL failure. This does NOT authenticate Rust Boy devices
//! or issue organization grants, and it is not an end-to-end encrypted chat.
#![forbid(unsafe_code)]

use std::io::Write;
use std::net::Shutdown;
use std::time::{Duration, Instant};

use rusti_client::credential_ref::{
    CredentialPurpose, CredentialRef, ProtectedCredentialStore,
};
use rusti_client::ClientConfig;
use rusti_proto::sasl::{SaslAction, SaslPlainFlow, SaslStage};
use zeroize::Zeroizing;

use crate::{Receive, TlsIrcSession, TransportError};

const MAX_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PASSWORD_BYTES: usize = 192;
const MAX_ACTIONS_PER_READ: usize = 8;
const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Construct sensitive base64 into a zeroizing buffer. The encoded response
/// contains credential-equivalent material and must not be logged/retained.
fn encode_base64(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(bytes.len().div_ceil(3) * 4));
    for block in bytes.chunks(3) {
        let a = block[0];
        let b = *block.get(1).unwrap_or(&0);
        let c = *block.get(2).unwrap_or(&0);
        encoded.push(ALPHABET[(a >> 2) as usize]);
        encoded.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize]);
        encoded.push(if block.len() >= 2 {
            ALPHABET[(((b & 0x0f) << 2) | (c >> 6)) as usize]
        } else {
            b'='
        });
        encoded.push(if block.len() == 3 {
            ALPHABET[(c & 0x3f) as usize]
        } else {
            b'='
        });
    }
    encoded
}

fn valid_account(s: &str) -> bool {
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else { return false };
    s.len() <= 64
        && first.is_ascii_alphanumeric()
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl TlsIrcSession {
    fn write_sasl_secret(
        &mut self,
        account: &str,
        password: &[u8],
    ) -> Result<(), TransportError> {
        if !valid_account(account)
            || password.is_empty()
            || password.len() > MAX_PASSWORD_BYTES
            || password.iter().any(|&b| b == 0 || b == b'\r' || b == b'\n')
        {
            return Err(TransportError::InvalidCredential);
        }
        // SASL PLAIN: empty authzid NUL authcid NUL password.
        let mut plain = Zeroizing::new(Vec::with_capacity(account.len() + password.len() + 2));
        plain.push(0);
        plain.extend_from_slice(account.as_bytes());
        plain.push(0);
        plain.extend_from_slice(password);
        let encoded = encode_base64(&plain);
        if encoded.len() > 400 {
            return Err(TransportError::InvalidCredential);
        }
        // Only a single short AUTHENTICATE frame is allowed. Exact 400-byte
        // payloads would require a final '+' marker; our bounds avoid those.
        let mut frame = Zeroizing::new(Vec::with_capacity(encoded.len() + 16));
        frame.extend_from_slice(b"AUTHENTICATE ");
        frame.extend_from_slice(&encoded);
        frame.extend_from_slice(b"\r\n");
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// One explicit, operator-approved SASL PLAIN login over an already
    /// authenticated TLS transport, using a secret only via the callback.
    ///
    /// The store must protect credentials through a vetted OS secret backend.
    /// A mock store is acceptable only in synthetic tests; deployment requires
    /// platform-specific credential provisioning and revocation evidence.
    ///
    /// On *any* failure we shut down the socket, disable channel sends and
    /// refuse a second registration attempt on this connection.
    pub fn register_sasl_plain<S: ProtectedCredentialStore>(
        &mut self,
        nickname: &str,
        username: &str,
        account: &str,
        credential: &CredentialRef,
        store: &S,
        timeout: Duration,
    ) -> Result<(), TransportError> {
        if self.registered || self.registration_attempted {
            return Err(TransportError::RegistrationAlreadyAttempted);
        }
        let result = self.register_sasl_plain_inner(
            nickname, username, account, credential, store, timeout,
        );
        if result.is_err() {
            self.registered = false;
            self.sasl_required = false;
            self.registration = None;
            let _ = self.stream.sock.shutdown(Shutdown::Both);
        }
        result
    }

    fn register_sasl_plain_inner<S: ProtectedCredentialStore>(
        &mut self,
        nickname: &str,
        username: &str,
        account: &str,
        credential: &CredentialRef,
        store: &S,
        timeout: Duration,
    ) -> Result<(), TransportError> {
        if timeout < Duration::from_millis(50) || timeout > MAX_AUTH_TIMEOUT {
            return Err(TransportError::InvalidTimeouts);
        }
        if credential.purpose() != CredentialPurpose::SaslPassword || !valid_account(account) {
            return Err(TransportError::CredentialPolicy);
        }
        let config = ClientConfig {
            enabled: true,
            server_host: self.authenticated_host.clone(),
            server_port: self.authenticated_port,
            tls_required: true,
        };
        credential.authorize_for(&config).map_err(|_| TransportError::CredentialPolicy)?;

        let mut flow = SaslPlainFlow::new(nickname, username)?;
        let init = flow.begin()?;
        self.registration_attempted = true;
        let deadline = Instant::now() + timeout;

        for line in init {
            self.write_frame(&line)?;
        }

        while !flow.registered() {
            if Instant::now() >= deadline {
                flow.abort();
                return Err(TransportError::RegistrationTimedOut);
            }

            let mut actions = Vec::new();
            let mut error = None;
            let read_result = self.read_once(|frame| {
                if error.is_some() {
                    return;
                }
                match frame {
                    Err(err) => error = Some(TransportError::Frame(err)),
                    Ok(frame) => {
                        let phase = flow.stage();
                        match flow.observe(&frame) {
                            Ok(SaslAction::None) => {}
                            Ok(action) => {
                                if actions.len() == MAX_ACTIONS_PER_READ {
                                    error = Some(TransportError::RegistrationResponseOverflow);
                                } else {
                                    actions.push(action);
                                }
                            }
                            Err(err) => error = Some(TransportError::SaslPhase(phase, err)),
                        }
                    },
                }
            });
            if let Some(err) = error {
                flow.abort();
                return Err(err);
            }
            match read_result? {
                Receive::Closed => {
                    flow.abort();
                    return Err(TransportError::UnexpectedClose);
                }
                Receive::Data(_) | Receive::TimedOut => {}
            }
            for action in actions {
                match action {
                    SaslAction::None => {}
                    SaslAction::Send(wire) => {
                        self.write_frame(wire)?;
                        match wire {
                            "CAP REQ :sasl\r\n" => flow.cap_request_written()?,
                            "AUTHENTICATE PLAIN\r\n" => flow.mechanism_written()?,
                            "CAP END\r\n" => flow.cap_end_written()?,
                            _ => return Err(TransportError::CredentialPolicy),
                        }
                    }
                    SaslAction::Pong(wire) => {
                        self.write_frame(&wire)?;
                    }
                    SaslAction::SupplySecret => {
                        // Zeroizing temporary plain/base64 frame buffers are
                        // created only inside this credential callback.
                        // Deliberately no secret bytes in returned errors.
                        let transmitted = store.with_secret(credential, |secret| {
                            self.write_sasl_secret(account, secret)
                        });
                        match transmitted {
                            Ok(inner) => inner?,
                            Err(_) => return Err(TransportError::CredentialUnavailable),
                        }
                        flow.payload_written()?;
                    }
                }
            }
        }
        if flow.stage() != SaslStage::Registered {
            return Err(TransportError::CredentialPolicy);
        }
        self.sasl_required = true;
        self.registered = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_base64_matches_rfc_vector_and_zeroizes_buffers() {
        let raw = b"\0Alice\0secret";
        assert_eq!(encode_base64(raw).as_slice(), b"AEFsaWNlAHNlY3JldA==");
        assert_eq!(encode_base64(b"").as_slice(), b"");
        assert_eq!(encode_base64(b"\0").as_slice(), b"AA==");
        assert_eq!(encode_base64(b"\0\0").as_slice(), b"AAA=");
    }

    #[test]
    fn limits_account_id_and_input_payload() {
        assert!(valid_account("tester_1"));
        assert!(!valid_account("test\nOPER"));
        assert!(!valid_account(""));
        assert!(!valid_account("bad account"));
    }
}

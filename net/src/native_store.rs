//! Optional OS-managed credential storage for desktop builds.
//!
//! Uses macOS Keychain / Windows Credential Manager only when the
//! os-keyring feature is explicitly enabled. Unsupported platforms,
//! including headless Linux, fail closed: no mock/file/env fallback.
//!
//! All I/O is blocking and must run in an operator-authorized worker context.
//! Secrets are never passed via argv or environment variables.
#![forbid(unsafe_code)]

use rusti_client::credential_ref::{
    CredentialPurpose, CredentialRef, ProtectedCredentialStore,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeStoreError {
    UnsupportedPlatform,
    OperatorApprovalRequired,
    WrongCredentialPurpose,
    InvalidSecret,
    StoreUnavailable,
}

pub struct NativeOsCredentialStore;

impl NativeOsCredentialStore {
    pub fn new() -> Self {
        Self
    }

    fn validate_ref(&self, credential: &CredentialRef) -> Result<(), NativeStoreError> {
        if credential.purpose() != CredentialPurpose::SaslPassword {
            return Err(NativeStoreError::WrongCredentialPurpose);
        }
        Ok(())
    }

    /// Explicit provisioning/rotation. The caller must obtain consent in a
    /// trusted local UI and supply bytes directly, not via CLI argv or env.
    /// This operation is not invoked by the IRC client on its own.
    pub fn provision(
        &self,
        credential: &CredentialRef,
        secret: &[u8],
        operator_approved: bool,
    ) -> Result<(), NativeStoreError> {
        if !operator_approved {
            return Err(NativeStoreError::OperatorApprovalRequired);
        }
        self.validate_ref(credential)?;
        if secret.is_empty()
            || secret.len() > 192
            || secret.iter().any(|&b| b == 0 || b == b'\r' || b == b'\n')
        {
            return Err(NativeStoreError::InvalidSecret);
        }
        write_native(credential, secret)
    }

    pub fn revoke(
        &self,
        credential: &CredentialRef,
        operator_approved: bool,
    ) -> Result<(), NativeStoreError> {
        if !operator_approved {
            return Err(NativeStoreError::OperatorApprovalRequired);
        }
        self.validate_ref(credential)?;
        delete_native(credential)
    }
}

impl Default for NativeOsCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtectedCredentialStore for NativeOsCredentialStore {
    type Error = NativeStoreError;

    fn with_secret<R, F>(
        &self,
        reference: &CredentialRef,
        use_secret: F,
    ) -> Result<R, Self::Error>
    where
        F: FnOnce(&[u8]) -> R,
    {
        self.validate_ref(reference)?;
        // The native backend may prompt for unlock; run on worker context.
        let material = Zeroizing::new(read_native(reference)?);
        Ok(use_secret(&material))
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn item(credential: &CredentialRef) -> Result<keyring::Entry, NativeStoreError> {
    // Credentials are bound to server *and exact port*. The opaque item key
    // is provided by operator onboarding; never expose the service ID in logs.
    let service = format!(
        "org.rusti_rc.irc.sasl.{}.{}",
        credential.server_identity(),
        credential.server_port(),
    );
    keyring::Entry::new(&service, credential.store_item_id())
        .map_err(|_| NativeStoreError::StoreUnavailable)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn write_native(credential: &CredentialRef, secret: &[u8]) -> Result<(), NativeStoreError> {
    item(credential)?
        .set_secret(secret)
        .map_err(|_| NativeStoreError::StoreUnavailable)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn read_native(credential: &CredentialRef) -> Result<Vec<u8>, NativeStoreError> {
    item(credential)?
        .get_secret()
        .map_err(|_| NativeStoreError::StoreUnavailable)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn delete_native(credential: &CredentialRef) -> Result<(), NativeStoreError> {
    item(credential)?
        .delete_credential()
        .map_err(|_| NativeStoreError::StoreUnavailable)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn write_native(_credential: &CredentialRef, _secret: &[u8]) -> Result<(), NativeStoreError> {
    Err(NativeStoreError::UnsupportedPlatform)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn read_native(_credential: &CredentialRef) -> Result<Vec<u8>, NativeStoreError> {
    Err(NativeStoreError::UnsupportedPlatform)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn delete_native(_credential: &CredentialRef) -> Result<(), NativeStoreError> {
    Err(NativeStoreError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> CredentialRef {
        CredentialRef::new(
            "operator_auth",
            "irc.example.org",
            6697,
            CredentialPurpose::SaslPassword,
        ).unwrap()
    }

    #[test]
    fn never_provisions_without_explicit_approval() {
        let store = NativeOsCredentialStore::new();
        assert_eq!(
            store.provision(&reference(), b"synthetic-password", false),
            Err(NativeStoreError::OperatorApprovalRequired),
        );
        assert_eq!(
            store.revoke(&reference(), false),
            Err(NativeStoreError::OperatorApprovalRequired),
        );
    }

    #[test]
    fn rejects_unsafe_secret_before_touching_keychain() {
        let store = NativeOsCredentialStore::new();
        for secret in [&b""[..], &b"abc\n123"[..], &b"abc\0xyz"[..]] {
            assert_eq!(
                store.provision(&reference(), secret, true),
                Err(NativeStoreError::InvalidSecret)
            );
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn unsupported_headless_host_fails_closed_without_mock_backend() {
        let store = NativeOsCredentialStore::new();
        assert_eq!(
            store.provision(&reference(), b"synthetic", true),
            Err(NativeStoreError::UnsupportedPlatform),
        );
        let result = store.with_secret(&reference(), |_| panic!("must never fetch"));
        assert_eq!(result, Err(NativeStoreError::UnsupportedPlatform));
    }
}

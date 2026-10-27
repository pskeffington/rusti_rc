//! Deliberately ignored, interactive macOS/Windows native keychain lifecycle QA.
//!
//! This is a manual, synthetic-only test and is NOT run by public CI.
//! It mutates an isolated test keychain entry scoped to this process.
//! No deployed operator credential or real IRC account is read.
#![forbid(unsafe_code)]
#![cfg(all(feature = "os-keyring", any(target_os = "macos", target_os = "windows")))]

use std::time::{SystemTime, UNIX_EPOCH};

use rusti_client::credential_ref::{
    CredentialPurpose, CredentialRef, ProtectedCredentialStore,
};
use rusti_transport_tls::native_store::NativeOsCredentialStore;

struct Cleanup {
    reference: CredentialRef,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = NativeOsCredentialStore::new().revoke(&self.reference, true);
    }
}

#[test]
#[ignore = "requires explicit local approval and an unlocked desktop OS keychain"]
fn isolated_native_store_provision_rotate_revoke() {
    // This flag authorizes only the synthetic test entry. It is not a password
    // or a substitute for UI identity, consent, or production access controls.
    assert_eq!(
        std::env::var("RUSTI_ALLOW_LOCAL_KEYRING_TEST").as_deref(),
        Ok("I_ACCEPT_SYNTHETIC_ENTRY"),
        "run only with RUSTI_ALLOW_LOCAL_KEYRING_TEST=I_ACCEPT_SYNTHETIC_ENTRY"
    );

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("valid system time")
        .as_nanos();
    let item = format!("g2e_manual_{}_{}", std::process::id(), timestamp);
    let reference = CredentialRef::new(
        &item,
        "localhost",
        6697,
        CredentialPurpose::SaslPassword,
    )
    .expect("unique isolated keychain record ID");
    let store = NativeOsCredentialStore::new();
    let _cleanup = Cleanup {
        reference: reference.clone(),
    };

    assert!(
        store.provision(&reference, b"synthetic_first_value", false).is_err(),
        "write requires explicit local approval"
    );
    store
        .provision(&reference, b"synthetic_first_value", true)
        .expect("OS keychain must store test-only entry");

    assert_eq!(
        store.with_secret(&reference, |s| s == b"synthetic_first_value"),
        Ok(true),
        "first provisioned value must be retrieved"
    );

    store
        .provision(&reference, b"synthetic_rotated_value", true)
        .expect("operator-authorized overwrite must rotate value");
    assert_eq!(
        store.with_secret(&reference, |s| s == b"synthetic_rotated_value"),
        Ok(true),
        "latest value must replace old value"
    );
    assert_eq!(
        store.with_secret(&reference, |s| s == b"synthetic_first_value"),
        Ok(false),
        "old value must not remain accessible through this reference"
    );

    assert!(
        store.revoke(&reference, false).is_err(),
        "revoke requires explicit local approval"
    );
    store.revoke(&reference, true).expect("test entry deletion");
    assert!(
        store.with_secret(&reference, |_| true).is_err(),
        "revoked reference must fail closed on retrieval"
    );
}

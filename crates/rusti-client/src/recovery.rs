//! Deterministic, finite, operator-authorized reconnect policy.
//!
//! Pure-data only: no thread, timer, network, OS credential, RNG, or retries
//! are started by constructing or importing this module. Every retry requires
//! a separate authorized action in the caller's execution context.
#![forbid(unsafe_code)]

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    TcpTimeout,
    ConnectionLost,
    IrcServerUnavailable,
    CertificateRejected,
    PeerIdentityChanged,
    AuthenticationRejected,
    CapabilityRequiredMissing,
    InvalidProtocol,
    ConfigurationInvalid,
    OperatorCancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    Disabled,
    SecurityFailure,
    Cancelled,
    AttemptsExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDecision {
    Stop(StopReason),
    /// A scheduling proposal only, not an I/O action.
    RetryAfter(Duration),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryPolicy {
    /// Hard limit across one operator-approved recovery session.
    pub max_attempts: u8,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(8),
        }
    }
}

impl RecoveryPolicy {
    pub fn validate(self) -> bool {
        self.max_attempts > 0
            && self.max_attempts <= 8
            && self.base_delay >= Duration::from_millis(100)
            && self.base_delay <= Duration::from_secs(10)
            && self.max_delay >= self.base_delay
            && self.max_delay <= Duration::from_secs(30)
    }

    /// failed_attempts counts already failed attempts; a retry increases it
    /// by one. No scheduling or network operation occurs here.
    /// Jitter is deterministic, not cryptographic randomness.
    pub fn decide(
        self,
        failure: FailureKind,
        failed_attempts: u8,
        operator_approved: bool,
        jitter_seed: u64,
    ) -> RecoveryDecision {
        // Cancellation is a terminal state regardless of prior approval:
        // it must never be interpreted as permission to restart/retry.
        if failure == FailureKind::OperatorCancelled {
            return RecoveryDecision::Stop(StopReason::Cancelled);
        }
        if !self.validate() || !operator_approved {
            return RecoveryDecision::Stop(StopReason::Disabled);
        }
        if !matches!(
            failure,
            FailureKind::TcpTimeout
                | FailureKind::ConnectionLost
                | FailureKind::IrcServerUnavailable
        ) {
            return RecoveryDecision::Stop(StopReason::SecurityFailure);
        }
        if failed_attempts >= self.max_attempts {
            return RecoveryDecision::Stop(StopReason::AttemptsExhausted);
        }

        let base = self.base_delay.as_millis() as u64;
        let cap = self.max_delay.as_millis() as u64;
        // Saturating arithmetic protects older 32-bit targets from overflow.
        let exponent = (failed_attempts as u32).min(7);
        let delay = base.saturating_mul(1u64 << exponent).min(cap);
        let window = (delay / 4).max(1);
        let jitter = jitter_seed % (window + 1);
        RecoveryDecision::RetryAfter(Duration::from_millis(delay.saturating_add(jitter).min(cap)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_automatic_retry_without_operator_approval() {
        assert_eq!(
            RecoveryPolicy::default().decide(FailureKind::TcpTimeout, 0, false, 123),
            RecoveryDecision::Stop(StopReason::Disabled)
        );
    }

    #[test]
    fn no_retry_for_cert_identity_auth_or_protocol_failures() {
        for kind in [
            FailureKind::CertificateRejected,
            FailureKind::PeerIdentityChanged,
            FailureKind::AuthenticationRejected,
            FailureKind::CapabilityRequiredMissing,
            FailureKind::InvalidProtocol,
            FailureKind::ConfigurationInvalid,
        ] {
            assert_eq!(
                RecoveryPolicy::default().decide(kind, 0, true, 55),
                RecoveryDecision::Stop(StopReason::SecurityFailure)
            );
        }
    }

    #[test]
    fn finite_retry_and_bounded_jitter() {
        let policy = RecoveryPolicy::default();
        for attempts in 0..3 {
            let result = policy.decide(FailureKind::ConnectionLost, attempts, true, 999);
            let RecoveryDecision::RetryAfter(delay) = result else {
                panic!("transport failure should be eligible for finite recovery");
            };
            assert!(delay >= Duration::from_millis(500));
            assert!(delay <= Duration::from_secs(8));
        }
        assert_eq!(
            policy.decide(FailureKind::ConnectionLost, 3, true, 0),
            RecoveryDecision::Stop(StopReason::AttemptsExhausted)
        );
    }

    #[test]
    fn determinism_and_invalid_policy_stop() {
        let p = RecoveryPolicy::default();
        assert_eq!(
            p.decide(FailureKind::TcpTimeout, 1, true, 27),
            p.decide(FailureKind::TcpTimeout, 1, true, 27)
        );
        let bad = RecoveryPolicy {
            max_attempts: 0,
            ..p
        };
        assert_eq!(
            bad.decide(FailureKind::TcpTimeout, 1, true, 27),
            RecoveryDecision::Stop(StopReason::Disabled)
        );
    }

    #[test]
    fn explicit_cancellation_is_terminal() {
        assert_eq!(
            RecoveryPolicy::default().decide(FailureKind::OperatorCancelled, 0, true, 123),
            RecoveryDecision::Stop(StopReason::Cancelled)
        );
        assert_eq!(
            RecoveryPolicy::default().decide(FailureKind::OperatorCancelled, 0, false, 123),
            RecoveryDecision::Stop(StopReason::Cancelled)
        );
    }
}

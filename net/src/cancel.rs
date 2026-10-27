//! Explicit, thread-safe cancellation for a single operator-invoked IRC
//! registration. Importing or constructing this value starts no I/O, worker,
//! or retry. The caller can share it with an existing UI/task worker.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Default)]
pub struct RegistrationCancellation {
    cancelled: AtomicBool,
}

impl RegistrationCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_is_explicit_and_one_way() {
        let token = RegistrationCancellation::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }
}

//! Total `SubmitHeaders` rate limit across calls.
//!
//! `server/mod.rs` gates this module on `rgb-validation`.

use crate::error::{EnclaveError, Result};

/// Fixed-window rate limit for `SubmitHeaders`. It admits at most
/// [`MAX_HEADERS_PER_RATE_WINDOW`] headers, valid or not, in each
/// [`RATE_LIMIT_WINDOW`]. This is enough for a cold-start sync, and it stops
/// a flood of bad headers from keeping the enclave busy.
#[derive(Default)]
pub struct SubmitRateLimiter {
    window_start: Option<std::time::SystemTime>,
    headers_in_window: u64,
}

/// Maximum headers in each [`RATE_LIMIT_WINDOW`]. A cold-start sync from the
/// mainnet checkpoint is a few thousand blocks.
const MAX_HEADERS_PER_RATE_WINDOW: u64 = 100_000;
/// Length of the rate-limit window.
const RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

impl SubmitRateLimiter {
    /// Add `count` headers at time `now`. Returns `Err` above the window budget.
    /// The window resets after `RATE_LIMIT_WINDOW`, or if the clock goes back.
    pub fn check(&mut self, count: u64, now: std::time::SystemTime) -> Result<()> {
        let reset = match self.window_start {
            None => true,
            Some(start) => now
                .duration_since(start)
                .map(|elapsed| elapsed >= RATE_LIMIT_WINDOW)
                .unwrap_or(true),
        };
        if reset {
            self.window_start = Some(now);
            self.headers_in_window = 0;
        }
        self.headers_in_window = self.headers_in_window.saturating_add(count);
        if self.headers_in_window > MAX_HEADERS_PER_RATE_WINDOW {
            return Err(EnclaveError::Spv(format!(
                "SubmitHeaders rate limit exceeded: {} headers within {}s (max {})",
                self.headers_in_window,
                RATE_LIMIT_WINDOW.as_secs(),
                MAX_HEADERS_PER_RATE_WINDOW,
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn rate_limiter_allows_up_to_budget_then_rejects() {
        let mut limiter = SubmitRateLimiter::default();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        // The full budget across several calls in one window is accepted.
        limiter
            .check(MAX_HEADERS_PER_RATE_WINDOW - 1, t0)
            .expect("under budget");
        limiter
            .check(1, t0 + Duration::from_secs(1))
            .expect("exactly at budget");

        // One more header in the same window is refused.
        let err = limiter.check(1, t0 + Duration::from_secs(2)).unwrap_err();
        assert!(matches!(err, EnclaveError::Spv(_)));
    }

    #[test]
    fn rate_limiter_resets_after_window() {
        let mut limiter = SubmitRateLimiter::default();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

        limiter
            .check(MAX_HEADERS_PER_RATE_WINDOW, t0)
            .expect("fills the budget");
        // Refused inside the window.
        assert!(limiter
            .check(1, t0 + RATE_LIMIT_WINDOW - Duration::from_secs(1))
            .is_err());
        // The budget resets after the window.
        limiter
            .check(MAX_HEADERS_PER_RATE_WINDOW, t0 + RATE_LIMIT_WINDOW)
            .expect("window reset");
    }

    #[test]
    fn rate_limiter_handles_clock_going_backwards() {
        let mut limiter = SubmitRateLimiter::default();
        let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
        limiter.check(10, t1).expect("first call");
        // An earlier timestamp (clock skew) resets the window.
        // It must not panic or underflow.
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        limiter
            .check(10, t0)
            .expect("backwards clock resets window");
    }
}

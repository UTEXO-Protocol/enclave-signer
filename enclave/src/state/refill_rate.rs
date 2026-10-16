//! RR15: the rights-refill rate limit. A refill has no deposit behind it, so
//! this bounds the validation work and fee a flood can cause. In memory, per
//! enclave; a restart resets it.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{EnclaveError, Result};

/// Refills admitted past the cheap gate in any sliding hour.
pub const MAX_REFILLS_PER_HOUR: usize = 12;

const WINDOW: Duration = Duration::from_secs(60 * 60);

/// Sliding one-hour window of admitted refills.
#[derive(Default)]
pub struct RefillRateLimit {
    admitted: Mutex<VecDeque<Instant>>,
}

impl RefillRateLimit {
    /// Admits one refill at `now`, or refuses it once the last hour holds
    /// [`MAX_REFILLS_PER_HOUR`]. A refused request does not count.
    pub fn admit(&self, now: Instant) -> Result<()> {
        let mut admitted = self
            .admitted
            .lock()
            .map_err(|e| EnclaveError::Internal(format!("refill rate limit poisoned: {e}")))?;
        while admitted
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= WINDOW)
        {
            admitted.pop_front();
        }
        if admitted.len() >= MAX_REFILLS_PER_HOUR {
            return Err(EnclaveError::CrossCheck(format!(
                "rights refill rate limit: {MAX_REFILLS_PER_HOUR} refills in the last hour - retry \
                 later"
            )));
        }
        admitted.push_back(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_twelve_in_an_hour_then_refuses_the_thirteenth() {
        let limit = RefillRateLimit::default();
        let t0 = Instant::now();
        for i in 0..MAX_REFILLS_PER_HOUR as u64 {
            limit.admit(t0 + Duration::from_secs(i)).unwrap();
        }
        let err = limit.admit(t0 + Duration::from_secs(60)).unwrap_err();
        assert!(err.to_string().contains("rate limit"), "{err}");
    }

    #[test]
    fn a_refusal_does_not_use_a_slot() {
        let limit = RefillRateLimit::default();
        let t0 = Instant::now();
        for _ in 0..MAX_REFILLS_PER_HOUR {
            limit.admit(t0).unwrap();
        }
        for _ in 0..3 {
            assert!(limit.admit(t0 + Duration::from_secs(1)).is_err());
        }
        // Only the twelve admitted ones age out, so the next hour is full again.
        for _ in 0..MAX_REFILLS_PER_HOUR {
            limit.admit(t0 + WINDOW).unwrap();
        }
    }

    #[test]
    fn the_window_slides_one_admission_at_a_time() {
        let limit = RefillRateLimit::default();
        let t0 = Instant::now();
        limit.admit(t0).unwrap();
        for _ in 1..MAX_REFILLS_PER_HOUR {
            limit.admit(t0 + Duration::from_secs(600)).unwrap();
        }
        assert!(limit.admit(t0 + WINDOW - Duration::from_secs(1)).is_err());
        limit.admit(t0 + WINDOW).unwrap();
        assert!(limit.admit(t0 + WINDOW).is_err());
    }
}

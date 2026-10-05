//! Periodic sync of the enclave clock from the hypervisor PTP clock.
//!
//! The enclave has no NTP client. Clock drift can make certificate validation
//! reject a certificate as expired or not yet valid.
//!
//! This module expects a hypervisor PTP clock at `/dev/ptp0`. The enclave
//! kernel must expose that device. The module periodically copies its time
//! into `CLOCK_REALTIME`.
//!
//! Fail-soft: if the PTP read fails, the enclave logs and keeps its current
//! clock. The `attestation-verify` tolerance is the second safety net.

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::thread;
use std::time::Duration;

use nix::sys::time::TimeValLike;
use nix::time::{clock_gettime, clock_settime, ClockId};

/// Hypervisor PTP clock exposed to the enclave by the built-in `ptp_kvm` driver.
const PTP_DEVICE: &str = "/dev/ptp0";

/// Attempt to synchronize the clock every five minutes. This is not an
/// accuracy guarantee; synchronization failures leave the current clock unchanged.
const SYNC_INTERVAL: Duration = Duration::from_secs(300);

/// Linux `FD_TO_CLOCKID(fd)` = `((~(clockid_t)fd) << 3) | CLOCKFD`, with
/// `CLOCKFD == 3`. Turns a PTP device fd into a dynamic POSIX clock id.
fn fd_to_clockid(fd: RawFd) -> nix::libc::clockid_t {
    ((!(fd as nix::libc::clockid_t)) << 3) | 3
}

/// Copy the PTP clock to CLOCK_REALTIME. Returns the offset in whole seconds
/// (new - old) for logging.
fn sync_from_ptp() -> Result<i64, String> {
    let dev = File::open(PTP_DEVICE).map_err(|e| format!("open {PTP_DEVICE}: {e}"))?;
    let clockid = ClockId::from_raw(fd_to_clockid(dev.as_raw_fd()));

    let host = clock_gettime(clockid).map_err(|e| format!("read PTP clock: {e}"))?;
    let before =
        clock_gettime(ClockId::CLOCK_REALTIME).map_err(|e| format!("read CLOCK_REALTIME: {e}"))?;
    clock_settime(ClockId::CLOCK_REALTIME, host).map_err(|e| format!("set CLOCK_REALTIME: {e}"))?;

    // Keep `dev` open until after the PTP read: closing the fd makes `clockid`
    // invalid.
    drop(dev);
    Ok(host.num_seconds() - before.num_seconds())
}

fn run() {
    loop {
        match sync_from_ptp() {
            Ok(offset) if offset.abs() >= 1 => tracing::info!(
                offset_secs = offset,
                device = PTP_DEVICE,
                "disciplined CLOCK_REALTIME from hypervisor PTP"
            ),
            Ok(_) => {
                tracing::debug!(device = PTP_DEVICE, "clock within 1s of PTP; no adjustment")
            }
            Err(e) => tracing::warn!(
                error = %e,
                "PTP clock sync failed; continuing on current clock \
                 (attestation-verify tolerance is the secondary net)"
            ),
        }
        thread::sleep(SYNC_INTERVAL);
    }
}

/// Start the background clock-sync thread. A spawn failure is logged and
/// ignored.
pub fn spawn() {
    match thread::Builder::new().name("clock-sync".into()).spawn(run) {
        Ok(_) => tracing::info!(
            device = PTP_DEVICE,
            interval_secs = SYNC_INTERVAL.as_secs(),
            "clock-sync thread started"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "failed to spawn clock-sync thread; enclave runs on the boot clock"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::fd_to_clockid;

    // Cross-checked against the C macro `((~(clockid_t)fd << 3) | 3)`.
    #[test]
    fn fd_to_clockid_matches_kernel_macro() {
        assert_eq!(fd_to_clockid(0), -5);
        assert_eq!(fd_to_clockid(3), -29);
        assert_eq!(fd_to_clockid(5), -45);
        for fd in 0..64 {
            assert_eq!(fd_to_clockid(fd), ((!fd) << 3) | 3);
        }
    }
}

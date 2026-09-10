//! Periodic enclave clock discipline from the hypervisor PTP source.
//!
//! Nitro enclaves read wall-clock time from the hypervisor ONCE at boot and then
//! free-run with no NTP, drifting by ~1s/day (proportional to enclave load). A
//! long-lived enclave therefore starts rejecting freshly-issued attestation certs
//! as "certificate not yet valid" (the clone clock-skew bug, found 2026-08-26) and
//! can also fail TLS handshakes to electrs/hub whose server certs then look
//! not-yet-valid / expired. Widening the attestation validity tolerance
//! (`attestation-verify`) only papers over ONE of those call sites; disciplining
//! the clock fixes the root cause for all of them at once.
//!
//! Our enclave kernel is built with `CONFIG_PTP_1588_CLOCK_KVM=y`, so the KVM
//! hypervisor (Nitro) exposes an accurate PTP clock at `/dev/ptp0` (backed by
//! Amazon Time Sync on the host). We periodically read it and set CLOCK_REALTIME,
//! keeping drift in the microsecond range. This mirrors AWS's own guidance and the
//! approach documented by Evervault for the same Nitro clock-drift quirk.
//!
//! FAIL-SOFT by design: if `/dev/ptp0` is absent or a read fails we log and keep
//! running on the current clock — the enclave is never worse off than before, and
//! the `attestation-verify` tolerance remains as a secondary safety net.

use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::thread;
use std::time::Duration;

use nix::sys::time::TimeValLike;
use nix::time::{clock_gettime, clock_settime, ClockId};

/// Hypervisor PTP clock exposed to the enclave by the built-in `ptp_kvm` driver.
const PTP_DEVICE: &str = "/dev/ptp0";

/// How often to re-discipline the clock. Drift is ~1s/day, so 5 min keeps the
/// worst-case error far below a second while costing one syscall pair per tick.
const SYNC_INTERVAL: Duration = Duration::from_secs(300);

/// Linux `FD_TO_CLOCKID(fd)` = `((~(clockid_t)fd) << 3) | CLOCKFD` with
/// `CLOCKFD == 3`: turn an open PTP character-device fd into the dynamic POSIX
/// clock id that `clock_gettime` understands. Pure arithmetic — unit-tested below.
fn fd_to_clockid(fd: RawFd) -> nix::libc::clockid_t {
    ((!(fd as nix::libc::clockid_t)) << 3) | 3
}

/// Read the hypervisor PTP clock and copy it onto CLOCK_REALTIME. Returns the
/// applied offset in whole seconds (new − old) for logging.
fn sync_from_ptp() -> Result<i64, String> {
    let dev = File::open(PTP_DEVICE).map_err(|e| format!("open {PTP_DEVICE}: {e}"))?;
    let clockid = ClockId::from_raw(fd_to_clockid(dev.as_raw_fd()));

    let host = clock_gettime(clockid).map_err(|e| format!("read PTP clock: {e}"))?;
    let before =
        clock_gettime(ClockId::CLOCK_REALTIME).map_err(|e| format!("read CLOCK_REALTIME: {e}"))?;
    clock_settime(ClockId::CLOCK_REALTIME, host).map_err(|e| format!("set CLOCK_REALTIME: {e}"))?;

    // Keep `dev` (and therefore the dynamic clock fd) alive until AFTER the PTP
    // read above — dropping it earlier would close the fd and invalidate `clockid`.
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

/// Start the background clock-discipline thread. Non-blocking; a spawn failure is
/// logged and ignored (the enclave keeps running on its boot clock).
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
        // General identity: ((~fd) << 3) | 3 for arbitrary fd.
        for fd in 0..64 {
            assert_eq!(fd_to_clockid(fd), ((!fd) << 3) | 3);
        }
    }
}

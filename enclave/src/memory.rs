//! The request memory model.
//!
//! The enclave has a fixed amount of RAM and no swap. When a process outgrows
//! it, the kernel ends the process and every key that lives only in memory.
//! So the heap a request can use must have a bound that does not depend on
//! the request content:
//!
//! ```text
//! peak heap of one request <= REQUEST_MEMORY_FACTOR * frame bytes
//!                             + MAX_WIRE_ELEMENTS * WIRE_ELEMENT_BYTES
//! ```
//!
//! The first term covers every parser: each byte of input costs at most
//! `REQUEST_MEMORY_FACTOR` bytes of heap. The second term covers the
//! protobuf decode. A repeated element can be 2 bytes on the wire and about
//! 80 bytes in memory. So `framing::check_request_shape` counts the elements
//! before the decode and refuses more than `MAX_WIRE_ELEMENTS`.
//!
//! [`crate::conn::WORKER_THREADS`] requests run at once, each at most
//! [`crate::framing::MAX_MESSAGE_SIZE`] bytes. Add the memory the enclave uses
//! with no request in flight, and the result is [`MIN_ENCLAVE_MEMORY_BYTES`].
//! [`check_at_boot`] refuses to start a release build on less.
//!
//! Responses from the pinned EVM RPC and the Bitcoin indexer are outside the
//! model. TLS pins their senders, and the host cannot change them.
//!
//! The factor is a tested rule, not an estimate. Each request type with a
//! large input has a test. The test runs the largest input and fails when the
//! peak is above the factor (`peak::assert_within_factor`). A parser whose
//! output grows faster than its input fails that test instead of reaching an
//! image. The tests live next to the code they measure: `framing`, the gas
//! transaction decoder, consignment validation and PSBT parsing.
//!
//! Connections waiting in the queue hold no heap: a worker reads the frame
//! only when it starts the request.

use crate::conn::WORKER_THREADS;
use crate::framing::{MAX_MESSAGE_SIZE, MAX_WIRE_ELEMENTS};
use crate::policy::BuildContext;

/// Upper bound on the heap one request uses, as a multiple of its input size.
/// Every request type with a large input has a test against this bound. The
/// largest measured value is consignment validation, at about 15.5 times the
/// consignment. Reading a frame takes 3 times the frame. The gas transaction
/// and PSBT parsers stay under 2.
pub const REQUEST_MEMORY_FACTOR: usize = 20;

/// Heap one decoded protobuf element may use beyond its wire bytes. This
/// covers the struct in its vector, a vector header, and the copy a growing
/// vector holds during a move. The measured value is about 80 bytes for an
/// empty proof entry.
pub const WIRE_ELEMENT_BYTES: usize = 128;

/// The second term of the request bound: the most the protobuf decode of one
/// request can add beyond the factor.
pub const ELEMENTS_BYTES: usize = MAX_WIRE_ELEMENTS * WIRE_ELEMENT_BYTES;

/// The most heap one request of `frame` bytes may use.
pub const fn request_bound(frame: usize) -> usize {
    REQUEST_MEMORY_FACTOR * frame + ELEMENTS_BYTES
}

/// Memory the enclave uses with no request in flight. This covers the binary
/// and its root file system, the SPV header chain, the schema rules, the
/// replay guards and the request queue. The value is an estimate with
/// headroom. The binary, the root file system and a mainnet header chain are
/// each well under 200 MiB.
pub const BASELINE_BYTES: usize = 512 * 1024 * 1024;

/// Memory the enclave needs to serve `WORKER_THREADS` largest requests at
/// once. `nitro-cli run-enclave --memory` must give at least this much. The
/// deploy scripts use 3072 MiB.
pub const MIN_ENCLAVE_MEMORY_BYTES: usize =
    BASELINE_BYTES + WORKER_THREADS * request_bound(MAX_MESSAGE_SIZE as usize);

// The deploy scripts and the README run the enclave with 3072 MiB. The
// largest four requests fit in the part above the baseline.
const _: () = assert!(MIN_ENCLAVE_MEMORY_BYTES <= 3072 * 1024 * 1024);
const _: () = assert!(
    MIN_ENCLAVE_MEMORY_BYTES - BASELINE_BYTES == 4 * (24 * 1024 * 1024 * 20 + 64 * 1024 * 1024)
);
const _: () = assert!(MIN_ENCLAVE_MEMORY_BYTES == 2688 * 1024 * 1024);

/// Refuses to start a release build with less memory than
/// [`MIN_ENCLAVE_MEMORY_BYTES`]. Debug and test builds run in local stacks of
/// any size, so they log a warning instead. When the check cannot read the
/// total memory (no `/proc/meminfo`), it logs a warning and continues.
pub fn check_at_boot(ctx: &BuildContext) -> Result<(), String> {
    let Some(total) = total_memory_bytes() else {
        tracing::warn!(
            required_mib = MIN_ENCLAVE_MEMORY_BYTES / (1024 * 1024),
            "total memory unknown; skipping the memory check"
        );
        return Ok(());
    };
    let required_mib = MIN_ENCLAVE_MEMORY_BYTES / (1024 * 1024);
    let total_mib = total / (1024 * 1024);
    if total >= MIN_ENCLAVE_MEMORY_BYTES {
        tracing::info!(total_mib, required_mib, "memory check passed");
        return Ok(());
    }
    let msg = format!(
        "enclave has {total_mib} MiB of memory, and {required_mib} MiB are needed for \
         {WORKER_THREADS} requests of {} MiB at a memory factor of {REQUEST_MEMORY_FACTOR} \
         plus {} MiB of decoded elements each (run-enclave --memory)",
        MAX_MESSAGE_SIZE / (1024 * 1024),
        ELEMENTS_BYTES / (1024 * 1024)
    );
    if ctx.debug_or_test {
        tracing::warn!("{msg}; continuing in a debug build");
        return Ok(());
    }
    Err(msg)
}

/// Total memory from `/proc/meminfo`, or `None` where it cannot be read.
fn total_memory_bytes() -> Option<usize> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_total(&meminfo)
}

/// Parses the `MemTotal:` line of `/proc/meminfo`, which is in kB.
fn parse_mem_total(meminfo: &str) -> Option<usize> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: usize = line
        .trim_start_matches("MemTotal:")
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

/// A heap meter for the factor tests. It counts the allocations of the
/// calling thread, so tests that run at the same time do not see each other.
/// The code under test must not move its work to other threads.
#[cfg(test)]
#[allow(unsafe_code)]
pub(crate) mod peak {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::Mutex;

    thread_local! {
        static CURRENT: Cell<usize> = const { Cell::new(0) };
        static PEAK: Cell<usize> = const { Cell::new(0) };
    }

    struct Meter;

    unsafe impl GlobalAlloc for Meter {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = System.alloc(layout);
            if !p.is_null() {
                add(layout.size());
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
            System.dealloc(p, layout);
            remove(layout.size());
        }
        unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let q = System.realloc(p, layout, new_size);
            if !q.is_null() {
                // A moving realloc holds the old and the new block at once.
                add(new_size);
                remove(layout.size());
            }
            q
        }
    }

    /// The thread-local cells have no destructor, so this never allocates.
    /// A thread that is shutting down is not counted.
    fn add(size: usize) {
        let _ = CURRENT.try_with(|current| {
            let now = current.get().saturating_add(size);
            current.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    fn remove(size: usize) {
        let _ = CURRENT.try_with(|current| current.set(current.get().saturating_sub(size)));
    }

    #[global_allocator]
    static METER: Meter = Meter;

    /// One measurement at a time, so large inputs of two tests do not sit in
    /// memory together.
    static MEASURING: Mutex<()> = Mutex::new(());

    /// Builds an input with `setup`, then runs `run` on it and returns the
    /// input, the result and the peak heap `run` added, in bytes. The count
    /// is per thread, and both closures run under the measurement lock.
    pub(crate) fn measure<I, R>(
        setup: impl FnOnce() -> I,
        run: impl FnOnce(&I) -> R,
    ) -> (I, R, usize) {
        let _guard = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
        let input = setup();
        let base = CURRENT.with(Cell::get);
        PEAK.with(|peak| peak.set(base));
        let result = run(&input);
        let peak = PEAK.with(Cell::get).saturating_sub(base);
        (input, result, peak)
    }

    /// Fails when `peak` is above the request bound for a frame of
    /// `frame_len` bytes: the factor plus the decoded-element term. For the
    /// decode of a whole request. `what` names the request in the message.
    pub(crate) fn assert_within_request_bound(what: &str, frame_len: usize, peak: usize) {
        let budget = super::request_bound(frame_len);
        println!("{what}: {frame_len} frame bytes, peak heap {peak} bytes, bound {budget} bytes");
        assert!(
            peak <= budget,
            "{what}: peak heap {peak} bytes is above the request bound of {budget} bytes \
             for a {frame_len}-byte frame"
        );
    }

    /// Fails when `peak` is above the request memory factor for an input of
    /// `input_len` bytes. For one parser. `what` names the parser in the
    /// message.
    pub(crate) fn assert_within_factor(what: &str, input_len: usize, peak: usize) {
        let budget = super::REQUEST_MEMORY_FACTOR * input_len;
        let factor = peak as f64 / input_len.max(1) as f64;
        println!("{what}: {input_len} input bytes, peak heap {peak} bytes, factor {factor:.2}");
        assert!(
            peak <= budget,
            "{what}: peak heap {peak} bytes is {factor:.1} times the {input_len}-byte input; \
             the request memory factor is {}",
            super::REQUEST_MEMORY_FACTOR
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_total_is_read_in_kib() {
        let meminfo = "MemTotal:        3014656 kB\nMemFree:         2900000 kB\n";
        assert_eq!(parse_mem_total(meminfo), Some(3_014_656 * 1024));
        assert_eq!(parse_mem_total("MemFree: 1 kB\n"), None);
        assert_eq!(parse_mem_total("MemTotal: lots kB\n"), None);
    }

    #[test]
    fn a_debug_build_only_warns() {
        // A test build is a debug build in the model: it never refuses.
        assert!(check_at_boot(&BuildContext::current()).is_ok());
    }

    #[test]
    fn the_meter_counts_the_thread_allocation() {
        let (n, len, peak) = peak::measure(|| 1usize << 20, |n| vec![0u8; *n].len());
        assert_eq!(len, n);
        // Per-thread count: exactly this allocation, whatever other tests do.
        assert_eq!(peak, 1 << 20, "peak {peak}");
    }
}

//! The request memory model.
//!
//! The enclave has a fixed amount of RAM and no swap. When a process outgrows
//! it, the kernel ends the process. So the heap a request can use must have a
//! bound that does not depend on the request content:
//!
//! ```text
//! peak heap of one request <= REQUEST_MEMORY_FACTOR * frame bytes
//!                             + MAX_WIRE_ELEMENTS * WIRE_ELEMENT_BYTES
//! ```
//!
//! The first term covers most parsers that grow with their input: each byte
//! costs at most `REQUEST_MEMORY_FACTOR` bytes of heap. The second term
//! covers the protobuf decode. A repeated element can be 2 bytes on the wire
//! and about 80 bytes in memory. So `framing::check_request_shape` counts the
//! elements before the decode and refuses more than `MAX_WIRE_ELEMENTS`.
//!
//! A few parsers take more than the factor on the densest inputs measured.
//! Each has a size limit, and at that limit it fits the bound of the largest
//! frame, `request_bound(MAX_MESSAGE_SIZE)`. That is the heap each worker
//! holds:
//!
//! - PSBTs, at most `MAX_PSBT_BYTES` (1 MiB): about 102 times for one input
//!   and outputs that each carry two empty records. A request holds at most
//!   two parsed PSBTs at once, a PSBT and its parent.
//! - Attestation documents, at most `attestation_verify::MAX_DOCUMENT_BYTES`
//!   (64 KiB): about 48 times for a document of CBOR nulls.
//! - Consignments, at most `max_consignment_bytes` (10 MiB): about 40 times
//!   for transfers that turn one mint right into tens of thousands. The rate
//!   changes a little with the genesis, through the layout of the maps in
//!   RGB validation. Validation of such a chain at the limit measured
//!   404 MiB. A whole burn request with such a consignment takes at most
//!   512 MiB by the test's count. That is less than the 544 MiB each worker
//!   holds, but a smaller frame with such a consignment can take more than
//!   its own request bound. `MAX_CONSIGNMENT_BYTES` can lower the limit, and
//!   the enclave refuses to start with a larger value.
//!
//! [`crate::conn::WORKER_THREADS`] requests run at once, each at most
//! [`crate::framing::MAX_MESSAGE_SIZE`] bytes. Add the memory the enclave uses
//! with no request in flight, and the result is [`MIN_ENCLAVE_MEMORY_BYTES`].
//! [`check_at_boot`] refuses to start a release build on less usable memory,
//! or with no readable total. The kernel keeps part of the launch value for
//! itself, so `run-enclave --memory` must give at least
//! [`RUN_ENCLAVE_MEMORY_MIB`].
//!
//! Responses from the pinned EVM RPC and the Bitcoin indexer are outside the
//! model. TLS pins their senders, and the host cannot change them.
//!
//! The model is a tested rule, not an estimate. Each parser of a request byte
//! field has a size limit, a measured factor, or both:
//!
//! - the frame (`MAX_MESSAGE_SIZE`) and its elements (`MAX_WIRE_ELEMENTS`),
//! - consignments (`max_consignment_bytes`), and the outputs that their
//!   terminals name (`MAX_TERMINAL_OUTPUTS`),
//! - PSBTs (`MAX_PSBT_BYTES`),
//! - gas transactions (`MAX_GAS_TX_BYTES`, `MAX_RLP_ITEMS`),
//! - attestation documents (`attestation_verify::MAX_DOCUMENT_BYTES`),
//! - fundsOut calldata (`MAX_FUNDS_OUT_CALL_DATA_LEN`),
//! - the EVM RPC CA certificate (`MAX_EVM_RPC_CA_DER_BYTES`),
//! - the `SetEndpoints` strings (`MAX_ENDPOINT_STRING_BYTES`),
//! - an imported mnemonic, on `allow-seed-import` builds only,
//! - headers (`MAX_HEADERS_PER_SUBMIT`) and Merkle paths
//!   (`MAX_MERKLE_PATH_DEPTH`).
//!
//! The other byte fields are fixed-size, refused before use, never read, or
//! read once into a buffer of their own size (the encrypted clone seed). The
//! asset ids and the cloning secret have no upper limit, and no parser reads
//! them: they are only compared, hashed or stored. No build reads
//! `EvmSource.token` or `EvmSource.recipient`, and the mint signer does not
//! read the destination consignment or its hash. They take memory only in
//! the decode, which the frame term covers. An error text can quote request
//! data, so dispatch cuts it to 1 KiB before it logs or returns it. The log
//! formatter keeps a buffer as large as the longest line it wrote on each
//! thread.
//!
//! The tests measure the frame, consignment, PSBT, gas transaction and
//! attestation document parsers on the densest shapes measured. The other
//! parsers have small size limits and refusal tests. The frame, PSBT,
//! attestation document and gas transaction tests run at the limits. The
//! consignment tests run histories of 2 000 and 10 000 transfers, and three
//! wide shapes at two sizes each. A test fails when the peak is above the
//! factor (`peak::assert_within_factor`), the request bound, or the heap each
//! worker holds. A parser whose output grows faster than its input fails such
//! a test instead of reaching an image. `#[ignore]` marks the slow tests with
//! a history of 10 000 transfers, and CI runs them on the burn set. The tests
//! live next to the code they measure: `framing`, `config`, the gas
//! transaction decoder, consignment validation, PSBT parsing and attestation
//! documents. The tests of whole requests through `dispatch` are in
//! `server::sign::request_memory` and `server::rights_refill`.
//!
//! Connections waiting in the queue hold no heap: a worker reads the frame
//! only when it starts the request.
//!
//! Consignment validation also uses RAM outside the heap. rgb-lib reads a
//! consignment only from a file, so validation writes the bytes to a scratch
//! file in `std::env::temp_dir()`. In the enclave, `/tmp` is a tmpfs, so the
//! file takes up to `max_consignment_bytes` of RAM for each request. The heap
//! meter does not count it. The file exists only after validation releases
//! its decoded copy, when the heap is below the request peak. A one-off run
//! that counted the file as heap measured the same peaks.

use crate::conn::WORKER_THREADS;
use crate::framing::{MAX_MESSAGE_SIZE, MAX_WIRE_ELEMENTS};
use crate::policy::BuildContext;

/// Upper bound on the heap one request uses, as a multiple of its input size,
/// for most parsers that grow with their input. Reading a frame takes 3 times
/// the frame. Consignment validation of a long history takes about 10 times
/// the consignment. The gas transaction parser stays under 0.1, and a PSBT
/// whose bytes sit in large records about 1.5. A whole burn request through
/// `dispatch` holds the decoded request during validation. It peaks at about
/// 9.3 times its frame beyond the element term
/// (`server::sign::request_memory`). The parsers that take more on the
/// densest inputs measured have size limits (module docs). The tests count
/// requested bytes on the calling thread. The baseline includes allocator
/// overhead and fragmentation, and a parser that moves work to other threads
/// needs its own meter.
pub const REQUEST_MEMORY_FACTOR: usize = 20;

/// Heap one decoded protobuf element may use beyond its wire bytes. This
/// covers the struct in its vector, a vector header, and the copy a growing
/// vector holds during a move. The measured value is about 80 bytes per
/// occurrence at the element limit
/// (`framing::tests::the_wire_element_limit_is_exact`).
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

/// Usable memory the enclave needs to serve `WORKER_THREADS` largest requests
/// at once. The boot check requires this much in `MemTotal`.
pub const MIN_ENCLAVE_MEMORY_BYTES: usize =
    BASELINE_BYTES + WORKER_THREADS * request_bound(MAX_MESSAGE_SIZE as usize);

/// The least `nitro-cli run-enclave --memory` value, in MiB. `MemTotal` in
/// `/proc/meminfo` leaves out the memory the kernel keeps for itself, and the
/// root file system of the image sits in RAM too. So the launch value is
/// above [`MIN_ENCLAVE_MEMORY_BYTES`], with 1408 MiB to spare.
///
/// The value is a whole number of GiB. nitro-cli gives an enclave whole
/// hugepages, 1 GiB pages first, and the allocator reserves its pool the same
/// way. A value such as 3584 MiB takes three 1 GiB pages and 256 pages of
/// 2 MiB. When no 2 MiB page is free, it takes a fourth 1 GiB page. So a pool
/// of three times 3584 MiB can hold only two such enclaves. At 4096 MiB,
/// three enclaves take exactly 12288 MiB, with any mix of 1 GiB and 2 MiB
/// pages.
///
/// No `MemTotal` reading at this value is on record yet. To take one, run one
/// image at this value with `ENCLAVE_DEBUG_MODE=1`. Make sure that
/// `nitro-cli describe-enclaves` shows this value in `MemoryMiB`. Then read
/// `total_mib` in the "memory check passed" line on `nitro-cli console`. It
/// must be at least the minimum. Record the reading here.
///
/// The deploy scripts, the README, the spec and `build/deploy-to-ec2.sh`
/// carry this value and the minimum as literals, and a test pins them to the
/// constants. The deploy scripts refuse a smaller `ENCLAVE_MEMORY`, or one
/// that is not a whole number of GiB. `deploy-host.sh` and
/// `utexo-enclave-ctl.sh check` also refuse a hugepage pool that cannot hold
/// every enclave of the host at the launch value. `utexo-enclave-ctl.sh
/// start` refuses only when the free hugepages cannot hold its own enclave.
pub const RUN_ENCLAVE_MEMORY_MIB: usize = 4096;

// The largest four requests fit in the part above the baseline, and the
// kernel and the root file system get at least 512 MiB of the launch value.
const _: () = assert!(
    MIN_ENCLAVE_MEMORY_BYTES - BASELINE_BYTES == 4 * (24 * 1024 * 1024 * 20 + 64 * 1024 * 1024)
);
const _: () = assert!(MIN_ENCLAVE_MEMORY_BYTES == 2688 * 1024 * 1024);
const _: () =
    assert!(RUN_ENCLAVE_MEMORY_MIB * 1024 * 1024 - MIN_ENCLAVE_MEMORY_BYTES >= 512 * 1024 * 1024);
// nitro-cli gives an enclave whole 1 GiB pages first, so the launch value is a
// whole number of GiB.
const _: () = assert!(RUN_ENCLAVE_MEMORY_MIB.is_multiple_of(1024));

/// Refuses to start a release build with less usable memory than
/// [`MIN_ENCLAVE_MEMORY_BYTES`], or with no readable total. `main` panics on
/// the refusal. A release build on a host with no `/proc/meminfo` refuses to
/// start too, for example the TCP fallback of `main` on macOS. Debug and test
/// builds run in local stacks of any size and on other operating systems, so
/// they log a warning instead. A pass logs the total at info level, which is
/// how a deploy reads `MemTotal` (see [`RUN_ENCLAVE_MEMORY_MIB`]).
pub fn check_at_boot(ctx: &BuildContext) -> Result<(), String> {
    check(total_memory_bytes(), ctx)
}

/// The boot check for a known total. `None` means `/proc/meminfo` could not
/// be read or has no `MemTotal` line.
fn check(total: Option<usize>, ctx: &BuildContext) -> Result<(), String> {
    let required_mib = MIN_ENCLAVE_MEMORY_BYTES / (1024 * 1024);
    let problem = match total {
        Some(total) if total >= MIN_ENCLAVE_MEMORY_BYTES => {
            let total_mib = total / (1024 * 1024);
            tracing::info!(total_mib, required_mib, "memory check passed");
            return Ok(());
        }
        Some(total) => format!(
            "enclave has {} MiB of usable memory, and {required_mib} MiB are needed for \
             {WORKER_THREADS} requests of {} MiB at a memory factor of {REQUEST_MEMORY_FACTOR} \
             plus {} MiB of decoded elements each, and a {} MiB baseline; give run-enclave \
             --memory at least {RUN_ENCLAVE_MEMORY_MIB} MiB",
            total / (1024 * 1024),
            MAX_MESSAGE_SIZE / (1024 * 1024),
            ELEMENTS_BYTES / (1024 * 1024),
            BASELINE_BYTES / (1024 * 1024)
        ),
        None => format!(
            "total memory unknown: /proc/meminfo has no readable MemTotal line, and \
             {required_mib} MiB of usable memory are needed"
        ),
    };
    if ctx.debug_or_test {
        tracing::warn!("{problem}; continuing in a debug build");
        return Ok(());
    }
    Err(problem)
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

    /// Fails when `peak` is above the model for a request of `frame_len`
    /// bytes with `elements` field occurrences: the factor plus
    /// `WIRE_ELEMENT_BYTES` for each element. Tighter than the request bound,
    /// which takes the element limit. For a whole request through `dispatch`.
    pub(crate) fn assert_within_model(what: &str, frame_len: usize, elements: usize, peak: usize) {
        let elements_bytes = super::WIRE_ELEMENT_BYTES * elements;
        let budget = super::REQUEST_MEMORY_FACTOR * frame_len + elements_bytes;
        // Signed: below zero when the element term alone covers the peak.
        let beyond = (peak as f64 - elements_bytes as f64) / frame_len.max(1) as f64;
        println!(
            "{what}: {frame_len} frame bytes, {elements} elements ({elements_bytes} bytes), \
             peak heap {peak} bytes, factor {beyond:.2} beyond the elements, model {budget} bytes"
        );
        assert!(
            peak <= budget,
            "{what}: peak heap {peak} bytes is above the model of {budget} bytes for a \
             {frame_len}-byte frame with {elements} elements"
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

    fn build(debug_or_test: bool) -> BuildContext {
        BuildContext {
            debug_or_test,
            ..BuildContext::current()
        }
    }

    #[test]
    fn a_release_build_refuses_too_little_or_unknown_memory() {
        assert!(check(Some(MIN_ENCLAVE_MEMORY_BYTES), &build(false)).is_ok());
        let err = check(Some(MIN_ENCLAVE_MEMORY_BYTES - 1), &build(false)).unwrap_err();
        assert!(err.contains("2687 MiB of usable memory"), "{err}");
        assert!(err.contains("--memory at least 4096 MiB"), "{err}");
        let err = check(None, &build(false)).unwrap_err();
        assert!(err.contains("total memory unknown"), "{err}");
    }

    #[test]
    fn a_debug_build_only_warns() {
        assert!(check(Some(MIN_ENCLAVE_MEMORY_BYTES - 1), &build(true)).is_ok());
        assert!(check(None, &build(true)).is_ok());
        // A test build is a debug build in the model: the real check never
        // refuses, whatever the machine has.
        assert!(check_at_boot(&BuildContext::current()).is_ok());
    }

    /// The scripts and documents carry the two memory values as literals.
    /// This pins the literals to the constants: the values the scripts use,
    /// not their comments, and the values the documents state.
    #[test]
    fn the_scripts_and_documents_carry_the_memory_values() {
        let min = MIN_ENCLAVE_MEMORY_BYTES / (1024 * 1024);
        let run = RUN_ENCLAVE_MEMORY_MIB;
        let refusal = [
            format!("ENCLAVE_MEMORY:-{run}}}"),
            format!("-lt {run} "),
            format!("below the {run} MiB minimum"),
        ];
        let checks: [(&str, &str, usize, Vec<String>); 5] = [
            // The host script has the check twice: at the top and in the
            // embedded control script.
            (
                "deploy/deploy-host.sh",
                include_str!("../../deploy/deploy-host.sh"),
                2,
                refusal.to_vec(),
            ),
            (
                "deploy/systemd/utexo-enclave-ctl.sh",
                include_str!("../../deploy/systemd/utexo-enclave-ctl.sh"),
                1,
                refusal.to_vec(),
            ),
            (
                "README.md",
                include_str!("../../README.md"),
                1,
                vec![
                    format!("--memory {run} "),
                    format!("at least {run} MiB"),
                    format!("needs {min} MiB of usable"),
                ],
            ),
            (
                "docs/tee-spec.md",
                include_str!("../../docs/tee-spec.md"),
                1,
                vec![format!("({min} MiB)"), format!("at least {run} MiB")],
            ),
            (
                "build/deploy-to-ec2.sh",
                include_str!("../../build/deploy-to-ec2.sh"),
                1,
                vec![format!("--memory {run} ")],
            ),
        ];
        for (file, text, times, needles) in checks {
            for needle in needles {
                let found = text.matches(needle.as_str()).count();
                assert!(
                    found >= times,
                    "{file} says {needle:?} {found} times, not {times}"
                );
            }
        }
    }

    #[test]
    fn the_meter_counts_the_thread_allocation() {
        let (n, len, peak) = peak::measure(|| 1usize << 20, |n| vec![0u8; *n].len());
        assert_eq!(len, n);
        // Per-thread count: exactly this allocation, whatever other tests do.
        assert_eq!(peak, 1 << 20, "peak {peak}");
    }
}

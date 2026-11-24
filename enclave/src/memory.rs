//! The request memory model.
//!
//! The enclave has a fixed amount of RAM and no swap. When its processes
//! outgrow it, the kernel ends one of them: a validator child of the burn
//! signer before the enclave, as each child sets the highest OOM score. So
//! the heap a request can use must have a bound that does not depend on the
//! request content:
//!
//! ```text
//! peak heap of one request <= REQUEST_MEMORY_FACTOR * frame bytes
//!                             + MAX_WIRE_ELEMENTS * WIRE_ELEMENT_BYTES
//! ```
//!
//! The first term covers most parsers that grow with their input: each byte
//! costs at most `REQUEST_MEMORY_FACTOR` bytes of heap. The second term
//! covers the protobuf decode. A repeated element can be 2 bytes on the wire
//! and about 38 bytes in memory. So `framing::check_request_shape` counts the
//! elements before the decode and refuses more than `MAX_WIRE_ELEMENTS`.
//!
//! A few parsers take more than the factor on the densest inputs measured.
//! Each has a size limit, and at that limit it fits the bound of the largest
//! frame, `request_bound(MAX_MESSAGE_SIZE)`. That is the heap each worker
//! holds:
//!
//! - PSBTs, at most `max_psbt_bytes`: about 102 times for one input and
//!   outputs that each carry two empty records. A request holds one parsed
//!   PSBT at a time.
//! - A fascia, at most `MAX_FASCIA_BYTES`. A parse alone stays within the
//!   factor, but the core of the mint signer also runs rgb-lib's fascia
//!   inspection, which decodes a second copy and builds a record for each
//!   assignment. It takes about 31 times the bytes of the widest fascia
//!   measured, one propagate of 4 400 rights (`rgb::psbt_commit`). The core
//!   drops its own fascia first, so only one decoded fascia is live at a time.
//! - Attestation documents, at most `attestation_verify::MAX_DOCUMENT_BYTES`:
//!   about 48 times for a document of CBOR nulls.
//! - Consignments, at most `max_consignment_bytes`: about 53 times for
//!   transfers that turn one mint right into tens of thousands. The sender
//!   sets part of the rate through the order of the OpIds, which sets how
//!   full RGB validation keeps its B-trees. By the count of the test, a whole
//!   burn request with such a consignment fits the heap each worker holds at
//!   the image limits, with little room left: the enclave holds the decoded
//!   request, and the validator child the validation. A smaller frame with such
//!   a consignment can take more than its own request bound. Validation
//!   clones the decoded consignment, so each decoded list keeps only its
//!   length. `MAX_CONSIGNMENT_BYTES` can lower the image value, and
//!   `SetLimits` can raise it only with a frame that fits it.
//!
//! [`crate::conn::WORKER_THREADS`] requests run at once, each at most
//! [`crate::framing::MAX_MESSAGE_SIZE`] bytes. Add the memory the enclave uses
//! with no request in flight, and the result is [`MIN_ENCLAVE_MEMORY_BYTES`].
//! [`check_at_boot`] refuses to start a release build on less usable memory,
//! on less than the limits in force need ([`check_limits`]), or with no
//! readable total. The kernel keeps part of the launch value for itself, so
//! `run-enclave --memory` must give at least [`RUN_ENCLAVE_MEMORY_MIB`].
//!
//! Responses from the pinned EVM RPC are outside the model. TLS pins their
//! sender, and the host cannot change them. The reject
//! list is the one exception, because the operator sets its length limit: each
//! request can hold `max_reject_list_entries` entries, and `Limits::check`
//! counts them in the heap of a burn, in the enclave and its validator child
//! together.
//!
//! The values here are the values of the image. The operator can change the
//! frame, element and size limits at run time ([`crate::limits`]). A change
//! must pass [`check_limits`] and the checks of `Limits::check`, so the model
//! holds for the new values too.
//!
//! The model is a tested rule, not an estimate. Each parser of a request byte
//! field has a size limit, a measured factor, or both:
//!
//! - the frame (`MAX_MESSAGE_SIZE`) and its elements (`MAX_WIRE_ELEMENTS`),
//! - consignments (`max_consignment_bytes`),
//! - PSBTs (`MAX_PSBT_BYTES`) and fascias (`MAX_FASCIA_BYTES`),
//! - gas transactions (`max_gas_tx_bytes`, `max_rlp_items`),
//! - attestation documents (`attestation_verify::MAX_DOCUMENT_BYTES`),
//! - fundsOut calldata (`max_funds_out_call_data_bytes`),
//! - the EVM RPC CA certificate (`MAX_EVM_RPC_CA_DER_BYTES`),
//! - the `SetEndpoints` strings (`MAX_ENDPOINT_STRING_BYTES`),
//! - an imported mnemonic, on `allow-seed-import` builds only,
//! - headers (`max_headers_per_submit`).
//!
//! The other byte fields are fixed-size, refused before use, never read, or
//! read once into a buffer of their own size (the encrypted clone seed). The
//! asset ids and the cloning secret have no upper limit, and no parser reads
//! them: they are only compared, hashed or stored. No build reads
//! `EvmSource.token` or `EvmSource.recipient`. They take memory only in the
//! decode, which the frame term covers. An error text can quote request
//! data, so dispatch cuts it to `MAX_ERROR_TEXT_BYTES` before it logs or
//! returns it. The log formatter keeps a buffer as large as the longest line
//! it wrote on each thread.
//!
//! The tests measure the frame, consignment, PSBT, fascia, gas transaction
//! and attestation document parsers on the densest shapes measured. The
//! fascia is measured twice: its parse against the factor, and the whole core
//! against the request bound of a frame at the fascia limit. The other
//! parsers have small size limits and refusal tests. The frame, PSBT,
//! attestation document and gas transaction tests run at the limits. The
//! consignment tests run histories of 2 000 and 10 000 transfers, and four
//! wide shapes at two sizes each. A test fails when the peak is above the
//! factor (`peak::assert_within_factor`), the request bound, or the heap each
//! worker holds. A parser whose output grows faster than its input fails such
//! a test instead of reaching an image. `#[ignore]` marks the slow tests with
//! a history of 10 000 transfers, and CI runs them on the burn set. The tests
//! live next to the code they measure: `framing`,
//! `config`, the gas transaction decoder, consignment validation, PSBT and
//! fascia parsing, and attestation documents. The tests of whole requests
//! through `dispatch` are in `server::sign::request_memory` and
//! `server::rights_refill`. The meter counts the calling thread, so the
//! consignment tests run in-process the code of a validator child, and the
//! tests of a burn through `dispatch` measure the enclave side.
//!
//! Connections waiting in the queue hold no heap: a worker reads the frame
//! only when it starts the request.
//!
//! Reading a consignment or a fascia also uses RAM outside the heap. rgb-lib
//! takes each only from a file, so the enclave writes the bytes to a scratch
//! file in `std::env::temp_dir()`. In the enclave, `/tmp` is a tmpfs, so the
//! file takes up to `max_consignment_bytes` of RAM for a consignment and up to
//! `MAX_FASCIA_BYTES` for a fascia, and never more than the frame. The heap
//! meter does not count it. The file exists while the enclave keeps its
//! decoded copy and rgb-lib decodes a second one, so it adds to the request
//! peak. A request holds one such file at a time. A burn writes it before its
//! validator child starts and removes it after the child is reaped.
//!
//! The burn signer runs rgb-lib in a validator child, at most one for each
//! worker. Beside the validation heap, which the request bound counts, a
//! child takes [`validator_reserve`]: the process with rgb-lib's one-time
//! state ([`VALIDATOR_BASELINE_BYTES`]), its stack ([`VALIDATOR_STACK_BYTES`])
//! and its verdict frame, which the enclave reads while the child lives
//! ([`validator_frame_bytes`]).
//!
//! [`check_limits`] adds one file at the larger of the two limits and one
//! reserve for each worker, at boot and for a change of limits. At the image
//! values, they come from the memory that [`RUN_ENCLAVE_MEMORY_MIB`] keeps
//! above the minimum.

use crate::conn::WORKER_THREADS;
use crate::framing::{MAX_MESSAGE_SIZE, MAX_WIRE_ELEMENTS};
use crate::limits::Limits;
use crate::policy::{BuildContext, SignerRole};

/// Upper bound on the heap one request uses, as a multiple of its input size,
/// for most parsers that grow with their input. Reading a frame takes 3 times
/// the frame. Consignment validation of a long history takes about 21 times
/// the consignment, because rgb-lib decodes a second copy beside the one the
/// checks read. A fascia of many rights parses at about 11 times its bytes,
/// and the mint signer's whole fascia core at about 31 times. The
/// gas transaction parser stays under 0.1, and a PSBT whose bytes sit in
/// large records about 1.5. A whole burn request through `dispatch` keeps no
/// validation heap in the enclave, so it peaks at the read of its frame
/// (`server::sign::request_memory`). The parsers that take more on the
/// densest inputs measured have size limits (module docs). The tests count
/// requested bytes on the calling thread. The baseline includes allocator
/// overhead and fragmentation, and a parser that moves work to other threads
/// needs its own meter.
pub const REQUEST_MEMORY_FACTOR: usize = 24;

/// Heap one decoded protobuf element may use beyond its wire bytes. This
/// covers the struct in its vector, a vector header, and the copy a growing
/// vector holds during a move. The measured value is about 38 bytes per
/// occurrence, in a frame of [`MAX_WIRE_ELEMENTS`] empty headers
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
/// replay guards and the request queue. On the burn signer, each validator
/// child builds its own schema rules ([`VALIDATOR_BASELINE_BYTES`]). The
/// value is an estimate with headroom. The binary, the root file system and a
/// mainnet header chain are each well under 200 MiB.
pub const BASELINE_BYTES: usize = 512 * 1024 * 1024;

/// Usable memory the enclave needs to serve `WORKER_THREADS` largest requests
/// at once. The boot check requires at least this much in `MemTotal`.
pub const MIN_ENCLAVE_MEMORY_BYTES: usize =
    BASELINE_BYTES + WORKER_THREADS * request_bound(MAX_MESSAGE_SIZE as usize);

/// The least `nitro-cli run-enclave --memory` value, in MiB. `MemTotal` in
/// `/proc/meminfo` leaves out the memory the kernel keeps for itself, and the
/// root file system of the image sits in RAM too. So the launch value is
/// above [`MIN_ENCLAVE_MEMORY_BYTES`], with a margin for them. The consignment
/// scratch files and the validator children at the image values also come
/// from this margin.
///
/// The value is a whole number of GiB. nitro-cli gives an enclave whole
/// hugepages, 1 GiB pages first, and the allocator reserves its pool the same
/// way. A value such as 3584 MiB takes three 1 GiB pages and 256 pages of
/// 2 MiB. When no 2 MiB page is free, it takes a fourth 1 GiB page. So a pool
/// of three times 3584 MiB can hold only two such enclaves. At 4096 MiB,
/// three enclaves take exactly 12288 MiB, with any mix of 1 GiB and 2 MiB
/// pages.
///
/// The `MemTotal` reading at this value is 3943 MiB (2026-11-05, debug mode, an
/// `m6i.2xlarge` with nitro-cli 1.4.5). To take a new one, run one image at this
/// value with `ENCLAVE_DEBUG_MODE=1`. Make sure that
/// `nitro-cli describe-enclaves` shows this value in `MemoryMiB`. Then read
/// `total_mib` in the "memory check passed" line on `nitro-cli console`. It
/// must be at least the minimum. Record the reading here.
///
/// The deploy scripts and `docs/operations.md`
/// carry this value and the minimum as literals, and a test pins them to the
/// constants. The deploy scripts refuse a smaller `ENCLAVE_MEMORY`, or one
/// that is not a whole number of GiB, and check the hugepage pool.
pub const RUN_ENCLAVE_MEMORY_MIB: usize = 4096;

// The largest four requests fit in the part above the baseline. After the
// scratch files of `WORKER_THREADS` requests at the image consignment limit,
// and the validator reserves of a burn signer, the kernel and the root file
// system get at least 512 MiB of the launch value.
const _: () = assert!(
    MIN_ENCLAVE_MEMORY_BYTES - BASELINE_BYTES == 4 * (24 * 1024 * 1024 * 24 + 64 * 1024 * 1024)
);
const _: () = assert!(MIN_ENCLAVE_MEMORY_BYTES == 3072 * 1024 * 1024);
const _: () = assert!(
    RUN_ENCLAVE_MEMORY_MIB * 1024 * 1024
        - MIN_ENCLAVE_MEMORY_BYTES
        - WORKER_THREADS
            * (crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES + IMAGE_VALIDATOR_RESERVE_BYTES)
        >= 512 * 1024 * 1024
);
// See the hugepage rule in the doc of `RUN_ENCLAVE_MEMORY_MIB`.
const _: () = assert!(RUN_ENCLAVE_MEMORY_MIB.is_multiple_of(1024));

/// Memory one validator child takes beside the validation heap of its
/// request: the process, its runtime and rgb-lib's one-time state. The
/// smallest burn of `tests/support/bfa_burn.rs`, 1679 bytes, peaked at up to
/// 19.4 MiB resident in a debug child on macOS (aarch64); the value adds a
/// margin.
/// `tests/test_validator_child_memory.rs` checks it on Linux against an upper
/// bound of the child's peak: the larger of that peak and the peak of the test
/// process before the exec. An enclave logs the peak of each child in "RGB
/// validator ended".
pub const VALIDATOR_BASELINE_BYTES: usize = 48 * 1024 * 1024;

/// The main-thread stack limit a validator child sets; above a worker
/// thread's default stack.
pub const VALIDATOR_STACK_BYTES: usize = 8 * 1024 * 1024;

/// The part of a validator child's largest frame that does not grow with its
/// consignment.
pub const VALIDATOR_FRAME_FIXED_BYTES: usize = 64 * 1024;

/// The largest frame the enclave reads from a validator child: a verdict,
/// whose records take fewer bytes than its consignment.
pub fn validator_frame_bytes(limits: &Limits) -> u64 {
    limits.max_consignment_bytes.min(limits.max_message_bytes) + VALIDATOR_FRAME_FIXED_BYTES as u64
}

/// What a burn holds beyond its request bound because rgb-lib runs in a
/// child; zero for a build without validator children.
pub fn validator_reserve(limits: &Limits, build: &BuildContext) -> u64 {
    if !runs_validator_children(build) {
        return 0;
    }
    (VALIDATOR_BASELINE_BYTES + VALIDATOR_STACK_BYTES) as u64 + validator_frame_bytes(limits)
}

/// The burn signer validates each consignment in a validator child.
fn runs_validator_children(build: &BuildContext) -> bool {
    build.rgb_validation && build.signer_role == SignerRole::Burn
}

/// [`validator_reserve`] of a burn signer at the image values.
const IMAGE_VALIDATOR_RESERVE_BYTES: usize = VALIDATOR_BASELINE_BYTES
    + VALIDATOR_STACK_BYTES
    + crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES
    + VALIDATOR_FRAME_FIXED_BYTES;

/// Refuses to start a release build with less usable memory than
/// [`MIN_ENCLAVE_MEMORY_BYTES`], or than `limits`, the values in force at
/// boot, need as [`check_limits`] counts them, or with no readable total.
/// `main` panics on the refusal. A release build on a host with no
/// `/proc/meminfo` refuses to start too, for example the TCP fallback of
/// `main` on macOS. Debug and test builds run in local stacks of any size and
/// on other operating systems, so they log a warning instead. A pass logs the
/// total at info level, which is how a deploy reads `MemTotal` (see
/// [`RUN_ENCLAVE_MEMORY_MIB`]).
pub fn check_at_boot(limits: &Limits, ctx: &BuildContext) -> Result<(), String> {
    check(total_memory_bytes(), limits, ctx)
}

/// The boot check for a known total. `None` means `/proc/meminfo` could not
/// be read or has no `MemTotal` line.
fn check(total: Option<usize>, limits: &Limits, ctx: &BuildContext) -> Result<(), String> {
    let required_mib = MIN_ENCLAVE_MEMORY_BYTES / (1024 * 1024);
    let problem = match total {
        Some(total) if total >= MIN_ENCLAVE_MEMORY_BYTES => {
            check_limits_against(limits, Some(total), ctx).map_err(|e| {
                format!("{e}; give run-enclave --memory at least {RUN_ENCLAVE_MEMORY_MIB} MiB")
            })?;
            let total_mib = total / (1024 * 1024);
            let required_mib = needed_bytes(limits, ctx)
                .max(MIN_ENCLAVE_MEMORY_BYTES)
                .div_ceil(1024 * 1024);
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

/// Refuses limits whose requests do not fit the usable memory: the check of
/// [`check_at_boot`], for a change at run time ([`crate::limits`]), with the
/// scratch file and the validator reserve of each worker (module docs). So a
/// change cannot make a request that ends the enclave. A debug build only
/// logs a warning.
pub fn check_limits(limits: &Limits, ctx: &BuildContext) -> Result<(), String> {
    check_limits_against(limits, total_memory_bytes(), ctx)
}

/// The usable memory that `limits` need: the baseline, and for each worker
/// its request bound, its scratch file and its validator reserve.
fn needed_bytes(limits: &Limits, ctx: &BuildContext) -> usize {
    let request =
        limits.request_bound_bytes() + limits.scratch_file_bytes() + validator_reserve(limits, ctx);
    BASELINE_BYTES + WORKER_THREADS * request as usize
}

fn check_limits_against(
    limits: &Limits,
    total: Option<usize>,
    ctx: &BuildContext,
) -> Result<(), String> {
    let needed = needed_bytes(limits, ctx);
    let needed_mib = needed.div_ceil(1024 * 1024);
    let beside = match validator_reserve(limits, ctx) {
        0 => "their scratch files",
        _ => "their scratch files, their validator children",
    };
    let problem = match total {
        Some(total) if total >= needed => return Ok(()),
        Some(total) => format!(
            "these limits need {needed_mib} MiB of usable memory for {WORKER_THREADS} requests, \
             {beside} and the baseline, and the enclave has {} MiB",
            total / (1024 * 1024)
        ),
        None => format!("total memory unknown, and these limits need {needed_mib} MiB"),
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
        let image = Limits::DEFAULTS;
        let mint = release(SignerRole::Mint);
        assert!(check(Some(needed_bytes(&image, &mint)), &image, &mint).is_ok());
        let err = check(Some(MIN_ENCLAVE_MEMORY_BYTES - 1), &image, &mint).unwrap_err();
        assert!(err.contains("3071 MiB of usable memory"), "{err}");
        assert!(err.contains("--memory at least 4096 MiB"), "{err}");
        let err = check(None, &image, &mint).unwrap_err();
        assert!(err.contains("total memory unknown"), "{err}");
        assert!(check(Some(1), &image, &build(true)).is_ok());
    }

    /// At boot, the limits in force need what a change to them needs: their
    /// scratch files, and on a burn signer their validator reserves. A release
    /// build starts at that total and refuses one byte less.
    #[test]
    fn the_boot_check_needs_what_the_limits_in_force_need() {
        let image = Limits::DEFAULTS;
        let roles = [
            (SignerRole::Mint, 0, "need 3112 MiB"),
            (SignerRole::Burn, image_reserves(), "need 3377 MiB"),
        ];
        for (role, reserves, need) in roles {
            let build = release(role);
            let fits = MIN_ENCLAVE_MEMORY_BYTES + image_scratch_files() + reserves;
            assert_eq!(needed_bytes(&image, &build), fits, "{build:?}");
            assert!(check(Some(fits), &image, &build).is_ok(), "{build:?}");
            let err = check(Some(fits - 1), &image, &build).unwrap_err();
            assert!(err.contains(need), "{err}");
            assert!(err.contains("--memory at least 4096 MiB"), "{err}");
            assert!(check_limits_against(&image, Some(fits - 1), &build).is_err());
            let debug = BuildContext {
                debug_or_test: true,
                ..build
            };
            assert!(check(Some(fits - 1), &image, &debug).is_ok());
        }
    }

    const MIB: usize = 1024 * 1024;

    /// A release build of `role` with RGB validation.
    fn release(role: SignerRole) -> BuildContext {
        BuildContext {
            debug_or_test: false,
            rgb_validation: true,
            signer_role: role,
            ..BuildContext::current()
        }
    }

    /// The scratch files of [`WORKER_THREADS`] requests at the image values.
    fn image_scratch_files() -> usize {
        WORKER_THREADS * Limits::DEFAULTS.scratch_file_bytes() as usize
    }

    /// The validator reserves of [`WORKER_THREADS`] burns at the image values.
    fn image_reserves() -> usize {
        WORKER_THREADS * IMAGE_VALIDATOR_RESERVE_BYTES
    }

    /// A release build refuses limits that need more memory than it has, and
    /// the image limits fit the minimum with their scratch files and the
    /// reserves of a burn signer.
    #[test]
    fn a_change_of_limits_must_fit_the_usable_memory() {
        let image = Limits::DEFAULTS;
        let burn = release(SignerRole::Burn);
        let fits = MIN_ENCLAVE_MEMORY_BYTES + image_scratch_files() + image_reserves();
        assert!(check_limits_against(&image, Some(fits), &burn).is_ok());
        let larger = Limits {
            max_message_bytes: 2 * image.max_message_bytes,
            ..image
        };
        let err = check_limits_against(&larger, Some(fits), &burn).unwrap_err();
        assert!(err.contains("these limits need"), "{err}");
        assert!(check_limits_against(&larger, None, &burn).is_err());
        assert!(check_limits_against(&larger, Some(1), &build(true)).is_ok());
    }

    /// Each worker can hold a scratch file of `max_consignment_bytes` or of
    /// `MAX_FASCIA_BYTES`, whichever is larger, beside its heap, and never more
    /// than its frame. So the image values need memory for them above the
    /// minimum. A mint signer runs no validator child, so only its files count.
    #[test]
    fn a_change_of_limits_counts_a_scratch_file_for_each_worker() {
        let image = Limits::DEFAULTS;
        let mint = release(SignerRole::Mint);
        assert_eq!(image_scratch_files(), 40 * MIB);
        let fits = MIN_ENCLAVE_MEMORY_BYTES + image_scratch_files();
        let err = check_limits_against(&image, Some(fits - 1), &mint).unwrap_err();
        let need = format!("need {} MiB", fits.div_ceil(MIB));
        assert!(err.contains(&need), "{err}");
        assert!(
            err.contains("their scratch files and the baseline"),
            "{err}"
        );

        // One MiB more of consignment takes one MiB more on each worker.
        let larger = Limits {
            max_consignment_bytes: image.max_consignment_bytes + MIB as u64,
            ..image
        };
        let needed = fits + WORKER_THREADS * MIB;
        assert!(check_limits_against(&larger, Some(needed - 1), &mint).is_err());
        assert!(check_limits_against(&larger, Some(needed), &mint).is_ok());

        // Under the fascia limit, a fascia file sets the bound instead.
        let fascia = crate::config::MAX_FASCIA_BYTES;
        let small = Limits {
            max_consignment_bytes: 1024,
            ..image
        };
        let needed = MIN_ENCLAVE_MEMORY_BYTES + WORKER_THREADS * fascia;
        assert!(check_limits_against(&small, Some(needed - 1), &mint).is_err());
        assert!(check_limits_against(&small, Some(needed), &mint).is_ok());

        // A frame cannot carry a larger file.
        let frame = image.max_message_bytes;
        let needed = MIN_ENCLAVE_MEMORY_BYTES + WORKER_THREADS * frame as usize;
        for bytes in [frame, 2 * frame, 1 << 32] {
            let limits = Limits {
                max_consignment_bytes: bytes,
                ..image
            };
            assert!(check_limits_against(&limits, Some(needed - 1), &mint).is_err());
            assert!(check_limits_against(&limits, Some(needed), &mint).is_ok());
        }
    }

    /// The launch margin counts the reserve of a burn signer at the image
    /// values. A build without validator children has none.
    #[test]
    fn validator_reserve_of_the_image_values_is_the_one_the_launch_margin_counts() {
        let image = Limits::DEFAULTS;
        let reserve = validator_reserve(&image, &release(SignerRole::Burn));
        assert_eq!(reserve, IMAGE_VALIDATOR_RESERVE_BYTES as u64);
        // The verdict of a consignment at the image limit.
        let frame = image.max_consignment_bytes + VALIDATOR_FRAME_FIXED_BYTES as u64;
        assert_eq!(validator_frame_bytes(&image), frame);
        let child = (VALIDATOR_BASELINE_BYTES + VALIDATOR_STACK_BYTES) as u64;
        assert_eq!(reserve, child + frame);
        let unvalidated = BuildContext {
            rgb_validation: false,
            ..release(SignerRole::Burn)
        };
        for build in [
            release(SignerRole::Mint),
            release(SignerRole::Combined),
            unvalidated,
        ] {
            assert_eq!(validator_reserve(&image, &build), 0, "{build:?}");
        }
    }

    /// A burn signer needs the reserve of a validator child on each worker,
    /// beside the request bound and the scratch file. A larger consignment
    /// takes a larger verdict frame, up to the frame limit.
    #[test]
    fn a_change_of_limits_counts_a_validator_reserve_per_worker() {
        let image = Limits::DEFAULTS;
        let burn = release(SignerRole::Burn);
        let fits = MIN_ENCLAVE_MEMORY_BYTES + image_scratch_files() + image_reserves();
        assert!(check_limits_against(&image, Some(fits), &burn).is_ok());
        let err = check_limits_against(&image, Some(fits - 1), &burn).unwrap_err();
        let need = format!("need {} MiB", fits.div_ceil(MIB));
        assert!(err.contains(&need), "{err}");
        assert!(err.contains("their validator children"), "{err}");
        let mint = release(SignerRole::Mint);
        let fits_mint = fits - image_reserves();
        assert!(check_limits_against(&image, Some(fits_mint), &mint).is_ok());

        // One MiB more of consignment takes one more for the file and one
        // more for the verdict on each worker.
        let larger = Limits {
            max_consignment_bytes: image.max_consignment_bytes + MIB as u64,
            ..image
        };
        let needed = fits + WORKER_THREADS * 2 * MIB;
        assert!(check_limits_against(&larger, Some(needed - 1), &burn).is_err());
        assert!(check_limits_against(&larger, Some(needed), &burn).is_ok());

        // A frame cannot carry a larger verdict.
        let fixed = VALIDATOR_FRAME_FIXED_BYTES as u64;
        let frame = image.max_message_bytes;
        for bytes in [frame, 2 * frame, 1 << 32] {
            let limits = Limits {
                max_consignment_bytes: bytes,
                ..image
            };
            assert_eq!(validator_frame_bytes(&limits), frame + fixed);
        }
        let small = Limits {
            max_message_bytes: MIB as u64,
            ..image
        };
        assert_eq!(validator_frame_bytes(&small), MIB as u64 + fixed);
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
        let checks: [(&str, &str, usize, Vec<String>); 3] = [
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
                "docs/operations.md",
                include_str!("../../docs/operations.md"),
                1,
                vec![
                    format!("--memory {run} "),
                    format!("at least {run} MiB"),
                    format!("needs {min} MiB of usable"),
                ],
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
}

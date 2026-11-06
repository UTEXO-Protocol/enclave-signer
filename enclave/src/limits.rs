//! The time, memory and size limits, and how the operator changes them.
//!
//! A value here only sets when the enclave refuses a request or how long it
//! waits. So these values are configuration, not policy. The operator changes
//! them with `SetLimits` (`utexo-bridge-parent-cli limits`), and a change needs
//! no new image. The attestation does not cover them. Safety rules stay in the
//! image: the SPV depth, the fee limits, the clone replay guard and the pins.
//!
//! The mint replay guard is here because it is not a safety rule. A shorter
//! window lets a rebuilt mint for one deposit reach the signer sooner. Each
//! signature for that mint spends the same UTXO, so Bitcoin confirms at most
//! one (`docs/mint-flow.md`, section 6). A restart clears the guard anyway.
//!
//! The image sets the start values. [`Limits::DEFAULTS`] holds the constants of
//! the image, and [`Limits::image`] adds the request limits of `BridgeConfig`.
//! A change holds only until the enclave restarts. The deploy scripts send the
//! values of `/etc/utexo/enclave-limits.conf` again at each launch.
//!
//! Two kinds of limit stay constants. [`crate::conn::WORKER_THREADS`] and
//! [`crate::conn::MAX_QUEUED_CONNECTIONS`] set up the accept loop at boot. Small
//! fixed formats need no setting: a mnemonic, an envelope, a KMS reply.
//!
//! A change can only make a value that [`Limits::check`] accepts. Each limit
//! has a range, so no value can stop the operator from reaching the enclave
//! again. The checks across limits keep the request memory model
//! (`memory.rs`), and they keep the time budget of rgb-lib below the request
//! deadline.

use std::time::Duration;

use crate::config::BridgeConfig;
use crate::conn::{IO_IDLE_TIMEOUT, TOTAL_REQUEST_TIMEOUT};
use crate::framing::{MAX_MESSAGE_SIZE, MAX_WIRE_ELEMENTS};
use crate::proto;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Defines [`Limits`] from one row for each limit: name, value of the image,
/// lowest value, highest value.
macro_rules! limits {
    ($($(#[$doc:meta])* $name:ident: $default:expr, $low:expr, $high:expr;)*) => {
        /// A value for each limit. The units are in the names.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct Limits {
            $($(#[$doc])* pub $name: u64,)*
        }

        impl Limits {
            /// The constants of the image.
            pub const DEFAULTS: Self = Self { $($name: $default,)* };
            /// No value: nothing changes.
            const NONE: Self = Self { $($name: 0,)* };

            /// `self`, with each non-zero value of `changes` in its place.
            #[must_use]
            pub fn with(mut self, changes: &Self) -> Self {
                $(if changes.$name != 0 {
                    self.$name = changes.$name;
                })*
                self
            }

            fn check_ranges(&self) -> Result<(), String> {
                $(if !($low..=$high).contains(&self.$name) {
                    return Err(format!(
                        "{} is {}; it must be from {} to {}",
                        stringify!($name), self.$name, $low, $high
                    ));
                })*
                Ok(())
            }
        }

        impl From<&Limits> for proto::Limits {
            fn from(limits: &Limits) -> Self {
                Self { $($name: limits.$name,)* }
            }
        }

        impl From<&proto::Limits> for Limits {
            fn from(limits: &proto::Limits) -> Self {
                Self { $($name: limits.$name,)* }
            }
        }
    };
}

limits! {
    /// Socket deadline of one request, from accept
    /// ([`crate::conn::TOTAL_REQUEST_TIMEOUT`]). The highest value stays below
    /// the time that the parent waits.
    total_request_timeout_secs: TOTAL_REQUEST_TIMEOUT.as_secs(), 10, MAX_REQUEST_TIMEOUT_SECS;
    /// The longest time one socket read or write can block.
    io_idle_timeout_secs: IO_IDLE_TIMEOUT.as_secs(), 2, 60;
    /// Time for the first bytes of an egress client connection.
    first_bytes_timeout_secs: crate::egress::FIRST_BYTES_TIMEOUT.as_secs(), 1, 60;
    /// Time for each socket operation of the Electrum client. Without a
    /// timeout, a stalled read blocks the worker thread for ever. The ingress
    /// deadline does not cancel indexer work.
    electrum_timeout_secs: 15, 1, 90;
    /// Time for one Esplora HTTP call, connect and read.
    esplora_timeout_secs: 30, 1, 90;
    /// Time for one EVM JSON-RPC call. Without a timeout, a hung RPC blocks the
    /// worker thread for ever: `block_on` has no deadline, and alloy and reqwest
    /// set no timeout of their own. The ingress deadline does not cancel this
    /// work, so a few stalls can hold all the workers. The value of the image
    /// covers a healthy fetch through loopback, vsock and the RPC.
    evm_rpc_timeout_secs: 15, 1, MAX_EVM_RPC_TIMEOUT_SECS;
    /// Modeled time of rgb-lib on one consignment, validation and inspection
    /// (`validation::cost`). A 12 MiB history of transfers takes rgb-lib 15 s
    /// to validate alone, and the caps add up. The rgb-lib work runs on one
    /// worker, and the deadline does not stop it. The value of the image passes
    /// a history of 10 000 transfers with an SPV proof on each, which models at
    /// 19.95 s, and refuses the forged shapes of `validation/tests/caps.rs`,
    /// which model at 25 s and more.
    max_rgb_lib_ms: 21_000, 1_000, 75_000;
    /// Steps to check transitions against their witness txs. Forged bundles at
    /// the value of the image take rgb-lib 1.6 to 2.5 s. The burn of 2810 mints
    /// costs 8.5M (`validation/tests/caps.rs`, docs/burn-flow.md).
    max_witness_check_cost: 128 * MIB, MIB, 4_096 * MIB;
    /// Steps to hash bundle ids. 512 transitions in one bundle (one over) take
    /// rgb-lib 1.2 s, 2048 take 15.5 s. The burn of 2810 mints costs 11k.
    max_bundle_id_cost: 256 * KIB, KIB, 16 * MIB;
    /// Steps of the reject-list walk. The value of the image is about 5 s of
    /// walk at the measured 45 to 73 ns per step. The burn of 2810 mints costs
    /// 14k.
    max_reject_walk_cost: 64 * MIB, MIB, 2_048 * MIB;
    /// Entries of a reject list. Over this value the enclave refuses each
    /// request that reads the list. The list is append-only, so it cannot get
    /// shorter again. Each page takes one RPC call of the request deadline. At
    /// about a second for each page, the value of the image fits 30 s.
    max_reject_list_entries: 20_000, 1, 1 << 20;
    /// Entries in one `entries` call of a reject list. The value of the image
    /// is the page of rgb-lib. The page does not change what the enclave reads.
    reject_list_page_entries: 1_000, 1, 10_000;
    /// Size of one frame. The parent has its own limit too.
    max_message_bytes: MAX_MESSAGE_SIZE as u64, MIB, 256 * MIB;
    /// Protobuf field occurrences in one request.
    max_wire_elements: MAX_WIRE_ELEMENTS as u64, 1_024, 1 << 24;
    /// Size of one consignment.
    max_consignment_bytes: crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES as u64, KIB, 128 * MIB;
    /// Merkle proofs of one request.
    max_merkle_proofs: crate::config::DEFAULT_MAX_MERKLE_PROOFS as u64, 1, 1 << 20;
    /// Size of all the Merkle proofs of one request.
    max_total_proof_bytes: crate::config::DEFAULT_MAX_TOTAL_PROOF_BYTES as u64, KIB, 128 * MIB;
    /// Size of one PSBT or fascia.
    max_psbt_bytes: crate::config::MAX_PSBT_BYTES as u64, KIB, 16 * MIB;
    /// Size of an unsigned gas transaction.
    max_gas_tx_bytes: 1024 * KIB, KIB, 16 * MIB;
    /// RLP items of a gas transaction: every string and list, at any depth. A
    /// gas tx has 9 fields and a small or empty access list. Each decoded item
    /// takes 24 bytes, however short its encoding is. Without this limit, a
    /// 24 MiB request of one-byte empty lists decodes into more than 1 GiB.
    /// Calldata is one item at any length.
    max_rlp_items: 1024, 16, 1 << 20;
    /// Size of the calldata of a fundsOut.
    max_funds_out_call_data_bytes: 96 * KIB, KIB, 16 * MIB;
    /// Headers in one `SubmitHeaders`.
    max_headers_per_submit: 10_000, 1, 1 << 20;
    /// Headers in one minute.
    max_headers_per_minute: 100_000, 1, 1 << 24;
    /// How long the mint signer refuses a second request for one deposit. A
    /// retry of the same request does not reach the enclave: the parent answers
    /// it from the reply it kept (parent `signed_responses`). The value of the
    /// image covers the retry backoff of the listener and the usual
    /// confirmation of the first transaction. The PSBT is not part of the key,
    /// so a mint rebuilt for the same deposit (other inputs, higher fee) is
    /// refused until this time has passed. The lowest value is above the highest
    /// request deadline, so an entry outlives the request that made it.
    mint_replay_ttl_secs: 3_600, 120, 7 * 24 * 3_600;
    /// Deposits that the mint replay guard holds. When it is full, the guard
    /// removes the oldest entry and does not block signing.
    mint_replay_max_entries: 100_000, 1_024, 1 << 20;
}

/// The highest request deadline. The parent waits 10 s longer for a `Sign`
/// (`parent::grpc_server::SIGN_TIMEOUT`), because the enclave must give up
/// first: its failed write rolls the replay key back.
pub const MAX_REQUEST_TIMEOUT_SECS: u64 = 100;

/// The highest `evm_rpc_timeout_secs`. The EVM RPC client lives as long as the
/// enclave, so it gets this value as its own timeout, and each call applies the
/// value in force.
pub const MAX_EVM_RPC_TIMEOUT_SECS: u64 = 90;

/// The heap of a consignment at the densest rate measured, in tenths of a byte
/// for each byte, with the margin of the test
/// (`validation::tests::the_densest_consignments_at_the_limit_fit_the_heap_each_worker_holds`).
const DENSE_CONSIGNMENT_RATE_TENTHS: u64 = 542;
/// The heap of a consignment that does not grow with it.
const CONSIGNMENT_FIXED_BYTES: u64 = 3 * MIB;
/// The heap of a PSBT at the densest rate measured.
const DENSE_PSBT_RATE: u64 = 103;
/// The heap of one entry of a reject list, from the read to the set that
/// rgb-lib walks with, with a margin on the rate measured
/// (`networks::evm::reject_list::tests`). A request holds this beside the rest.
pub(crate) const REJECT_LIST_ENTRY_BYTES: u64 = 220;
/// The heap of one entry of the mint replay guard, with a margin on the rate
/// measured (`state::tests`). The baseline covers the entries of the image.
pub(crate) const MINT_REPLAY_ENTRY_BYTES: u64 = 200;

impl Limits {
    /// The values of the image: the constants, and the request limits that
    /// `MAX_CONSIGNMENT_BYTES`, `MAX_MERKLE_PROOFS` and `MAX_TOTAL_PROOF_BYTES`
    /// can lower.
    pub fn image(cfg: &BridgeConfig) -> Self {
        Self {
            max_consignment_bytes: cfg.max_consignment_bytes as u64,
            max_merkle_proofs: cfg.max_merkle_proofs as u64,
            max_total_proof_bytes: cfg.max_total_proof_bytes as u64,
            ..Self::DEFAULTS
        }
    }

    /// Refuses values outside their range, or that do not fit each other.
    pub fn check(&self) -> Result<(), String> {
        self.check_ranges()?;
        // The enclave's own work on a request runs beside rgb-lib. A request
        // past the deadline does all its work and then loses its reply.
        if self.max_rgb_lib_ms * 4 > self.total_request_timeout_secs * 1000 * 3 {
            return Err(format!(
                "max_rgb_lib_ms is {}; it must be at most three quarters of \
                 total_request_timeout_secs, {} s",
                self.max_rgb_lib_ms, self.total_request_timeout_secs
            ));
        }
        if self.io_idle_timeout_secs > self.total_request_timeout_secs {
            return Err(format!(
                "io_idle_timeout_secs is {}; it must be at most \
                 total_request_timeout_secs, {}",
                self.io_idle_timeout_secs, self.total_request_timeout_secs
            ));
        }
        // The boot check gives each worker the heap of the image values. So a
        // lower frame limit keeps that heap.
        let held = self
            .request_bound_bytes()
            .max(Self::DEFAULTS.request_bound_bytes());
        let frame = self.max_message_bytes;
        let elements = self.elements_bytes();
        // Validation runs beside the decoded request (`memory.rs`). A frame
        // cannot carry more than itself.
        let consignment = self.max_consignment_bytes.min(frame) * DENSE_CONSIGNMENT_RATE_TENTHS
            / 10
            + CONSIGNMENT_FIXED_BYTES;
        let list = self.max_reject_list_entries * REJECT_LIST_ENTRY_BYTES;
        let request = (3 * frame).max(frame + consignment) + elements + list;
        if request > held {
            return Err(format!(
                "max_consignment_bytes is {} and max_reject_list_entries is {}; a burn with the \
                 densest consignment and a list at those sizes takes {request} bytes, over the \
                 {held} bytes of a {frame}-byte frame",
                self.max_consignment_bytes, self.max_reject_list_entries
            ));
        }
        let psbts = 2 * self.max_psbt_bytes.min(frame) * DENSE_PSBT_RATE + 3 * frame + elements;
        if psbts > held {
            return Err(format!(
                "max_psbt_bytes is {}; two dense PSBTs at that size take {psbts} bytes, over the \
                 {held} bytes of a {frame}-byte frame",
                self.max_psbt_bytes
            ));
        }
        Ok(())
    }

    fn elements_bytes(&self) -> u64 {
        self.max_wire_elements * crate::memory::WIRE_ELEMENT_BYTES as u64
    }

    /// The most heap one request can use under these values.
    pub fn request_bound_bytes(&self) -> u64 {
        crate::memory::REQUEST_MEMORY_FACTOR as u64 * self.max_message_bytes + self.elements_bytes()
    }

    /// The heap of the mint replay guard above the entries that the baseline
    /// covers.
    pub fn replay_guard_growth_bytes(&self) -> u64 {
        self.mint_replay_max_entries
            .saturating_sub(Self::DEFAULTS.mint_replay_max_entries)
            * MINT_REPLAY_ENTRY_BYTES
    }

    /// The socket deadline of one request.
    pub fn total_request_timeout(&self) -> Duration {
        Duration::from_secs(self.total_request_timeout_secs)
    }

    /// The longest time one socket read or write can block.
    pub fn io_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.io_idle_timeout_secs)
    }

    /// The modeled time of rgb-lib, in ns.
    pub fn max_rgb_lib_ns(&self) -> u64 {
        self.max_rgb_lib_ms * 1_000_000
    }
}

#[cfg(not(test))]
mod store {
    use super::Limits;
    use std::sync::RwLock;

    static CHANGES: RwLock<Limits> = RwLock::new(Limits::NONE);

    pub(super) fn read() -> Limits {
        *CHANGES.read().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn update<T>(f: impl FnOnce(&mut Limits) -> T) -> T {
        f(&mut CHANGES.write().unwrap_or_else(|e| e.into_inner()))
    }
}

/// Each test thread has its own values, so a test that changes a limit cannot
/// reach another test.
#[cfg(test)]
mod store {
    use super::Limits;
    use std::cell::Cell;

    thread_local! {
        static CHANGES: Cell<Limits> = const { Cell::new(Limits::NONE) };
    }

    pub(super) fn read() -> Limits {
        CHANGES.with(Cell::get)
    }

    pub(super) fn update<T>(f: impl FnOnce(&mut Limits) -> T) -> T {
        CHANGES.with(|changes| {
            let mut limits = changes.get();
            let result = f(&mut limits);
            changes.set(limits);
            result
        })
    }
}

/// Changes limits for the calling test. Each test thread has its own values.
#[cfg(test)]
pub(crate) fn change_for_test(edit: impl FnOnce(&mut Limits)) {
    let mut changes = Limits::NONE;
    edit(&mut changes);
    apply(&BridgeConfig::default(), &changes, false, |_| Ok(()))
        .expect("the test changes the limits to values that pass the checks");
}

/// The values in force. The three request limits of `BridgeConfig` show their
/// constants here, so read those with [`in_force`].
pub fn get() -> Limits {
    Limits::DEFAULTS.with(&store::read())
}

/// The values in force for `cfg`.
pub fn in_force(cfg: &BridgeConfig) -> Limits {
    Limits::image(cfg).with(&store::read())
}

/// Applies `changes` to the values in force for `cfg`, after the `reset` to the
/// image values if asked. Refuses and changes nothing if the result does not
/// pass `check`, which also gets the memory that the result needs. Returns the
/// values in force.
pub fn apply(
    cfg: &BridgeConfig,
    changes: &Limits,
    reset: bool,
    check: impl FnOnce(&Limits) -> Result<(), String>,
) -> Result<Limits, String> {
    store::update(|stored| {
        let base = if reset { Limits::NONE } else { *stored };
        let next = base.with(changes);
        let limits = Limits::image(cfg).with(&next);
        limits.check()?;
        check(&limits)?;
        *stored = next;
        Ok(limits)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MIN_ENCLAVE_MEMORY_BYTES, RUN_ENCLAVE_MEMORY_MIB};

    fn changes(edit: impl FnOnce(&mut Limits)) -> Limits {
        let mut limits = Limits::NONE;
        edit(&mut limits);
        limits
    }

    fn accept(_: &Limits) -> Result<(), String> {
        Ok(())
    }

    fn apply_to_defaults(edit: impl FnOnce(&mut Limits)) -> Result<Limits, String> {
        apply(&BridgeConfig::default(), &changes(edit), false, accept)
    }

    /// The image values must pass the rules that a change must pass, and they
    /// must equal the constants that the memory model uses.
    #[test]
    fn the_image_values_pass_the_checks_and_match_the_memory_model() {
        Limits::DEFAULTS.check().unwrap();
        Limits::image(&BridgeConfig::default()).check().unwrap();
        assert_eq!(
            Limits::DEFAULTS.request_bound_bytes() as usize,
            crate::memory::request_bound(MAX_MESSAGE_SIZE as usize)
        );
        let needed = crate::memory::BASELINE_BYTES as u64
            + Limits::DEFAULTS.replay_guard_growth_bytes()
            + crate::conn::WORKER_THREADS as u64 * Limits::DEFAULTS.request_bound_bytes();
        assert_eq!(needed as usize, MIN_ENCLAVE_MEMORY_BYTES);
        assert!(needed <= RUN_ENCLAVE_MEMORY_MIB as u64 * MIB);
    }

    #[test]
    fn a_change_holds_until_a_reset_and_keeps_the_other_values() {
        let cfg = BridgeConfig::default();
        let limits = apply_to_defaults(|l| l.max_rgb_lib_ms = 20_000).unwrap();
        assert_eq!(limits.max_rgb_lib_ms, 20_000);
        assert_eq!(get().max_rgb_lib_ms, 20_000);
        assert_eq!(get().max_psbt_bytes, Limits::DEFAULTS.max_psbt_bytes);

        apply_to_defaults(|l| l.max_psbt_bytes = 2 * MIB).unwrap();
        assert_eq!(
            get().max_rgb_lib_ms,
            20_000,
            "a second change keeps the first"
        );

        let limits = apply(&cfg, &Limits::NONE, true, accept).unwrap();
        assert_eq!(limits, Limits::image(&cfg));
        assert_eq!(get(), Limits::DEFAULTS);
    }

    #[test]
    fn a_reset_with_values_keeps_only_those_values() {
        apply_to_defaults(|l| l.max_rgb_lib_ms = 20_000).unwrap();
        let limits = apply(
            &BridgeConfig::default(),
            &changes(|l| l.max_psbt_bytes = 2 * MIB),
            true,
            accept,
        )
        .unwrap();
        assert_eq!(limits.max_rgb_lib_ms, Limits::DEFAULTS.max_rgb_lib_ms);
        assert_eq!(limits.max_psbt_bytes, 2 * MIB);
    }

    #[test]
    fn a_refused_change_changes_nothing() {
        apply_to_defaults(|l| l.max_rgb_lib_ms = 20_000).unwrap();
        let err = apply_to_defaults(|l| {
            l.max_psbt_bytes = 2 * MIB;
            l.total_request_timeout_secs = 1;
        })
        .unwrap_err();
        assert!(err.contains("total_request_timeout_secs is 1"), "{err}");
        assert_eq!(get().max_rgb_lib_ms, 20_000);
        assert_eq!(get().max_psbt_bytes, Limits::DEFAULTS.max_psbt_bytes);
    }

    #[test]
    fn the_memory_check_of_the_caller_can_refuse_a_change() {
        let err = apply(
            &BridgeConfig::default(),
            &changes(|l| l.max_message_bytes = 48 * MIB),
            false,
            |_| Err("no memory".into()),
        )
        .unwrap_err();
        assert_eq!(err, "no memory");
        assert_eq!(get(), Limits::DEFAULTS);
    }

    /// The trap of a budget at the deadline: the gate passes a request, and the
    /// request then loses its reply.
    #[test]
    fn the_rgb_lib_budget_must_stay_below_the_deadline() {
        let err = apply_to_defaults(|l| l.max_rgb_lib_ms = 30_000).unwrap_err();
        assert!(err.contains("three quarters"), "{err}");
        let limits = apply_to_defaults(|l| {
            l.max_rgb_lib_ms = 30_000;
            l.total_request_timeout_secs = 40;
        })
        .unwrap();
        assert_eq!(limits.max_rgb_lib_ms, 30_000);
    }

    /// A larger consignment or PSBT needs a larger frame budget. The memory
    /// model holds at each size that passes. A lower frame limit needs nothing.
    #[test]
    fn the_size_limits_must_fit_the_heap_of_a_frame() {
        let err = apply_to_defaults(|l| l.max_consignment_bytes = 11 * MIB).unwrap_err();
        assert!(err.contains("max_consignment_bytes"), "{err}");
        let err = apply_to_defaults(|l| l.max_psbt_bytes = 3 * MIB).unwrap_err();
        assert!(err.contains("max_psbt_bytes"), "{err}");
        apply_to_defaults(|l| {
            l.max_consignment_bytes = 11 * MIB;
            l.max_message_bytes = 32 * MIB;
        })
        .unwrap();
        apply_to_defaults(|l| {
            l.max_consignment_bytes = Limits::DEFAULTS.max_consignment_bytes;
            l.max_message_bytes = MIB;
        })
        .unwrap();
    }

    /// A burn holds the list beside the rest of the request. A longer list
    /// takes a smaller consignment or a larger frame budget.
    #[test]
    fn a_long_reject_list_must_fit_the_heap_of_a_frame() {
        apply_to_defaults(|l| l.max_reject_list_entries = 30_000).unwrap();
        let err = apply_to_defaults(|l| l.max_reject_list_entries = 40_000).unwrap_err();
        assert!(err.contains("max_reject_list_entries is 40000"), "{err}");
        apply_to_defaults(|l| {
            l.max_reject_list_entries = 100_000;
            l.max_consignment_bytes = 10_000_000;
        })
        .unwrap();
    }

    /// An entry outlives the request that made it, at the highest deadline
    /// and the 10 s that the parent waits after it.
    #[test]
    fn the_lowest_mint_replay_window_outlives_each_request() {
        let lowest = 120;
        assert!(lowest > MAX_REQUEST_TIMEOUT_SECS + 10);
        apply_to_defaults(|l| l.mint_replay_ttl_secs = lowest).unwrap();
        let err = apply_to_defaults(|l| l.mint_replay_ttl_secs = lowest - 1).unwrap_err();
        assert!(err.contains("mint_replay_ttl_secs"), "{err}");
    }

    /// The EVM RPC client keeps this value for its whole life, so no value in
    /// force can pass it.
    #[test]
    fn the_evm_rpc_timeout_stops_at_the_timeout_of_the_client() {
        apply_to_defaults(|l| l.evm_rpc_timeout_secs = MAX_EVM_RPC_TIMEOUT_SECS).unwrap();
        let err = apply_to_defaults(|l| l.evm_rpc_timeout_secs = MAX_EVM_RPC_TIMEOUT_SECS + 1)
            .unwrap_err();
        assert!(err.contains("evm_rpc_timeout_secs"), "{err}");
    }

    /// `SetLimits` is 250 bytes at most, so the lowest values still let the
    /// operator reach the enclave and raise them again.
    #[test]
    fn the_lowest_values_keep_the_enclave_reachable() {
        let lowest = changes(|l| {
            l.max_message_bytes = MIB;
            l.max_wire_elements = 1_024;
            l.total_request_timeout_secs = 10;
            l.io_idle_timeout_secs = 2;
            l.max_rgb_lib_ms = 1_000;
            l.max_consignment_bytes = KIB;
            l.max_psbt_bytes = KIB;
        });
        apply(&BridgeConfig::default(), &lowest, false, accept).unwrap();
    }

    #[test]
    fn the_config_values_are_the_start_values_of_the_request_limits() {
        let cfg = BridgeConfig {
            max_consignment_bytes: 1024,
            ..BridgeConfig::default()
        };
        assert_eq!(in_force(&cfg).max_consignment_bytes, 1024);
        apply(
            &cfg,
            &changes(|l| l.max_consignment_bytes = 2048),
            false,
            accept,
        )
        .unwrap();
        assert_eq!(in_force(&cfg).max_consignment_bytes, 2048);
    }

    #[test]
    fn the_proto_keeps_each_value() {
        let limits = Limits::DEFAULTS;
        let wire = proto::Limits::from(&limits);
        assert_eq!(Limits::from(&wire), limits);
    }
}

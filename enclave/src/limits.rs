//! The time, memory and size limits, and how the operator changes them.
//!
//! A value here only sets when the enclave refuses a request or how long it
//! waits. So these values are configuration, not policy. The operator changes
//! them with `SetLimits` (`utexo-bridge-parent-cli limits`), and a change needs
//! no new image. The attestation does not cover them. Safety rules stay in the
//! image: the SPV depth, the fee limits, the clone replay guard and the pins.
//!
//! The mint replay guard is here because it is not a safety rule. A shorter
//! window lets a retry for one deposit reach the signer sooner. Each signature
//! for that deposit is for the one transaction that its lockId names (M6), so
//! Bitcoin confirms at most one (`docs/mint-flow.md`, section 6). A restart
//! clears the guard anyway.
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
//! A change can only make a value that [`Limits::check`] accepts. The lowest
//! value of each limit keeps the enclave reachable, so the operator can always
//! send a new change. The highest values are very wide on purpose, because
//! validation takes longer as histories grow, and a new image costs a change of
//! the PCR values. They only stop a typing error and an overflow. The checks
//! across limits protect the enclave: they keep the request memory model
//! (`memory.rs`), and they keep each per-call timeout within the request
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
            /// The highest value of each limit.
            #[cfg(test)]
            const HIGHEST: Self = Self { $($name: $high,)* };

            /// `self`, with each non-zero value of `changes` in its place.
            #[must_use]
            pub fn with(mut self, changes: &Self) -> Self {
                $(if changes.$name != 0 {
                    self.$name = changes.$name;
                })*
                self
            }

            fn check_ranges(&self) -> Result<(), String> {
                $({
                    let (low, high): (u64, u64) = ($low, $high);
                    if !(low..=high).contains(&self.$name) {
                        return Err(format!(
                            "{} is {}; it must be from {low} to {high}",
                            stringify!($name), self.$name
                        ));
                    }
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
    /// ([`crate::conn::TOTAL_REQUEST_TIMEOUT`]). The parent reads the value in
    /// force and waits longer by its margin (`ENCLAVE_WAIT_MARGIN_SECS` in
    /// `parent/src/grpc_server.rs`), so the enclave still gives up first.
    total_request_timeout_secs: TOTAL_REQUEST_TIMEOUT.as_secs(), 10, 86_400;
    /// The longest time one socket read or write can block.
    io_idle_timeout_secs: IO_IDLE_TIMEOUT.as_secs(), 2, 3_600;
    /// Time for the first bytes of an egress client connection.
    first_bytes_timeout_secs: crate::egress::FIRST_BYTES_TIMEOUT.as_secs(), 1, 3_600;
    /// Time for one EVM JSON-RPC call. Without a timeout, a hung RPC blocks the
    /// worker thread for ever: `block_on` has no deadline, and alloy and reqwest
    /// set no timeout of their own. The ingress deadline does not cancel this
    /// work, so a few stalls can hold all the workers. The value of the image
    /// covers a healthy fetch through loopback, vsock and the RPC.
    evm_rpc_timeout_secs: 15, 1, 3_600;
    /// Entries of a reject list. Over this value the enclave refuses each
    /// request that reads the list. The list is append-only, so it cannot get
    /// shorter again. Each page takes one RPC call of the request deadline. At
    /// about a second for each page, the value of the image fits that deadline.
    max_reject_list_entries: 20_000, 1, 1 << 32;
    /// Entries in one `entries` call of a reject list. The value of the image
    /// is the page of rgb-lib. The page does not change what the enclave reads.
    reject_list_page_entries: 1_000, 1, 1 << 20;
    /// Size of one frame. The parent has its own limit too.
    max_message_bytes: MAX_MESSAGE_SIZE as u64, MIB, u32::MAX as u64;
    /// Protobuf field occurrences in one request.
    max_wire_elements: MAX_WIRE_ELEMENTS as u64, 1_024, 1 << 32;
    /// Size of one consignment.
    max_consignment_bytes: crate::config::DEFAULT_MAX_CONSIGNMENT_BYTES as u64, KIB, 1 << 32;
    /// Size of one PSBT or fascia.
    max_psbt_bytes: crate::config::MAX_PSBT_BYTES as u64, KIB, 1 << 32;
    /// Size of an unsigned gas transaction.
    max_gas_tx_bytes: 1024 * KIB, KIB, 1 << 32;
    /// RLP items of a gas transaction: every string and list, at any depth. A
    /// gas tx has 9 fields and a small or empty access list. Each decoded item
    /// takes 24 bytes, however short its encoding is. Without this limit, a
    /// 24 MiB request of one-byte empty lists decodes into more than 1 GiB.
    /// Calldata is one item at any length.
    max_rlp_items: 1024, 16, 1 << 20;
    /// Size of the calldata of a fundsOut.
    max_funds_out_call_data_bytes: 96 * KIB, KIB, 1 << 32;
    /// Headers in one `SubmitHeaders`.
    max_headers_per_submit: 10_000, 1, 1 << 32;
    /// Headers in one minute.
    max_headers_per_minute: 100_000, 1, 1 << 40;
    /// How long the mint signer refuses a second request for one deposit. A
    /// retry of the same request normally does not reach the enclave: the
    /// parent answers it from the reply it kept (parent `signed_responses`). It
    /// does when the parent has no copy of the reply (`docs/mint-flow.md` S7.6).
    /// The value of the image covers the retry backoff of the listener and the
    /// usual confirmation of the first transaction. A mint rebuilt for the same
    /// deposit has another txid, so M6 refuses it after this time too. The value
    /// must be above the request deadline, so an entry outlives its request.
    mint_replay_ttl_secs: 3_600, 120, 366 * 24 * 3_600;
    /// Deposits that the mint replay guard holds. When it is full, the guard
    /// removes the oldest entry and does not block signing. Only a real deposit
    /// adds an entry, so a high value does not let a request grow the guard.
    mint_replay_max_entries: 100_000, 1_024, 1 << 32;
    /// Inputs of a mint tx, before any fascia is decoded. This is looser than
    /// `MINT_INPUTS`, which the rules enforce exactly after the fascia.
    mint_max_inputs: 16, 1, 1 << 20;
    /// Outputs of a mint tx, before any fascia is decoded.
    mint_max_outputs: 16, 1, 1 << 20;
}

/// The heap of a consignment at the densest rate measured, in tenths of a byte
/// for each byte, with the margin of the test
/// (`validation::tests::the_densest_consignments_at_the_limit_fit_the_heap_each_worker_holds`).
/// A request sets this rate, so the general bound of a frame does not cover it.
const DENSE_CONSIGNMENT_RATE_TENTHS: u64 = 545;
/// The heap of a PSBT at the densest rate measured. A request sets this rate too.
const DENSE_PSBT_RATE: u64 = 103;
/// The heap of one entry of a reject list, from the read of the enclave to the
/// set that rgb-lib walks with in the validator child, with a margin on the
/// rate measured (`networks::rgb::validation::ipc::tests`). A request holds
/// this beside the rest. The read reserves the length that the RPC reports, so
/// only this limit stops a bad length.
pub(crate) const REJECT_LIST_ENTRY_BYTES: u64 = 220;

impl Limits {
    /// The values of the image: the constants, and the consignment limit that
    /// `MAX_CONSIGNMENT_BYTES` can lower.
    pub fn image(cfg: &BridgeConfig) -> Self {
        Self {
            max_consignment_bytes: cfg.max_consignment_bytes as u64,
            ..Self::DEFAULTS
        }
    }

    /// Refuses values outside their range, or that do not fit each other.
    pub fn check(&self) -> Result<(), String> {
        self.check_ranges()?;
        // The deadline stops the reads and writes of the request socket, but
        // not the network calls of the enclave, beside the EVM calls that
        // answer a validator child. So a longer network timeout lets one
        // stalled call hold a worker past the deadline, and the request loses
        // its reply. A longer idle timeout never applies.
        for (name, secs) in self.per_call_timeouts() {
            if secs > self.total_request_timeout_secs {
                return Err(format!(
                    "{name} is {secs}; it must be at most total_request_timeout_secs, {}",
                    self.total_request_timeout_secs
                ));
            }
        }
        // An entry must outlive the request that made it, or a concurrent
        // duplicate passes the guard.
        if self.mint_replay_ttl_secs <= self.total_request_timeout_secs {
            return Err(format!(
                "mint_replay_ttl_secs is {}; it must be above \
                 total_request_timeout_secs, {}",
                self.mint_replay_ttl_secs, self.total_request_timeout_secs
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
        let consignment =
            self.max_consignment_bytes.min(frame) * DENSE_CONSIGNMENT_RATE_TENTHS / 10;
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

    /// The time limits of one socket operation or one network call, with
    /// their names.
    fn per_call_timeouts(&self) -> [(&'static str, u64); 3] {
        [
            ("io_idle_timeout_secs", self.io_idle_timeout_secs),
            ("first_bytes_timeout_secs", self.first_bytes_timeout_secs),
            ("evm_rpc_timeout_secs", self.evm_rpc_timeout_secs),
        ]
    }

    fn elements_bytes(&self) -> u64 {
        self.max_wire_elements * crate::memory::WIRE_ELEMENT_BYTES as u64
    }

    /// The most heap one request can use under these values.
    pub fn request_bound_bytes(&self) -> u64 {
        crate::memory::REQUEST_MEMORY_FACTOR as u64 * self.max_message_bytes + self.elements_bytes()
    }

    /// The most RAM the scratch file of one request can take (`memory.rs`).
    /// A request holds one file at a time: the consignment of a burn, or one
    /// fascia of a mint or refill. So the larger limit sets the bound, and a
    /// frame cannot carry more than itself.
    pub fn scratch_file_bytes(&self) -> u64 {
        self.max_consignment_bytes
            .max(self.max_psbt_bytes)
            .min(self.max_message_bytes)
    }

    /// The socket deadline of one request.
    pub fn total_request_timeout(&self) -> Duration {
        Duration::from_secs(self.total_request_timeout_secs)
    }

    /// The longest time one socket read or write can block.
    pub fn io_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.io_idle_timeout_secs)
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

/// Makes `values` the values in force of this process, as they are: a
/// validator child takes the values the enclave holds in force. The enclave
/// judged them against its own configuration, so they are not checked again.
/// A zero keeps the image value.
pub fn adopt(values: &Limits) {
    store::update(|stored| *stored = *values);
}

#[cfg(test)]
mod tests;

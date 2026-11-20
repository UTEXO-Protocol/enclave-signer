//! The validator child: this binary started with [`CHILD_ARG`]. It validates
//! one consignment file and asks the enclave for every resolver answer.
//!
//! The child gets one socket as its fd 0 and no environment of the enclave.
//! It decodes no request: the enclave sends the path of the file it wrote, the
//! limits in force and the one safe height of the validation.

use std::cell::Cell;
use std::num::NonZeroU32;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use prost::bytes::Bytes;
use prost::Message;
use rgb_lib::ChainNet;

use super::bfa::{AnchorBinder, BoundAnchors, MintAnchor};
use super::ipc::{self, start, to_child, to_enclave};
use super::reject_list::{Decisions, ListAccess, RejectListContract, RejectListReader};
use super::types::ValidatedConsignment;
use super::validator::RgbValidator;
use super::witness::BuriedHeaders;
use crate::error::{EnclaveError, Result};
use crate::framing;
use crate::policy::BuildContext;

/// The one argument that starts this binary as a validator child.
pub const CHILD_ARG: &str = "--rgb-validator";

/// Set for a test binary that serves as a validator child.
#[cfg(any(test, debug_assertions))]
pub const TEST_ENTRY_ENV: &str = "UTEXO_RGB_VALIDATOR_TEST_ENTRY";

/// Names the fault a test child acts out instead of its job.
#[cfg(test)]
pub(super) const FAULT_ENV: &str = "UTEXO_RGB_VALIDATOR_FAULT";

/// The highest OOM score adjustment (`include/uapi/linux/oom.h`).
#[cfg(target_os = "linux")]
pub(super) const OOM_SCORE_ADJ_MAX: i32 = 1000;

/// Exit code of a child whose fd 0 is not a usable socket.
const EXIT_NO_CHANNEL: i32 = 2;
/// Exit code of a child that got no valid start frame.
const EXIT_NO_START: i32 = 3;

/// The error a resolver gets when the enclave refused its request. The
/// enclave keeps the real reason, so this text never reaches a reply.
const HELD_TEXT: &str = "the enclave refused this request";

/// Runs the one job of a validator child and returns its exit code.
pub fn serve() -> i32 {
    abort_on_panic();
    let confined = confine();
    let Ok(mut io) = channel() else {
        return EXIT_NO_CHANNEL;
    };
    crate::bootstrap::init_child_tracing();
    let _span = tracing::info_span!("rgb_validator", pid = std::process::id()).entered();
    let start = match framing::read_message::<ipc::ToChild>(&mut io) {
        Ok(ipc::ToChild {
            body: Some(to_child::Body::Start(start)),
        }) => start,
        Ok(_) => {
            tracing::error!("the first frame of the enclave is not a start frame");
            return EXIT_NO_START;
        }
        Err(e) => {
            tracing::error!("no start frame from the enclave: {e}");
            return EXIT_NO_START;
        }
    };
    let body = run_job(start, confined, &io);
    match framing::write_message(&mut io, &ipc::ToEnclave { body: Some(body) }) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("could not send the result to the enclave: {e}");
            EXIT_NO_CHANNEL
        }
    }
}

/// Serves as a validator child when this is a test binary started with
/// [`TEST_ENTRY_ENV`].
#[cfg(any(test, debug_assertions))]
pub fn run_if_test_child() -> Option<i32> {
    std::env::var_os(TEST_ENTRY_ENV).map(|_| serve())
}

/// The libtest name of the lib tests' child entry, without the crate name.
#[cfg(test)]
pub(super) fn lib_test_entry() -> &'static str {
    let full = concat!(module_path!(), "::tests::validator_child_entry");
    full.split_once("::").map_or(full, |(_, name)| name)
}

/// Ends the process with SIGABRT after the report of any panic, in every
/// build profile.
pub(super) fn abort_on_panic() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        std::process::abort();
    }));
}

/// Drops every inherited descriptor, puts the child first in line for the
/// OOM killer, turns core files off and sets the stack limit.
#[cfg(target_os = "linux")]
fn confine() -> std::result::Result<(), String> {
    use nix::libc::rlim_t;
    use nix::sys::resource::{getrlimit, setrlimit, Resource};

    close_inherited_fds().map_err(|e| format!("could not close inherited descriptors: {e}"))?;
    std::fs::write("/proc/self/oom_score_adj", OOM_SCORE_ADJ_MAX.to_string())
        .map_err(|e| format!("could not raise the OOM score: {e}"))?;
    match oom_score_adj() {
        Some(OOM_SCORE_ADJ_MAX) => {}
        other => return Err(format!("the OOM score adjustment reads {other:?}")),
    }
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| format!("could not turn core files off: {e}"))?;
    let (_, hard) = getrlimit(Resource::RLIMIT_STACK)
        .map_err(|e| format!("could not read the stack limit: {e}"))?;
    let stack = rlim_t::try_from(crate::memory::VALIDATOR_STACK_BYTES)
        .unwrap_or(rlim_t::MAX)
        .min(hard);
    setrlimit(Resource::RLIMIT_STACK, stack, stack)
        .map_err(|e| format!("could not set the stack limit: {e}"))
}

#[cfg(not(target_os = "linux"))]
fn confine() -> std::result::Result<(), String> {
    Err("no validator confinement on this OS".into())
}

/// A release child refuses a job it could not confine. A debug or test child
/// logs it and goes on.
fn confinement_outcome(
    confined: std::result::Result<(), String>,
    build: &BuildContext,
) -> std::result::Result<(), String> {
    let Err(e) = confined else {
        return Ok(());
    };
    if !build.debug_or_test {
        return Err(format!("the validator could not confine itself: {e}"));
    }
    if cfg!(target_os = "linux") {
        tracing::warn!("the validator could not confine itself: {e}; continuing in a debug build");
    } else {
        tracing::debug!("the validator could not confine itself: {e}; continuing in a debug build");
    }
    Ok(())
}

/// Closes each descriptor above 2. The listing's own descriptor is closed
/// before the loop, so its number gives `EBADF`.
#[cfg(target_os = "linux")]
fn close_inherited_fds() -> std::io::Result<()> {
    let fds: Vec<i32> = std::fs::read_dir("/proc/self/fd")?
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .filter(|fd| *fd > 2)
        .collect();
    for fd in fds {
        match nix::unistd::close(fd) {
            Ok(()) | Err(nix::errno::Errno::EBADF) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// The OOM score adjustment of this process.
#[cfg(target_os = "linux")]
fn oom_score_adj() -> Option<i32> {
    std::fs::read_to_string("/proc/self/oom_score_adj")
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(not(target_os = "linux"))]
fn oom_score_adj() -> Option<i32> {
    None
}

/// A `kB` field of `/proc/self/status`, such as `VmHWM`, in bytes.
#[cfg(target_os = "linux")]
fn status_bytes(field: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))?;
    let kib: u64 = value.trim().strip_suffix("kB")?.trim().parse().ok()?;
    kib.checked_mul(1024)
}

#[cfg(not(target_os = "linux"))]
fn status_bytes(_field: &str) -> Option<u64> {
    None
}

/// The child's end of its socket: fd 0.
fn channel() -> std::io::Result<UnixStream> {
    Ok(UnixStream::from(
        std::io::stdin().as_fd().try_clone_to_owned()?,
    ))
}

/// The last frame of the job that `start` names.
fn run_job(
    start: ipc::Start,
    confined: std::result::Result<(), String>,
    io: &UnixStream,
) -> to_enclave::Body {
    let job = match start.job {
        Some(start::Job::Probe(_)) => {
            // The enclave judges the report; this names the failed step.
            if let Err(e) = &confined {
                if cfg!(target_os = "linux") {
                    tracing::warn!("the validator could not confine itself: {e}");
                } else {
                    tracing::debug!("the validator could not confine itself: {e}");
                }
            }
            return to_enclave::Body::Ready(ready(confined.is_ok()));
        }
        Some(start::Job::Validate(job)) => job,
        None => {
            return refused(&EnclaveError::Internal(
                "the start frame names no job".into(),
            ))
        }
    };
    if let Err(e) = confinement_outcome(confined, &BuildContext::current()) {
        return refused(&EnclaveError::Internal(e));
    }
    let Some(limits) = start.limits else {
        return refused(&EnclaveError::Internal(
            "the start frame carries no limits".into(),
        ));
    };
    crate::limits::adopt(&(&limits).into());
    to_enclave::Body::Verdict(validate(job, io))
}

/// A verdict that refuses with `e`.
fn refused(e: &EnclaveError) -> to_enclave::Body {
    to_enclave::Body::Verdict(ipc::Verdict {
        outcome: Some(ipc::verdict::Outcome::Refused(ipc::refusal(e))),
        peak_rss_bytes: 0,
    })
}

/// Validates the file of `job`. A held refusal answers every refusal of the
/// enclave, so the enclave returns the error it kept.
fn validate(job: ipc::Validate, io: &UnixStream) -> ipc::Verdict {
    let link = ParentLink {
        io,
        refused: Cell::new(false),
    };
    let result = validate_with(&job, &link);
    let outcome = if link.refused.get() {
        ipc::held()
    } else {
        match result {
            Ok(validated) => ipc::verdict::Outcome::Validated(Box::new(ipc::validated(&validated))),
            Err(e) => ipc::verdict::Outcome::Refused(ipc::refusal(&e)),
        }
    };
    ipc::Verdict {
        outcome: Some(outcome),
        peak_rss_bytes: status_bytes("VmHWM").unwrap_or(0),
    }
}

/// Validates the file of `job` in this process, with each resolver answer
/// from the enclave.
fn validate_with(job: &ipc::Validate, link: &ParentLink<'_>) -> Result<ValidatedConsignment> {
    let chain_net: ChainNet = job
        .chain_net
        .parse()
        .map_err(|e| EnclaveError::Internal(format!("the enclave sent an unknown chain: {e}")))?;
    let headers = ParentChain {
        link,
        safe: NonZeroU32::new(job.safe_height),
    };
    let bind_asset = |contract_id: &str| link.bind_asset(contract_id);
    let bind = |anchors: &[MintAnchor]| link.bind(anchors);
    let read = |list: &RejectListContract| link.reject_list(list);
    let lists = ListAccess {
        bind_asset: &bind_asset,
        read: job
            .read_reject_list
            .then_some(&read as RejectListReader<'_>),
    };
    RgbValidator::for_chain_net(chain_net).validate_consignment_file(
        Path::new(&job.consignment_path),
        job.bind_anchors.then_some(&bind as AnchorBinder<'_>),
        &headers,
        &lists,
    )
}

/// How a probe child set itself up.
fn ready(confined: bool) -> ipc::Ready {
    ipc::Ready {
        confined,
        oom_score_adj: oom_score_adj().unwrap_or(0),
        vm_data_bytes: status_bytes("VmData").unwrap_or(0),
        vm_rss_bytes: status_bytes("VmRSS").unwrap_or(0),
    }
}

/// The enclave end of the socket. A resolver asks one question at a time, and
/// `&UnixStream` reads and writes, so it needs no lock.
struct ParentLink<'a> {
    io: &'a UnixStream,
    /// The enclave refused a request and keeps the reason.
    refused: Cell<bool>,
}

impl ParentLink<'_> {
    /// Sends `request` and reads its answer. After a refusal the child asks
    /// nothing more.
    fn ask(&self, request: to_enclave::Body) -> Result<to_child::Body> {
        if self.refused.get() {
            return Err(EnclaveError::Internal(HELD_TEXT.into()));
        }
        let mut io = self.io;
        framing::write_message(
            &mut io,
            &ipc::ToEnclave {
                body: Some(request),
            },
        )?;
        // The frame drops once decoded.
        let answer = {
            let cap = ipc::enclave_frame_bytes(&crate::limits::get());
            let frame = framing::read_frame_within(&mut io, cap)?;
            ipc::ToChild::decode(&frame[..])?
        };
        match answer.body {
            Some(to_child::Body::Refused(_)) => {
                self.refused.set(true);
                Err(EnclaveError::Internal(HELD_TEXT.into()))
            }
            Some(answer) => Ok(answer),
            None => Err(EnclaveError::Internal(
                "the enclave sent an empty answer".into(),
            )),
        }
    }

    fn bind_asset(&self, contract_id: &str) -> Result<()> {
        let request = to_enclave::Body::BindAsset(ipc::BindAsset {
            contract_id: Bytes::copy_from_slice(contract_id.as_bytes()),
        });
        match self.ask(request)? {
            to_child::Body::AssetBound(_) => Ok(()),
            other => Err(unexpected("an asset bind", &other)),
        }
    }

    fn bind(&self, anchors: &[MintAnchor]) -> Result<BoundAnchors> {
        let request = to_enclave::Body::Anchors(ipc::Anchors {
            records: ipc::pack_anchors(anchors).into(),
        });
        match self.ask(request)? {
            to_child::Body::Bound(bound) => Ok(BoundAnchors {
                evm_chain_id: bound.evm_chain_id,
                locks: ipc::unpack_locks(&bound.locks).map_err(EnclaveError::Internal)?,
            }),
            other => Err(unexpected("a lock bind", &other)),
        }
    }

    fn header(&self, height: u32) -> Result<bitcoin::block::Header> {
        match self.ask(to_enclave::Body::Header(height))? {
            to_child::Body::Header(bytes) => bitcoin::consensus::deserialize(&bytes).map_err(|e| {
                EnclaveError::Internal(format!(
                    "the enclave sent a header that does not decode: {e}"
                ))
            }),
            other => Err(unexpected("a header", &other)),
        }
    }

    fn reject_list(&self, list: &RejectListContract) -> Result<Decisions> {
        let request = to_enclave::Body::RejectList(ipc::ListAddress {
            chain_id: list.chain_id,
            address: Bytes::copy_from_slice(&list.address),
        });
        match self.ask(request)? {
            to_child::Body::Decisions(answer) => {
                ipc::unpack_decisions(answer).map_err(EnclaveError::Internal)
            }
            other => Err(unexpected("a reject list", &other)),
        }
    }
}

/// The error of an answer of another kind than the request asked for.
fn unexpected(asked: &str, answer: &to_child::Body) -> EnclaveError {
    let kind = match answer {
        to_child::Body::Start(_) => "a start frame",
        to_child::Body::AssetBound(_) => "an asset bind",
        to_child::Body::Bound(_) => "a lock bind",
        to_child::Body::Header(_) => "a header",
        to_child::Body::Decisions(_) => "a reject list",
        to_child::Body::Refused(_) => "a refusal",
    };
    EnclaveError::Internal(format!("the enclave answered {asked} with {kind}"))
}

/// The enclave chain as the child reads it: each header from the enclave, and
/// the one safe height the enclave read before the child started.
struct ParentChain<'a> {
    link: &'a ParentLink<'a>,
    safe: Option<NonZeroU32>,
}

impl BuriedHeaders for ParentChain<'_> {
    fn buried_header(&self, height: u32) -> Result<bitcoin::block::Header> {
        self.link.header(height)
    }

    fn safe_height(&self) -> Option<NonZeroU32> {
        self.safe
    }
}

#[cfg(test)]
mod tests;

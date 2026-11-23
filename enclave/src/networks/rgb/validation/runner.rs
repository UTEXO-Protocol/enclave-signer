//! Runs one burn validation in a validator child and answers its resolvers.
//! The enclave ends the child at its kill time, before the request deadline,
//! also while the worker answers one of its questions.
//!
//! The child is this binary started with `CHILD_ARG`, so exec gives it a new
//! address space. Of the enclave's environment it gets only `RUST_LOG`, and
//! one socket as its fd 0. The enclave keeps the scratch file, the one safe
//! height and every resolver answer, and it checks the verdict before it uses
//! it.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use prost::bytes::Bytes;
use prost::Message;
use rgb_lib::ChainNet;
use sha2::{Digest, Sha256};

use super::super::scratch::with_scratch_file;
use super::bfa::AnchorBinder;
use super::child::CHILD_ARG;
#[cfg(any(test, debug_assertions, not(feature = "vsock")))]
use super::child::TEST_ENTRY_ENV;
use super::ipc::{self, start, to_child, to_enclave, verdict};
use super::reject_list::{ListAccess, RejectListContract};
use super::types::{TransitionSummary, ValidatedConsignment};
use super::validator::RgbValidator;
use super::witness::BuriedHeaders;
use crate::conn::{DeadlineStream, RESPONSE_MARGIN};
use crate::error::{EnclaveError, Result};
use crate::framing;
use crate::limits::Limits;
use crate::memory::VALIDATOR_FRAME_FIXED_BYTES;
use crate::networks::evm::events::with_calls_ending_by;

/// The program of a validator child, its arguments and its environment beside
/// `RUST_LOG`.
#[derive(Debug, Clone)]
pub struct ChildProgram {
    program: PathBuf,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
}

impl ChildProgram {
    /// This binary with [`CHILD_ARG`]. On Linux the path names the running
    /// image, even after its file is replaced.
    pub fn this_binary() -> Result<Self> {
        #[cfg(target_os = "linux")]
        let program = PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let program = std::env::current_exe().map_err(|e| {
            EnclaveError::Internal(format!(
                "cannot find this binary for the RGB validator: {e}"
            ))
        })?;
        Ok(Self::child_of(program))
    }

    /// The binary at `path` with [`CHILD_ARG`]: an integration test runs the
    /// binary that cargo built. A release build with `vsock`, as each image
    /// is, runs only [`Self::this_binary`].
    #[cfg(any(test, debug_assertions, not(feature = "vsock")))]
    pub fn binary(path: impl Into<PathBuf>) -> Self {
        Self::child_of(path.into())
    }

    /// This test binary, running only its test `entry` as the child.
    #[cfg(any(test, debug_assertions, not(feature = "vsock")))]
    pub fn test_entry(entry: &str) -> Result<Self> {
        let program = std::env::current_exe()
            .map_err(|e| EnclaveError::Internal(format!("cannot find the test binary: {e}")))?;
        Ok(Self {
            program,
            args: ["--exact", entry, "--nocapture"].map(OsString::from).into(),
            env: vec![(TEST_ENTRY_ENV.into(), "1".into())],
        })
    }

    /// Adds `key=value` to the child's environment.
    #[cfg(test)]
    pub(crate) fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    fn child_of(program: PathBuf) -> Self {
        Self {
            program,
            args: vec![CHILD_ARG.into()],
            env: Vec::new(),
        }
    }

    /// Starts the child with one end of a new socket as its fd 0. Each read
    /// and write on the other end stops at `kill_at`.
    fn spawn(&self, kill_at: Instant) -> Result<Running> {
        let start_error = |e: io::Error| {
            let e = EnclaveError::Internal(format!(
                "cannot start the RGB validator {}: {e}",
                self.program.display()
            ));
            tracing::error!("{e}");
            e
        };
        let (ours, theirs) = UnixStream::pair().map_err(start_error)?;
        // The command holds a copy of the child's end until it drops here.
        // Then the enclave reads EOF when the child is gone.
        let child = {
            let mut command = Command::new(&self.program);
            command.args(&self.args).env_clear();
            if let Some(filter) = std::env::var_os("RUST_LOG") {
                command.env("RUST_LOG", filter);
            }
            command
                .envs(self.env.iter().map(|(key, value)| (key, value)))
                .stdin(Stdio::from(OwnedFd::from(theirs)))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(start_error)?
        };
        Ok(Running {
            child: Mutex::new(child),
            io: DeadlineStream::with_deadline(ours, kill_at, Duration::MAX),
            reaped: false,
        })
    }
}

/// How a probe child set itself up, and the time from its start to its report.
#[derive(Debug, Clone, Copy)]
pub struct ChildReport {
    /// Each confinement step passed.
    pub confined: bool,
    pub oom_score_adj: i32,
    pub vm_data_bytes: u64,
    pub vm_rss_bytes: u64,
    pub spawn_ms: u64,
}

/// Starts a child of `program` that only reports how it set itself up, and
/// ends it within `within`.
pub fn probe(program: &ChildProgram, within: Duration) -> Result<ChildReport> {
    let started = Instant::now();
    let mut running = program.spawn(started + within)?;
    let ready = ready_of(&mut running.io);
    let spawn_ms = millis(started.elapsed());
    let _ = running.finish();
    let ready = ready?;
    Ok(ChildReport {
        confined: ready.confined,
        oom_score_adj: ready.oom_score_adj,
        vm_data_bytes: ready.vm_data_bytes,
        vm_rss_bytes: ready.vm_rss_bytes,
        spawn_ms,
    })
}

/// Sends a probe job and reads the report of the child.
fn ready_of(io: &mut DeadlineStream<UnixStream>) -> Result<ipc::Ready> {
    let start = ipc::Start {
        limits: None,
        job: Some(start::Job::Probe(ipc::Empty {})),
    };
    send(io, to_child::Body::Start(start))?;
    let frame = framing::read_frame_within(io, VALIDATOR_FRAME_FIXED_BYTES as u64)?;
    match ipc::ToEnclave::decode(Bytes::from(frame))?.body {
        Some(to_enclave::Body::Ready(ready)) => Ok(ready),
        _ => Err(EnclaveError::Internal(
            "the RGB validator answered its probe with another frame".into(),
        )),
    }
}

impl RgbValidator {
    /// Validates `consignment` in a validator child, and answers the child's
    /// resolvers from `bind`, `headers` and `lists` in this process. The child
    /// takes `limits`, the values in force here, as they are. It ends at
    /// [`kill_time`], and each EVM RPC call of an answer ends then too, so the
    /// reply is still written before `deadline`.
    pub(super) fn validate_in_child(
        &self,
        consignment: &[u8],
        bind: Option<AnchorBinder<'_>>,
        headers: &dyn BuriedHeaders,
        lists: &ListAccess<'_>,
        limits: &Limits,
        deadline: Instant,
    ) -> Result<ValidatedConsignment> {
        let program = self.program.as_ref().ok_or_else(|| {
            EnclaveError::Internal("this RGB validator has no child program".into())
        })?;
        let kill_at = kill_time(deadline)?;
        let safe = headers.safe_height();
        let services = Services {
            headers,
            bind,
            lists,
            list_entries: limits.max_reject_list_entries,
        };
        with_scratch_file("consignment", consignment, |path| {
            let path = path.to_str().ok_or_else(|| {
                EnclaveError::Internal(format!("scratch path {} is not UTF-8", path.display()))
            })?;
            let job = ipc::Validate {
                consignment_path: path.into(),
                chain_net: self.chain_net.prefix().into(),
                safe_height: safe.map_or(0, NonZeroU32::get),
                bind_anchors: bind.is_some(),
                read_reject_list: lists.read.is_some(),
            };
            let start = ipc::Start {
                limits: Some(limits.into()),
                job: Some(start::Job::Validate(job)),
            };
            // The records of a verdict take fewer bytes than the file holds.
            let cap = consignment.len() as u64 + VALIDATOR_FRAME_FIXED_BYTES as u64;
            // The write of the file took time.
            kill_time(deadline)?;
            let started = Instant::now();
            let mut running = program.spawn(kill_at)?;
            let _span = tracing::info_span!("rgb_validator", pid = running.pid()).entered();
            let ex = running.until_killed(kill_at, |io| {
                with_calls_ending_by(kill_at, || exchange(io, start, cap, kill_at, &services))
            })?;
            let status = running.finish();
            tracing::info!(
                elapsed_ms = millis(started.elapsed()),
                requests = ex.requests,
                peak_rss_kib = ex.ended.peak_rss_bytes() / 1024,
                outcome = ex.ended.name(),
                "RGB validator ended"
            );
            outcome(ex, status, self.chain_net, safe)
        })
    }
}

/// When the enclave ends a validator child: [`RESPONSE_MARGIN`] before the
/// request deadline, so the reply can still be written. A time already past
/// refuses the validation before it starts.
pub(super) fn kill_time(deadline: Instant) -> Result<Instant> {
    deadline
        .checked_sub(RESPONSE_MARGIN)
        .filter(|at| *at > Instant::now())
        .ok_or_else(|| {
            EnclaveError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "request deadline passed before RGB validation",
            ))
        })
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// A started child. Dropping it ends and reaps the child, also on an early
/// return or an unwinding panic.
struct Running {
    /// A [`KillTimer`] kills the child through the lock; only `finish` reaps.
    child: Mutex<Child>,
    io: DeadlineStream<UnixStream>,
    reaped: bool,
}

impl Running {
    fn pid(&self) -> u32 {
        lock(&self.child).id()
    }

    /// Runs `work` on the socket, while a timer thread kills the child at
    /// `kill_at`: the worker may then be in an answer that does not watch the
    /// time. The timer stops before this returns.
    fn until_killed<T>(
        &mut self,
        kill_at: Instant,
        work: impl FnOnce(&mut DeadlineStream<UnixStream>) -> T,
    ) -> Result<T> {
        let timer = KillTimer::default();
        let Running { child, io, .. } = self;
        let child = &*child;
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("rgb-validator-timer".into())
                .spawn_scoped(scope, || timer.run(child, kill_at))
                .map_err(|e| {
                    EnclaveError::Internal(format!(
                        "cannot start the kill timer of the RGB validator: {e}"
                    ))
                })?;
            let _stop = StopTimer(&timer);
            Ok(work(io))
        })
    }

    /// Ends the child and reaps it. The kill does not change the status of a
    /// child that is already exiting.
    fn finish(&mut self) -> io::Result<ExitStatus> {
        let child = self.child.get_mut().unwrap_or_else(PoisonError::into_inner);
        let _ = child.kill();
        self.reaped = true;
        child.wait()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Kills a child at its kill time from a thread of its own.
#[derive(Default)]
struct KillTimer {
    stopped: Mutex<bool>,
    wake: Condvar,
}

impl KillTimer {
    /// Kills `child` at `kill_at`, unless the timer stops first. The kill
    /// holds the lock that a stop takes, and the worker stops the timer before
    /// it reaps, so the kill never reaches a reaped child.
    fn run(&self, child: &Mutex<Child>, kill_at: Instant) {
        let mut stopped = lock(&self.stopped);
        while !*stopped {
            let left = kill_at.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let _ = lock(child).kill();
                return;
            }
            stopped = self
                .wake
                .wait_timeout(stopped, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// Stops its timer when it drops: after the work, or on an unwinding panic.
struct StopTimer<'a>(&'a KillTimer);

impl Drop for StopTimer<'_> {
    fn drop(&mut self) {
        *lock(&self.0.stopped) = true;
        self.0.wake.notify_all();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.finish();
        }
    }
}

/// The resolver answers the enclave gives its child.
struct Services<'a> {
    headers: &'a dyn BuriedHeaders,
    bind: Option<AnchorBinder<'a>>,
    lists: &'a ListAccess<'a>,
    /// `max_reject_list_entries` of the start frame: the child reads no
    /// longer list, whatever the limits in force are now.
    list_entries: u64,
}

/// How an exchange with a child ended.
#[derive(Debug)]
enum Ended {
    /// The child sent its verdict.
    Verdict(ipc::Verdict),
    /// The kill time came first.
    Deadline,
    /// The child closed its end: an EOF, or a write that failed.
    Closed,
    /// The child broke the protocol, as the text says.
    Protocol(String),
}

impl Ended {
    /// A name for the log line.
    fn name(&self) -> &'static str {
        match self {
            _ if self.is_held() => "held",
            Ended::Verdict(verdict) => match &verdict.outcome {
                Some(verdict::Outcome::Validated(_)) => "validated",
                Some(verdict::Outcome::Refused(_)) => "refused",
                None => "empty verdict",
            },
            Ended::Deadline => "deadline",
            Ended::Closed => "closed",
            Ended::Protocol(_) => "protocol error",
        }
    }

    /// The child answered a refusal of the enclave with a held refusal.
    fn is_held(&self) -> bool {
        matches!(
            self,
            Ended::Verdict(ipc::Verdict {
                outcome: Some(verdict::Outcome::Refused(refusal)),
                ..
            }) if refusal.kind == ipc::REFUSAL_HELD
        )
    }

    /// The peak resident size the child reported, or 0.
    fn peak_rss_bytes(&self) -> u64 {
        match self {
            Ended::Verdict(verdict) => verdict.peak_rss_bytes,
            _ => 0,
        }
    }
}

/// The end of an exchange and what the enclave kept from it.
struct Exchange {
    ended: Ended,
    /// The enclave's own error of the request it refused.
    kept: Option<EnclaveError>,
    /// The contract id the asset bind passed.
    bound: Option<String>,
    /// Digest of the lock records the enclave bound, in the order it sent them.
    locks: Sha256,
    /// Requests answered, for the log.
    requests: u64,
}

/// Starts the child's job and answers its requests until its verdict, the
/// kill time, its end or a protocol error. A request after a refusal breaks
/// the protocol. No state grows with the number of requests.
fn exchange<S: Read + Write>(
    io: &mut S,
    start: ipc::Start,
    cap: u64,
    kill_at: Instant,
    services: &Services<'_>,
) -> Exchange {
    let mut ex = Exchange {
        ended: Ended::Closed,
        kept: None,
        bound: None,
        locks: Sha256::new(),
        requests: 0,
    };
    let mut list_read = false;
    if let Err(e) = send(io, to_child::Body::Start(start)) {
        ex.ended = io_end(&e, kill_at);
        return ex;
    }
    ex.ended = loop {
        let frame = match framing::read_frame_within(io, cap) {
            Ok(frame) => frame,
            Err(EnclaveError::Io(e)) => break io_end(&e, kill_at),
            Err(e) => break Ended::Protocol(e.to_string()),
        };
        // The fields of the message share the bytes of the frame.
        let request = match ipc::ToEnclave::decode(Bytes::from(frame)) {
            Ok(ipc::ToEnclave {
                body: Some(to_enclave::Body::Verdict(verdict)),
            }) => break Ended::Verdict(verdict),
            Ok(ipc::ToEnclave {
                body: Some(request),
            }) => request,
            Ok(ipc::ToEnclave { body: None }) => {
                break Ended::Protocol("a frame with no message".into())
            }
            Err(e) => break Ended::Protocol(format!("a frame that does not decode: {e}")),
        };
        if ex.kept.is_some() {
            break Ended::Protocol("a request after the enclave refused one".into());
        }
        let answer = match answer(request, &mut ex, &mut list_read, services) {
            Ok(answer) => answer,
            Err(what) => break Ended::Protocol(what),
        };
        ex.requests += 1;
        if let Err(e) = send(io, answer) {
            break io_end(&e, kill_at);
        }
    };
    ex
}

/// The answer to one request, or why the request breaks the protocol. The
/// list is read only after the asset bind passed, as in the enclave. A
/// refused request keeps the enclave's error, and the child gets `Refused`.
fn answer(
    request: to_enclave::Body,
    ex: &mut Exchange,
    list_read: &mut bool,
    services: &Services<'_>,
) -> std::result::Result<to_child::Body, String> {
    if ex.bound.is_none() && !matches!(request, to_enclave::Body::BindAsset(_)) {
        return Err("a request before the asset bind".into());
    }
    let served = match request {
        to_enclave::Body::BindAsset(ask) => {
            if ex.bound.is_some() {
                return Err("a second asset bind".into());
            }
            let id = contract_id(&ask.contract_id)?;
            (services.lists.bind_asset)(&id).map(|()| {
                ex.bound = Some(id);
                to_child::Body::AssetBound(ipc::Empty {})
            })
        }
        to_enclave::Body::Anchors(ask) => {
            let bind = services
                .bind
                .ok_or("mint anchors, but the enclave binds no anchor")?;
            // At most one record, checked before the records are read.
            if ask.records.len() > ipc::ANCHOR_RECORD_BYTES {
                return Err(format!(
                    "{} bytes of mint anchors in one request, over one record",
                    ask.records.len()
                ));
            }
            let anchors = ipc::unpack_anchors(&ask.records)?;
            bind(&anchors).map(|bound| {
                let locks = ipc::pack_locks(&bound.locks);
                ex.locks.update(&locks);
                to_child::Body::Bound(ipc::Bound {
                    evm_chain_id: bound.evm_chain_id,
                    locks,
                })
            })
        }
        to_enclave::Body::Header(height) => {
            if height == 0 {
                return Err("a header at height 0".into());
            }
            services
                .headers
                .buried_header(height)
                .map(|header| to_child::Body::Header(bitcoin::consensus::serialize(&header)))
        }
        to_enclave::Body::RejectList(ask) => {
            let read = services
                .lists
                .read
                .ok_or("a reject list, but the enclave reads no list")?;
            if std::mem::replace(list_read, true) {
                return Err("a second reject-list read".into());
            }
            let address = <[u8; 20]>::try_from(ask.address.as_ref())
                .map_err(|_| format!("a list address of {} bytes", ask.address.len()))?;
            let list = RejectListContract {
                chain_id: ask.chain_id,
                address,
            };
            read(&list).and_then(|decisions| {
                // The reader caps the list under the limits in force now.
                let entries = decisions.reject.len() + decisions.allow.len();
                if entries as u64 > services.list_entries {
                    return Err(EnclaveError::CrossCheck(format!(
                        "reject list 0x{} holds at least {entries} entries, over the {} in force \
                         when this validation started - refusing to sign",
                        hex::encode(address),
                        services.list_entries
                    )));
                }
                Ok(to_child::Body::Decisions(ipc::pack_decisions(decisions)))
            })
        }
        to_enclave::Body::Verdict(_) | to_enclave::Body::Ready(_) => {
            return Err("a frame that is not a request".into())
        }
    };
    Ok(served.unwrap_or_else(|e| {
        ex.kept = Some(e);
        to_child::Body::Refused(ipc::Empty {})
    }))
}

/// The contract id of an asset bind: UTF-8, at most
/// [`ipc::MAX_CONTRACT_ID_BYTES`].
fn contract_id(bytes: &[u8]) -> std::result::Result<String, String> {
    if bytes.len() > ipc::MAX_CONTRACT_ID_BYTES {
        return Err(format!("a contract id of {} bytes", bytes.len()));
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| format!("a contract id that is not UTF-8: {e}"))
}

/// A read or write that failed ends the exchange at the kill time, or because
/// the child closed its end.
fn io_end(e: &io::Error, kill_at: Instant) -> Ended {
    let timed_out = matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    );
    if timed_out || Instant::now() >= kill_at {
        Ended::Deadline
    } else {
        Ended::Closed
    }
}

/// Writes one frame to the child. The message drops once it is encoded.
fn send<S: Write>(io: &mut S, body: to_child::Body) -> io::Result<()> {
    let frame = ipc::ToChild { body: Some(body) }.encode_to_vec();
    let len = u32::try_from(frame.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a frame over 4 GiB"))?;
    io.write_all(&len.to_le_bytes())?;
    io.write_all(&frame)?;
    io.flush()
}

/// The result of a validation, from the end of its exchange and the status
/// of its child. The enclave's own error of a refused request comes first.
fn outcome(
    ex: Exchange,
    status: io::Result<ExitStatus>,
    chain_net: ChainNet,
    safe: Option<NonZeroU32>,
) -> Result<ValidatedConsignment> {
    let Exchange {
        ended,
        kept,
        bound,
        locks,
        ..
    } = ex;
    if let Some(kept) = kept {
        if !ended.is_held() {
            tracing::warn!(
                ended = ended.name(),
                "the RGB validator did not end with a held refusal after the enclave refused its \
                 request"
            );
        }
        return Err(kept);
    }
    let what = match ended {
        Ended::Verdict(ipc::Verdict {
            outcome: Some(verdict::Outcome::Validated(validated)),
            ..
        }) => match bound {
            Some(bound) => {
                match into_validated(*validated, &bound, &locks.finalize(), chain_net, safe) {
                    Ok(validated) => return Ok(validated),
                    Err(what) => what,
                }
            }
            None => "a validated consignment without an asset bind".into(),
        },
        Ended::Verdict(ipc::Verdict {
            outcome: Some(verdict::Outcome::Refused(refusal)),
            ..
        }) => match ipc::refusal_error(&refusal) {
            Ok(e) => return Err(e),
            Err(what) => what,
        },
        Ended::Verdict(ipc::Verdict { outcome: None, .. }) => "a verdict with no outcome".into(),
        Ended::Deadline => {
            tracing::warn!("the enclave ended its RGB validator at the kill time");
            return Err(EnclaveError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "RGB validation did not end before the request deadline: the enclave ended its \
                 validator",
            )));
        }
        Ended::Closed => {
            let e = ended_without_verdict(status);
            tracing::error!("{e}");
            return Err(e);
        }
        Ended::Protocol(what) => what,
    };
    let e = EnclaveError::Internal(format!("the RGB validator broke its protocol: {what}"));
    tracing::error!("{e}");
    Err(e)
}

/// The consignment of a verdict, after the checks that tie it to this
/// validation, or what broke the protocol. The witness txids are the ones of
/// the bundles, so the enclave's own B3.2 check compares them with the witness
/// blocks. Its mint locks must be the ones the enclave bound, whose digest is
/// `answered_locks`. The transitions by witness and the outputs of the
/// settling transition stay empty.
fn into_validated(
    v: ipc::Validated,
    bound: &str,
    answered_locks: &[u8],
    chain_net: ChainNet,
    safe: Option<NonZeroU32>,
) -> std::result::Result<ValidatedConsignment, String> {
    if v.contract_id.as_ref() != bound.as_bytes() {
        return Err("a verdict on another contract than the bound one".into());
    }
    if v.chain_net.as_ref() != chain_net.prefix().as_bytes() {
        return Err(format!(
            "a verdict on another chain than {}",
            chain_net.prefix()
        ));
    }
    let witness_blocks = ipc::unpack_witness_blocks(&v.witness_blocks)?;
    if !witness_blocks.is_sorted_by(|a, b| a.txid < b.txid) {
        return Err("witness blocks out of txid order".into());
    }
    // The one view of the chain: no witness above the safe height of the start.
    let safe = safe.map_or(0, NonZeroU32::get);
    if let Some(block) = witness_blocks
        .iter()
        .find(|block| !(1..=safe).contains(&block.height))
    {
        return Err(format!(
            "a witness block at height {}, not from 1 to {safe}",
            block.height
        ));
    }
    let witness_txids = ipc::unpack_witness_txids(&v.witness_txids)?;
    if !witness_txids.is_sorted_by(|a, b| a < b) {
        return Err("witness txids out of order".into());
    }
    let (settling_witness_txid, settling_op_id, settling_transition) = match v.settling {
        Some(settling) => {
            let (txid, op_id, transition) = settling_of(settling, &witness_txids)?;
            (Some(txid), Some(op_id), Some(transition))
        }
        None => (None, None, None),
    };
    if Sha256::digest(&v.mint_locks).as_slice() != answered_locks {
        return Err("mint locks other than the ones the enclave bound".into());
    }
    let mint_locks = ipc::unpack_locks(&v.mint_locks)?;
    Ok(ValidatedConsignment {
        contract_id: bound.to_owned(),
        chain_net: chain_net.prefix().to_owned(),
        witness_txids,
        settling_witness_txid,
        settling_transition,
        settling_op_id,
        witness_blocks,
        transitions_by_witness: Vec::new(),
        mint_locks,
    })
}

/// The settling transition of a verdict, with its witness txid and OpId. The
/// witness must be one of `witness_txids`, in display order.
fn settling_of(
    settling: ipc::Settling,
    witness_txids: &[[u8; 32]],
) -> std::result::Result<(bitcoin::Txid, [u8; 32], TransitionSummary), String> {
    let txid = <[u8; 32]>::try_from(settling.witness_txid.as_ref())
        .map_err(|_| format!("a settling txid of {} bytes", settling.witness_txid.len()))?;
    let mut display = txid;
    display.reverse();
    if witness_txids.binary_search(&display).is_err() {
        return Err("a settling witness that is not a witness of the consignment".into());
    }
    let op_id = <[u8; 32]>::try_from(settling.op_id.as_ref())
        .map_err(|_| format!("a settling OpId of {} bytes", settling.op_id.len()))?;
    let transition_type = ipc::transition_type(settling.transition_type)
        .ok_or_else(|| format!("the unknown transition type {}", settling.transition_type))?;
    let burn_reason = match settling.burn_reason.len() {
        0 => None,
        len => Some(
            <[u8; 32]>::try_from(settling.burn_reason.as_ref())
                .map_err(|_| format!("a burn reason of {len} bytes"))?,
        ),
    };
    let transition = TransitionSummary {
        op_id: hex::encode(op_id),
        transition_type,
        asset_output_amount: settling.asset_output_amount,
        outputs: Vec::new(),
        burned_asset_amount: settling.burned_asset_amount,
        burn_reason,
    };
    Ok((bitcoin::Txid::from_byte_array(txid), op_id, transition))
}

/// The error of a child that closed its end before its verdict. A crash
/// refuses the consignment that caused it. Any other end is a fault of the
/// enclave, as a retry may pass.
fn ended_without_verdict(status: io::Result<ExitStatus>) -> EnclaveError {
    let status = match status {
        Ok(status) => status,
        Err(e) => return EnclaveError::Internal(format!("could not reap the RGB validator: {e}")),
    };
    #[cfg(target_os = "linux")]
    if let Some(signal) = status.signal() {
        if let Some((_, name)) = CRASH_SIGNALS.iter().find(|(crash, _)| *crash == signal) {
            return EnclaveError::CrossCheck(format!(
                "RGB consignment validation failed: the validator stopped on signal {signal} \
                 ({name}): a panic, a failed allocation or a stack overflow on this consignment - \
                 refusing to sign"
            ));
        }
        // The enclave sends its kill only after the child closed its end.
        if signal == nix::libc::SIGKILL {
            return EnclaveError::Internal(format!(
                "the RGB validator was ended by signal {signal}: the kernel ends a process this \
                 way when the enclave runs out of memory"
            ));
        }
    }
    EnclaveError::Internal(format!(
        "the RGB validator ended with {status} before its verdict"
    ))
}

/// The signals that end a child on a crash: an abort after a panic or a
/// failed allocation, or a fault.
#[cfg(target_os = "linux")]
const CRASH_SIGNALS: [(i32, &str); 5] = [
    (nix::libc::SIGABRT, "SIGABRT"),
    (nix::libc::SIGSEGV, "SIGSEGV"),
    (nix::libc::SIGBUS, "SIGBUS"),
    (nix::libc::SIGILL, "SIGILL"),
    (nix::libc::SIGFPE, "SIGFPE"),
];

#[cfg(test)]
mod tests;

//! Keeps the enclave's header chain at the tip of one Electrum server.
//!
//! The parent holds no chain and no cursor. Each step reads the enclave tip,
//! checks it against the source on one connection and sends the missing
//! headers.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, ensure, Context};
use bitcoin::block::Header;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::AbortHandle;

use crate::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, GetLastSavedBlockRequest, Limits,
    SubmitHeadersRequest, SubmitHeadersResponse,
};
use crate::grpc_server::ParentAdapterService;
use crate::header_source::{ElectrumSource, CALL_TIMEOUT, MAX_HEADERS};

/// Headers above a fork point that a fork repair resends: one less than the
/// enclave's `MAX_REORG_DEPTH`, so a repair replaces the deepest fork that the
/// enclave accepts. A low batch limit lowers it (`repair_depth`).
const REWIND: u32 = 99;
/// Headers in each `RATE_WINDOW` until the parent has read the limits in force:
/// half the image value of the enclave's `max_headers_per_minute`. Then the
/// sync sends half the value in force.
const RATE_LIMIT: u32 = 50_000;
const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Failed steps in a row that make the state `stalled`.
const STALL_AFTER: u32 = 3;
/// The enclave names its checkpoint in this refusal (`SpvError::BelowCheckpoint`).
const BELOW_CHECKPOINT: &str = "below checkpoint ";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncState {
    Off,
    Unconfigured,
    #[default]
    Syncing,
    Synced,
    Stalled,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SyncStatus {
    pub state: SyncState,
    pub source_tip: Option<u32>,
    pub enclave_tip: Option<u32>,
    pub lag_blocks: Option<u32>,
    pub tip_age_secs: Option<u32>,
    pub last_ok_unix: Option<u64>,
    pub last_error: Option<String>,
}

pub struct HeaderSync {
    service: ParentAdapterService,
    source: Option<Arc<ElectrumSource>>,
    /// Why there is no source, when `HEADER_ELECTRUM_URL` was set but bad.
    source_error: Option<String>,
    interval: Duration,
    status: watch::Sender<SyncStatus>,
    /// A source call that timed out and may still run on a blocking thread.
    pending: Option<AbortHandle>,
    failures: u32,
    sent: VecDeque<(Instant, u32)>,
    age_level: u8,
    /// The enclave's checkpoint height, once a refusal has named it. A fork
    /// repair never starts at or below it.
    floor: Option<u32>,
}

impl HeaderSync {
    /// `source` is `Err` when `HEADER_ELECTRUM_URL` was set but does not
    /// parse: the sync reports `unconfigured` with that error and the parent
    /// keeps serving.
    pub fn new(
        service: ParentAdapterService,
        source: Result<Option<ElectrumSource>, String>,
        interval: Duration,
    ) -> (Self, watch::Receiver<SyncStatus>) {
        let (status, rx) = watch::channel(SyncStatus::default());
        let (source, source_error) = match source {
            Ok(source) => (source.map(Arc::new), None),
            Err(e) => (None, Some(e)),
        };
        let sync = Self {
            service,
            source,
            source_error,
            interval,
            status,
            pending: None,
            failures: 0,
            sent: VecDeque::new(),
            age_level: 0,
            floor: None,
        };
        (sync, rx)
    }

    pub async fn run(mut self) {
        loop {
            let result = self.step().await;
            let behind = matches!(result, Ok(SyncState::Syncing));
            self.record(result);
            if !behind {
                tokio::time::sleep(self.interval).await;
            }
        }
    }

    fn record(&mut self, result: anyhow::Result<SyncState>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let previous = self.status.borrow().state;
        let failures = &mut self.failures;
        let source_error = &self.source_error;
        self.status.send_modify(|s| match result {
            Ok(state) => {
                *failures = 0;
                s.last_error = match state {
                    SyncState::Unconfigured => source_error.clone(),
                    _ => None,
                };
                s.state = state;
                if matches!(s.state, SyncState::Synced | SyncState::Syncing) {
                    s.last_ok_unix = Some(now);
                }
            }
            Err(e) => {
                *failures += 1;
                tracing::warn!(error = format!("{e:#}"), "header sync step failed");
                s.last_error = Some(format!("{e:#}"));
                if *failures >= STALL_AFTER {
                    s.state = SyncState::Stalled;
                }
            }
        });
        let state = self.status.borrow().state;
        if state != previous {
            match state {
                SyncState::Unconfigured => match &self.source_error {
                    Some(e) => {
                        tracing::error!(error = %e, "HEADER_ELECTRUM_URL is bad; the parent syncs no headers")
                    }
                    None => tracing::error!(
                        "HEADER_ELECTRUM_URL is not set; the parent syncs no headers"
                    ),
                },
                SyncState::Stalled => tracing::error!("header sync stalled"),
                _ => tracing::info!(?state, "header sync state"),
            }
        }
    }

    async fn step(&mut self) -> anyhow::Result<SyncState> {
        let health = crate::health::probe(&self.service)
            .await
            .map_err(|e| anyhow!(e))?;
        self.status
            .send_modify(|s| s.tip_age_secs = Some(health.spv_tip_age_secs));
        if health.spv_max_tip_age_secs == 0 {
            return Ok(SyncState::Off);
        }
        let Some(source) = self.source.clone() else {
            return Ok(SyncState::Unconfigured);
        };
        self.log_tip_age(health.spv_tip_age_secs, health.spv_max_tip_age_secs);

        let (h, hash) = self.enclave_tip().await?;
        self.status.send_modify(|s| s.enclave_tip = Some(h));
        let (max_batch, rate) = header_limits(self.service.limits_in_force().as_ref());
        // A fork repair starts `repair_depth` below the tip, but never at or
        // below the checkpoint: the enclave refuses to rewrite history there.
        let rewind_to = h
            .saturating_sub(repair_depth(max_batch))
            .max(self.floor.map_or(1, |f| f + 1));
        let (s, batch) = self
            .source_call(&source, move |src| {
                fetch(src, h, hash, rewind_to, max_batch)
            })
            .await?;
        self.status.send_modify(|st| {
            st.source_tip = Some(s);
            st.lag_blocks = Some(s.saturating_sub(h));
        });
        let Some((start, headers)) = batch else {
            return Ok(SyncState::Synced);
        };

        let len = headers.len() as u32;
        let last_height = start + len - 1;
        let last_hash = headers
            .last()
            .context("source sent no headers")?
            .block_hash();
        self.wait_for_rate(len, rate).await;
        let reply = self.submit(start, &headers).await?;
        ensure!(
            reply.headers_accepted == len
                && reply.last_block_height == last_height
                && reply.last_block_hash == last_hash.as_byte_array(),
            "enclave reply does not match the batch {start}..={last_height}: accepted {}, tip {}",
            reply.headers_accepted,
            reply.last_block_height
        );
        self.status.send_modify(|st| {
            st.enclave_tip = Some(last_height);
            st.lag_blocks = Some(s.saturating_sub(last_height));
        });
        Ok(if last_height >= s {
            SyncState::Synced
        } else {
            SyncState::Syncing
        })
    }

    /// Logs an old header tip of the enclave: a warning at half the enclave's
    /// `spv_max_tip_age_secs`, and an error at that age, where signing stops.
    fn log_tip_age(&mut self, age: u32, max_age: u32) {
        let level = match age {
            a if a >= max_age => 2,
            a if a >= max_age / 2 => 1,
            _ => 0,
        };
        if level > self.age_level {
            if level == 2 {
                tracing::error!(
                    age,
                    max_age,
                    "enclave header tip is at the enclave's maximum tip age; signing stops"
                );
            } else {
                tracing::warn!(
                    age,
                    max_age,
                    "enclave header tip is at half the enclave's maximum tip age"
                );
            }
        }
        self.age_level = level;
    }

    /// Run one source call on a blocking thread. Never starts a second call
    /// while an earlier one still runs.
    async fn source_call<T: Send + 'static>(
        &mut self,
        source: &Arc<ElectrumSource>,
        f: impl FnOnce(&ElectrumSource) -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        if self.pending.as_ref().is_some_and(|p| !p.is_finished()) {
            bail!("source call still running");
        }
        self.pending = None;
        let source = source.clone();
        let mut call = tokio::task::spawn_blocking(move || f(&source));
        match tokio::time::timeout(CALL_TIMEOUT + Duration::from_secs(1), &mut call).await {
            Ok(joined) => joined.context("source call failed")?,
            Err(_) => {
                self.pending = Some(call.abort_handle());
                bail!("source call timed out")
            }
        }
    }

    async fn wait_for_rate(&mut self, n: u32, limit: u32) {
        loop {
            let now = Instant::now();
            while self
                .sent
                .front()
                .is_some_and(|(t, _)| now.duration_since(*t) >= RATE_WINDOW)
            {
                self.sent.pop_front();
            }
            let used: u32 = self.sent.iter().map(|(_, n)| n).sum();
            match self.sent.front() {
                Some((oldest, _)) if used + n > limit => {
                    tokio::time::sleep(RATE_WINDOW - now.duration_since(*oldest)).await;
                }
                _ => break,
            }
        }
        self.sent.push_back((Instant::now(), n));
    }

    async fn enclave_tip(&self) -> anyhow::Result<(u32, BlockHash)> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::GetLastSavedBlock(
                GetLastSavedBlockRequest {},
            )),
        };
        let resp = self
            .service
            .send_to_enclave(req)
            .await
            .map_err(|s| anyhow!("enclave: {}", s.message()))?;
        match resp.response {
            Some(enclave_response::Response::GetLastSavedBlock(r)) => {
                let hash = BlockHash::from_slice(&r.block_hash)
                    .map_err(|_| anyhow!("enclave tip hash is not 32 bytes"))?;
                Ok((r.block_height, hash))
            }
            Some(enclave_response::Response::Error(e)) => {
                bail!("enclave error (code {}): {}", e.code, e.message)
            }
            other => bail!("unexpected enclave response: {other:?}"),
        }
    }

    async fn submit(
        &mut self,
        start_height: u32,
        headers: &[Header],
    ) -> anyhow::Result<SubmitHeadersResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SubmitHeaders(
                SubmitHeadersRequest {
                    headers: headers.iter().map(serialize).collect(),
                    start_height,
                },
            )),
        };
        let resp = self
            .service
            .send_to_enclave(req)
            .await
            .map_err(|s| anyhow!("enclave: {}", s.message()))?;
        match resp.response {
            Some(enclave_response::Response::SubmitHeaders(r)) => Ok(r),
            Some(enclave_response::Response::Error(e)) => {
                if let Some(checkpoint) = checkpoint_in(&e.message) {
                    tracing::info!(
                        checkpoint,
                        "enclave checkpoint learned; fork repairs stay above it"
                    );
                    self.floor = Some(checkpoint);
                }
                bail!("enclave refused headers (code {}): {}", e.code, e.message)
            }
            other => bail!("unexpected enclave response: {other:?}"),
        }
    }
}

/// The headers the enclave is missing, from this start height.
type Batch = (u32, Vec<Header>);

/// The most headers in one batch, and in one `RATE_WINDOW`. The enclave refuses
/// more than `max_headers_per_submit` in one `SubmitHeaders`, and more than
/// `max_headers_per_minute` in a minute. So the batch is the source's
/// `MAX_HEADERS` or the enclave's limit in force, if lower, and the rate is half
/// the enclave's limit in force. Before the first read of the limits, the sync
/// uses `MAX_HEADERS` and `RATE_LIMIT`. A batch is never above the rate.
/// How far below the enclave tip a fork repair starts: `REWIND`, or less when
/// `max_batch` is low. A repair batch must reach at least one header past the
/// old tip, because the enclave keeps its own chain when the work is equal. So
/// the repair starts at most `max_batch - 2` below the tip. A batch limit below
/// two headers repairs no fork.
fn repair_depth(max_batch: u32) -> u32 {
    REWIND.min(max_batch.saturating_sub(2))
}

fn header_limits(limits: Option<&Limits>) -> (u32, u32) {
    let to_u32 = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
    let per_submit = limits.map(|l| l.max_headers_per_submit).filter(|&n| n != 0);
    let per_minute = limits.map(|l| l.max_headers_per_minute).filter(|&n| n != 0);
    let rate = per_minute.map_or(RATE_LIMIT, |n| to_u32(n / 2).max(1));
    let batch = per_submit.map_or(MAX_HEADERS, |n| to_u32(n).min(MAX_HEADERS));
    (batch.min(rate), rate)
}

/// On one connection: the source tip, and the batch the enclave is missing
/// above its tip `h` (`None` when it has them all). A fork is repaired from
/// `rewind_to`. Every header is checked to link to the one before.
fn fetch(
    src: &ElectrumSource,
    h: u32,
    hash: BlockHash,
    rewind_to: u32,
    max_count: u32,
) -> anyhow::Result<(u32, Option<Batch>)> {
    let session = src.connect()?;
    let (s, tip_header) = session.tip()?;
    ensure!(s >= h, "source tip {s} is below the enclave tip {h}");
    let at_h = if s == h {
        tip_header
    } else {
        *session
            .headers(h, 1)?
            .first()
            .context("source has no header at the enclave tip")?
    };
    let (start, prev) = if at_h.block_hash() == hash {
        if s == h {
            return Ok((s, None));
        }
        (h + 1, Some(hash))
    } else {
        ensure!(
            s > h,
            "source header at {h} differs from the enclave; waiting for the source to get ahead"
        );
        ensure!(
            rewind_to <= h,
            "source header at {h} differs from the enclave at its checkpoint; the chains do not meet"
        );
        (rewind_to, None)
    };
    let count = (s - start + 1).min(max_count);
    let headers = session.headers(start, count)?;
    ensure!(!headers.is_empty(), "source sent no headers");
    if let Some(prev) = prev {
        ensure!(
            headers[0].prev_blockhash == prev,
            "source header {start} does not link to the enclave tip"
        );
    }
    for (i, pair) in headers.windows(2).enumerate() {
        ensure!(
            pair[1].prev_blockhash == pair[0].block_hash(),
            "source header {} does not link to the one before",
            start as usize + i + 1
        );
    }
    Ok((s, Some((start, headers))))
}

/// The checkpoint height an enclave `BelowCheckpoint` refusal names.
fn checkpoint_in(message: &str) -> Option<u32> {
    let rest = &message[message.find(BELOW_CHECKPOINT)? + BELOW_CHECKPOINT.len()..];
    let digits = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sync's own values follow the enclave image.
    #[test]
    fn the_sync_constants_match_the_enclave() {
        use utexo_bridge_enclave::limits::Limits as EnclaveLimits;
        use utexo_bridge_enclave::networks::rgb::spv::chain::MAX_REORG_DEPTH;
        assert_eq!(REWIND + 1, MAX_REORG_DEPTH);
        let image = EnclaveLimits::DEFAULTS;
        assert_eq!(u64::from(RATE_LIMIT) * 2, image.max_headers_per_minute);
        assert!(u64::from(MAX_HEADERS) <= image.max_headers_per_submit);
    }

    /// The batch and the rate stay within the header limits in force.
    #[test]
    fn the_sync_follows_the_header_limits_in_force() {
        let limits = |per_submit, per_minute| Limits {
            max_headers_per_submit: per_submit,
            max_headers_per_minute: per_minute,
            ..Default::default()
        };
        assert_eq!(header_limits(None), (MAX_HEADERS, RATE_LIMIT));
        // The image values.
        assert_eq!(
            header_limits(Some(&limits(10_000, 100_000))),
            (MAX_HEADERS, 50_000)
        );
        // A lower limit of one submit gives a smaller batch.
        assert_eq!(header_limits(Some(&limits(500, 100_000))), (500, 50_000));
        // A lower limit of one minute lowers the rate, and the batch with it.
        assert_eq!(header_limits(Some(&limits(10_000, 1_000))), (500, 500));
        // A higher limit raises only the rate.
        assert_eq!(
            header_limits(Some(&limits(1 << 32, 400_000))),
            (MAX_HEADERS, 200_000)
        );
        // The smallest limits still send one header.
        assert_eq!(header_limits(Some(&limits(1, 1))), (1, 1));
    }

    /// A repair batch reaches past the old tip, so it can carry more work than
    /// the headers it replaces.
    #[test]
    fn a_fork_repair_fits_the_batch_limit() {
        assert_eq!(repair_depth(MAX_HEADERS), REWIND);
        assert_eq!(repair_depth(REWIND + 2), REWIND);
        assert_eq!(repair_depth(100), 98);
        assert_eq!(repair_depth(2), 0);
        assert_eq!(repair_depth(1), 0);
        for max_batch in 2..=REWIND + 3 {
            assert!(repair_depth(max_batch) + 2 <= max_batch, "{max_batch}");
        }
    }

    #[test]
    fn checkpoint_is_read_from_the_enclave_refusal() {
        let refusal = utexo_bridge_enclave::networks::rgb::spv::SpvError::BelowCheckpoint {
            got: 151,
            checkpoint: 200,
        }
        .to_string();
        assert_eq!(checkpoint_in(&refusal), Some(200));
        assert_eq!(
            checkpoint_in("batch start_height 5 leaves a gap above tip 3"),
            None
        );
        assert_eq!(checkpoint_in("below checkpoint x"), None);
    }
}

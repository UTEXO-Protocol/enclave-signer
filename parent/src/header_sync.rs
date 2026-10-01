//! Keeps the enclave's header chain at the tip of one Electrum server.
//!
//! The parent holds no chain and no cursor. Each step reads the enclave tip,
//! checks it against the source and sends the missing headers.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, ensure, Context};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio::task::AbortHandle;

use crate::enclave_proto::{
    enclave_request, enclave_response, EnclaveRequest, GetLastSavedBlockRequest,
    SubmitHeadersRequest, SubmitHeadersResponse,
};
use crate::grpc_server::ParentAdapterService;
use crate::header_source::{ElectrumSource, CALL_TIMEOUT, MAX_HEADERS};

/// Headers above a fork point that a fork repair resends.
const REWIND: u32 = 99;
/// Half the enclave's limit of 100,000 headers in 60 seconds.
const RATE_LIMIT: u32 = 50_000;
const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Failed steps in a row that make the state `stalled`.
const STALL_AFTER: u32 = 3;
const TIP_AGE_WARN_SECS: u32 = 3600;
const TIP_AGE_ERROR_SECS: u32 = 7200;

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
    interval: Duration,
    status: watch::Sender<SyncStatus>,
    /// A source call that timed out and may still run on a blocking thread.
    pending: Option<AbortHandle>,
    failures: u32,
    sent: VecDeque<(Instant, u32)>,
    age_level: u8,
}

impl HeaderSync {
    pub fn new(
        service: ParentAdapterService,
        source: Option<ElectrumSource>,
        interval: Duration,
    ) -> (Self, watch::Receiver<SyncStatus>) {
        let (status, rx) = watch::channel(SyncStatus::default());
        let sync = Self {
            service,
            source: source.map(Arc::new),
            interval,
            status,
            pending: None,
            failures: 0,
            sent: VecDeque::new(),
            age_level: 0,
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
        self.status.send_modify(|s| match result {
            Ok(state) => {
                *failures = 0;
                s.last_error = None;
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
                SyncState::Unconfigured => {
                    tracing::error!("HEADER_ELECTRUM_URL is not set; the parent syncs no headers")
                }
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
        self.log_tip_age(health.spv_tip_age_secs);

        let (h, hash) = self.enclave_tip().await?;
        self.status.send_modify(|s| s.enclave_tip = Some(h));
        let s = self.source_call(&source, |src| src.tip()).await?;
        self.status.send_modify(|st| {
            st.source_tip = Some(s);
            st.lag_blocks = Some(s.saturating_sub(h));
        });
        ensure!(s >= h, "source tip {s} is below the enclave tip {h}");

        let at_h = self
            .source_call(&source, move |src| src.headers(h, 1))
            .await?;
        let at_h = at_h
            .first()
            .context("source has no header at the enclave tip")?;
        let (start, prev) = if sha256d(at_h) == hash {
            if s == h {
                return Ok(SyncState::Synced);
            }
            (h + 1, Some(hash))
        } else {
            ensure!(
                s > h,
                "source header at {h} differs from the enclave; waiting for the source to get ahead"
            );
            (h.saturating_sub(REWIND).max(1), None)
        };
        let count = (s - start + 1).min(MAX_HEADERS);
        let headers = self
            .source_call(&source, move |src| src.headers(start, count))
            .await?;
        let last = headers.last().context("source sent no headers")?;
        if let Some(prev) = prev {
            ensure!(
                headers[0][4..36] == prev,
                "source header {start} does not link to the enclave tip"
            );
        }
        for (i, pair) in headers.windows(2).enumerate() {
            ensure!(
                pair[1][4..36] == sha256d(&pair[0]),
                "source header {} does not link to the one before",
                start as usize + i + 1
            );
        }

        let len = headers.len() as u32;
        let last_height = start + len - 1;
        let last_hash = sha256d(last);
        self.wait_for_rate(len).await;
        let reply = self.submit(start, headers).await?;
        ensure!(
            reply.headers_accepted == len
                && reply.last_block_height == last_height
                && reply.last_block_hash == last_hash,
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

    fn log_tip_age(&mut self, age: u32) {
        let level = match age {
            a if a >= TIP_AGE_ERROR_SECS => 2,
            a if a >= TIP_AGE_WARN_SECS => 1,
            _ => 0,
        };
        if level > self.age_level {
            if level == 2 {
                tracing::error!(age, "enclave header tip is two hours old; signing stops");
            } else {
                tracing::warn!(age, "enclave header tip is one hour old");
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

    async fn wait_for_rate(&mut self, n: u32) {
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
                Some((oldest, _)) if used + n > RATE_LIMIT => {
                    tokio::time::sleep(RATE_WINDOW - now.duration_since(*oldest)).await;
                }
                _ => break,
            }
        }
        self.sent.push_back((Instant::now(), n));
    }

    async fn enclave_tip(&self) -> anyhow::Result<(u32, [u8; 32])> {
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
                let hash = r
                    .block_hash
                    .try_into()
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
        &self,
        start_height: u32,
        headers: Vec<[u8; 80]>,
    ) -> anyhow::Result<SubmitHeadersResponse> {
        let req = EnclaveRequest {
            request: Some(enclave_request::Request::SubmitHeaders(
                SubmitHeadersRequest {
                    headers: headers.iter().map(|h| h.to_vec()).collect(),
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
                bail!("enclave refused headers (code {}): {}", e.code, e.message)
            }
            other => bail!("unexpected enclave response: {other:?}"),
        }
    }
}

fn sha256d(header: &[u8; 80]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(header)).into()
}

//! Signed mint results, kept so a retry after a lost reply gets the same
//! bytes instead of a replay refusal.
//!
//! In memory and per instance, like the replay guard: a restart clears it.
//! An entry is returned only for the byte-identical request that made it, so
//! it gives the caller nothing the first reply did not already carry.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::replay_guard::Bounds;
use crate::proto::EnclaveResponse;

struct Entry {
    at: Instant,
    request: [u8; 32],
    response: EnclaveResponse,
}

#[derive(Default)]
struct Inner {
    map: HashMap<[u8; 32], Entry>,
    order: VecDeque<[u8; 32]>,
}

pub struct SignedResultCache {
    inner: Mutex<Inner>,
    bounds: Bounds,
}

/// The cache of the mint signer. The operator sets its limits. A mint has one
/// input and few outputs, so a reply is small.
impl Default for SignedResultCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            bounds: Bounds::MintReply,
        }
    }
}

impl SignedResultCache {
    pub fn with_capacity(max: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            bounds: Bounds::Fixed { max, ttl },
        }
    }

    /// The reply for `op_key`, if `request` is the digest that made it.
    pub fn get(&self, op_key: &[u8; 32], request: &[u8; 32]) -> Option<EnclaveResponse> {
        self.get_at(op_key, request, Instant::now())
    }

    pub(super) fn get_at(
        &self,
        op_key: &[u8; 32],
        request: &[u8; 32],
        now: Instant,
    ) -> Option<EnclaveResponse> {
        let (_, ttl) = self.bounds.get();
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let entry = g.map.get(op_key)?;
        let live = now.saturating_duration_since(entry.at) < ttl;
        (live && &entry.request == request).then(|| entry.response.clone())
    }

    /// Keep `response` for `op_key`. Evicts expired entries, then the oldest.
    pub fn put(&self, op_key: [u8; 32], request: [u8; 32], response: EnclaveResponse) {
        self.put_at(op_key, request, response, Instant::now());
    }

    pub(super) fn put_at(
        &self,
        op_key: [u8; 32],
        request: [u8; 32],
        response: EnclaveResponse,
        now: Instant,
    ) {
        let (max, ttl) = self.bounds.get();
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if g.map.remove(&op_key).is_some() {
            g.order.retain(|k| k != &op_key);
        }
        while let Some(&oldest) = g.order.front() {
            let expired = g
                .map
                .get(&oldest)
                .is_none_or(|e| now.saturating_duration_since(e.at) >= ttl);
            if !expired && g.map.len() < max {
                break;
            }
            g.order.pop_front();
            g.map.remove(&oldest);
        }
        g.order.push_back(op_key);
        g.map.insert(
            op_key,
            Entry {
                at: now,
                request,
                response,
            },
        );
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.inner.lock().map(|g| g.map.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(tag: u8) -> EnclaveResponse {
        EnclaveResponse {
            response: Some(crate::proto::enclave_response::Response::Error(
                crate::proto::ErrorResponse {
                    message: format!("r{tag}"),
                    ..Default::default()
                },
            )),
        }
    }

    #[test]
    fn returns_the_reply_only_for_the_same_request() {
        let c = SignedResultCache::default();
        c.put([1; 32], [9; 32], reply(1));
        assert_eq!(c.get(&[1; 32], &[9; 32]), Some(reply(1)));
        assert_eq!(c.get(&[1; 32], &[8; 32]), None);
        assert_eq!(c.get(&[2; 32], &[9; 32]), None);
    }

    #[test]
    fn forgets_an_entry_after_the_ttl() {
        let c = SignedResultCache::with_capacity(4, Duration::from_secs(10));
        let t0 = Instant::now();
        c.put_at([1; 32], [9; 32], reply(1), t0);
        assert!(c
            .get_at(&[1; 32], &[9; 32], t0 + Duration::from_secs(9))
            .is_some());
        assert!(c
            .get_at(&[1; 32], &[9; 32], t0 + Duration::from_secs(10))
            .is_none());
    }

    #[test]
    fn evicts_the_oldest_at_capacity() {
        let c = SignedResultCache::with_capacity(2, Duration::from_secs(60));
        c.put([1; 32], [1; 32], reply(1));
        c.put([2; 32], [2; 32], reply(2));
        c.put([3; 32], [3; 32], reply(3));
        assert_eq!(c.count(), 2);
        assert_eq!(c.get(&[1; 32], &[1; 32]), None);
        assert!(c.get(&[3; 32], &[3; 32]).is_some());
    }

    /// The operator sets the limits, and a change reaches a cache that holds
    /// replies.
    #[test]
    fn the_cache_of_the_mint_signer_follows_the_limits_in_force() {
        let c = SignedResultCache::default();
        let t0 = Instant::now() - Duration::from_secs(600);
        c.put_at([1; 32], [9; 32], reply(1), t0);
        assert!(c.get(&[1; 32], &[9; 32]).is_some());

        crate::limits::change_for_test(|l| l.mint_reply_ttl_secs = 300);
        assert_eq!(c.get(&[1; 32], &[9; 32]), None);

        crate::limits::change_for_test(|l| l.mint_reply_max_entries = 1);
        c.put([2; 32], [2; 32], reply(2));
        c.put([3; 32], [3; 32], reply(3));
        assert_eq!(c.count(), 1);
    }

    #[test]
    fn a_new_put_replaces_the_old_one_for_the_key() {
        let c = SignedResultCache::with_capacity(2, Duration::from_secs(60));
        c.put([1; 32], [1; 32], reply(1));
        c.put([1; 32], [2; 32], reply(2));
        assert_eq!(c.count(), 1);
        assert_eq!(c.get(&[1; 32], &[2; 32]), Some(reply(2)));
    }
}

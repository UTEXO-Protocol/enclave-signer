//! The signed responses the parent keeps for a retried bridge sign.
//!
//! The enclave commits its replay key as soon as its response is written to
//! the parent. If the gRPC stream to the node is gone by then, the response is
//! lost on the way out, and the enclave refuses the retry as a duplicate for
//! the length of its replay window. Nothing may lose a response between the
//! enclave and the node, so the parent keeps the reply of every EVM->RGB
//! bridge sign, keyed by the exact enclave request, and captures it inside the
//! blocking exchange itself: a dropped gRPC future cannot discard it.
//!
//! A retry of the same request is answered from here without a second
//! exchange. A retry that arrives while the first exchange is still waiting on
//! the enclave joins it and gets the reply itself over a watch channel, also
//! when the store keeps nothing (a reply above the byte limit) or evicts it at
//! once. So the enclave never sees two copies of one request in flight.
//!
//! The parent is untrusted; this is a delivery aid, not a security control. A
//! wrong stored reply fails in the node or in rgb-lib, as any wrong parent
//! output does. The enclave's own guard still refuses a second PSBT for the
//! same deposit. Bounded by count, bytes and age; a restart clears it, and
//! then only the enclave's window applies.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use prost::Message;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::enclave_proto::{EnclaveRequest, SignedPsbtResponse};

/// Default age limit of a stored reply. The enclave's replay window is one
/// hour too; after it a repeated request is signed again anyway.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);

/// Default count limit. A mint reply is a few KB, so this is a few MB.
pub const DEFAULT_MAX_ENTRIES: usize = 1_024;

/// Default byte limit over all stored replies.
pub const DEFAULT_MAX_BYTES: usize = 16 << 20;

/// The parent's answer to a claim on a request key.
pub enum Claim {
    /// This exact request was signed before, or its exchange has just
    /// finished: answer with these bytes.
    Serve(SignedPsbtResponse),
    /// Nobody holds this key: the caller performs the exchange and reports
    /// through the lead. A retry that arrives meanwhile waits on it.
    Lead(Lead),
}

enum Slot {
    /// An exchange is running. Its reply is sent on the channel; a dropped
    /// sender with no reply means it failed and the waiters try themselves.
    InFlight(watch::Receiver<Option<SignedPsbtResponse>>),
    Done(SignedPsbtResponse),
}

struct State {
    slots: HashMap<[u8; 32], Slot>,
    /// Finished entries, oldest first, for age and capacity eviction. Its
    /// length is the count of kept replies; `slots` also holds in-flight keys.
    order: VecDeque<([u8; 32], Instant)>,
    bytes: usize,
}

impl State {
    fn evict_oldest(&mut self) -> bool {
        match self.order.pop_front() {
            Some((old, _)) => {
                if let Some(Slot::Done(response)) = self.slots.remove(&old) {
                    self.bytes -= response.signed_psbt.len();
                }
                true
            }
            None => false,
        }
    }

    fn evict_expired(&mut self, ttl: Duration, now: Instant) {
        while let Some(&(_, stored_at)) = self.order.front() {
            if now.saturating_duration_since(stored_at) >= ttl {
                self.evict_oldest();
            } else {
                break;
            }
        }
    }
}

/// Replies by request key, with one in-flight exchange per key.
pub struct SignedResponses {
    inner: Mutex<State>,
    ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
}

/// The right to perform the exchange for one key. Drop it without
/// [`Lead::complete`] when the exchange failed: waiters are released and the
/// next of them leads.
#[must_use = "complete the lead with the reply, or drop it to release the waiters"]
pub struct Lead {
    cache: Arc<SignedResponses>,
    key: [u8; 32],
    done: Option<watch::Sender<Option<SignedPsbtResponse>>>,
}

impl Lead {
    /// Store `response` for the key and hand it to the waiters.
    pub fn complete(mut self, response: &SignedPsbtResponse) {
        let Some(done) = self.done.take() else {
            return;
        };
        self.cache.store(self.key, response, Instant::now());
        done.send_replace(Some(response.clone()));
    }
}

impl Drop for Lead {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            // Failed or abandoned: free the key, then wake the waiters by
            // dropping the sender.
            let mut c = self.cache.inner.lock().unwrap_or_else(|p| p.into_inner());
            if matches!(c.slots.get(&self.key), Some(Slot::InFlight(_))) {
                c.slots.remove(&self.key);
            }
            drop(c);
            drop(done);
        }
    }
}

impl SignedResponses {
    pub fn new(ttl: Duration, max_entries: usize, max_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(State {
                slots: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
            }),
            ttl,
            max_entries,
            max_bytes,
        })
    }

    /// The key of a request: SHA-256 of its protobuf encoding. Two requests
    /// with the same key ask the enclave for the same signature.
    pub fn key(request: &EnclaveRequest) -> [u8; 32] {
        Sha256::digest(request.encode_to_vec()).into()
    }

    /// Claim `key`: a stored reply, or the lead on a new exchange. A claim on a
    /// key whose exchange is in flight waits for it and gets its reply; if the
    /// exchange fails, the claim looks again and may lead.
    pub async fn claim(self: &Arc<Self>, key: [u8; 32]) -> Claim {
        loop {
            let mut waiter = {
                let mut c = self.inner.lock().unwrap_or_else(|p| p.into_inner());
                let now = Instant::now();
                c.evict_expired(self.ttl, now);
                match c.slots.get(&key) {
                    Some(Slot::Done(response)) => return Claim::Serve(response.clone()),
                    Some(Slot::InFlight(rx)) => rx.clone(),
                    None => {
                        let (tx, rx) = watch::channel(None);
                        c.slots.insert(key, Slot::InFlight(rx));
                        return Claim::Lead(Lead {
                            cache: Arc::clone(self),
                            key,
                            done: Some(tx),
                        });
                    }
                }
            };
            // A reply comes on the channel itself, so a waiter does not
            // depend on the store keeping it. A failed exchange sends none:
            // look again.
            let _ = waiter.changed().await;
            let reply = waiter.borrow_and_update().clone();
            if let Some(response) = reply {
                return Claim::Serve(response);
            }
        }
    }

    fn store(&self, key: [u8; 32], response: &SignedPsbtResponse, now: Instant) {
        let size = response.signed_psbt.len();
        let mut c = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // The in-flight slot goes in every case; a reply too large to keep
        // simply leaves no entry, and a later retry is a new exchange.
        c.slots.remove(&key);
        if size > self.max_bytes {
            return;
        }
        c.evict_expired(self.ttl, now);
        // Count kept replies only: in-flight keys hold no reply.
        while c.order.len() >= self.max_entries || c.bytes + size > self.max_bytes {
            if !c.evict_oldest() {
                break;
            }
        }
        c.bytes += size;
        c.slots.insert(key, Slot::Done(response.clone()));
        c.order.push_back((key, now));
    }

    /// Finished replies currently stored.
    pub fn stored(&self) -> usize {
        let c = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        c.order.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(tag: u8) -> SignedPsbtResponse {
        SignedPsbtResponse {
            signed_psbt: vec![tag; 64],
            inputs_signed: 1,
        }
    }

    fn lead(claim: Claim) -> Lead {
        match claim {
            Claim::Lead(lead) => lead,
            Claim::Serve(_) => panic!("expected the lead"),
        }
    }

    fn served(claim: Claim) -> SignedPsbtResponse {
        match claim {
            Claim::Serve(r) => r,
            Claim::Lead(_) => panic!("expected a stored reply"),
        }
    }

    #[tokio::test]
    async fn a_completed_exchange_answers_the_same_request_again() {
        let cache = SignedResponses::new(DEFAULT_TTL, 8, 1 << 20);
        lead(cache.claim([1; 32]).await).complete(&reply(7));

        assert_eq!(served(cache.claim([1; 32]).await), reply(7));
        assert!(matches!(cache.claim([2; 32]).await, Claim::Lead(_)));
        assert_eq!(cache.stored(), 1);
    }

    #[tokio::test]
    async fn a_retry_during_the_exchange_waits_and_gets_its_reply() {
        let cache = SignedResponses::new(DEFAULT_TTL, 8, 1 << 20);
        let first = lead(cache.claim([1; 32]).await);

        let waiter = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { served(cache.claim([1; 32]).await) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "the retry waits for the exchange");

        first.complete(&reply(9));
        assert_eq!(waiter.await.unwrap(), reply(9));
    }

    /// A waiter gets the reply from the channel, also when the store keeps
    /// nothing (above the byte limit): it does not lead a second exchange.
    #[tokio::test]
    async fn a_waiter_gets_a_reply_the_store_did_not_keep() {
        let cache = SignedResponses::new(DEFAULT_TTL, 8, 10);
        let first = lead(cache.claim([1; 32]).await);

        let waiter = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { served(cache.claim([1; 32]).await) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;

        first.complete(&reply(4));
        assert_eq!(waiter.await.unwrap(), reply(4));
        assert_eq!(
            cache.stored(),
            0,
            "a 64-byte reply is above the 10-byte budget"
        );
    }

    #[tokio::test]
    async fn a_failed_exchange_releases_the_waiter_to_lead() {
        let cache = SignedResponses::new(DEFAULT_TTL, 8, 1 << 20);
        let first = lead(cache.claim([1; 32]).await);

        let waiter = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { lead(cache.claim([1; 32]).await) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(first);

        let second = waiter.await.unwrap();
        second.complete(&reply(3));
        assert_eq!(served(cache.claim([1; 32]).await), reply(3));
    }

    #[tokio::test]
    async fn a_reply_expires_with_the_window() {
        let cache = SignedResponses::new(Duration::from_millis(30), 8, 1 << 20);
        lead(cache.claim([1; 32]).await).complete(&reply(1));
        assert!(matches!(cache.claim([1; 32]).await, Claim::Serve(_)));

        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(matches!(cache.claim([1; 32]).await, Claim::Lead(_)));
        assert_eq!(cache.stored(), 0);
    }

    #[tokio::test]
    async fn count_and_byte_limits_evict_the_oldest_reply() {
        let cache = SignedResponses::new(DEFAULT_TTL, 2, 1 << 20);
        lead(cache.claim([1; 32]).await).complete(&reply(1));
        lead(cache.claim([2; 32]).await).complete(&reply(2));
        lead(cache.claim([3; 32]).await).complete(&reply(3));
        assert_eq!(cache.stored(), 2);
        assert!(matches!(cache.claim([1; 32]).await, Claim::Lead(_)));
        assert_eq!(served(cache.claim([3; 32]).await), reply(3));

        // 150 bytes hold two 64-byte replies, not three.
        let cache = SignedResponses::new(DEFAULT_TTL, 8, 150);
        lead(cache.claim([1; 32]).await).complete(&reply(1));
        lead(cache.claim([2; 32]).await).complete(&reply(2));
        lead(cache.claim([3; 32]).await).complete(&reply(3));
        assert_eq!(cache.stored(), 2);
        assert!(matches!(cache.claim([1; 32]).await, Claim::Lead(_)));

        // A reply above the whole budget is not stored; the key is free again.
        let cache = SignedResponses::new(DEFAULT_TTL, 8, 10);
        lead(cache.claim([1; 32]).await).complete(&reply(1));
        assert_eq!(cache.stored(), 0);
        assert!(matches!(cache.claim([1; 32]).await, Claim::Lead(_)));
    }

    /// Exchanges in flight do not count against the count limit.
    #[tokio::test]
    async fn in_flight_exchanges_do_not_take_the_place_of_kept_replies() {
        let cache = SignedResponses::new(DEFAULT_TTL, 2, 1 << 20);
        let _a = lead(cache.claim([10; 32]).await);
        let _b = lead(cache.claim([11; 32]).await);

        lead(cache.claim([1; 32]).await).complete(&reply(1));
        lead(cache.claim([2; 32]).await).complete(&reply(2));
        assert_eq!(cache.stored(), 2);
        assert_eq!(served(cache.claim([1; 32]).await), reply(1));
        assert_eq!(served(cache.claim([2; 32]).await), reply(2));
    }

    #[test]
    fn the_key_is_the_request_digest() {
        use crate::enclave_proto::{enclave_request, SignRequest};
        let a = EnclaveRequest {
            request: Some(enclave_request::Request::Sign(SignRequest {
                amount: 1,
                ..Default::default()
            })),
        };
        let b = EnclaveRequest {
            request: Some(enclave_request::Request::Sign(SignRequest {
                amount: 2,
                ..Default::default()
            })),
        };
        assert_eq!(SignedResponses::key(&a), SignedResponses::key(&a));
        assert_ne!(SignedResponses::key(&a), SignedResponses::key(&b));
    }
}

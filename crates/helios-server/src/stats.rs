//! Request counters and path access tracking, kept off shared cache lines:
//! the narinfo path runs at over a million requests per second, where a
//! single atomic or lock touched by every core would become the bottleneck.

use std::collections::HashSet;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use crate::state::{PassThroughHasher, PathKey};

const STRIPES: usize = 32;

#[repr(align(128))]
#[derive(Default)]
struct Padded(AtomicU64);

static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// Each thread increments its own stripe.
    static SLOT: usize = NEXT_SLOT.fetch_add(1, Ordering::Relaxed) % STRIPES;
}

/// A monotonically increasing counter striped across cache lines.
#[derive(Default)]
pub struct Counter {
    stripes: [Padded; STRIPES],
}

impl Counter {
    pub fn add(&self, n: u64) {
        let slot = SLOT.with(|s| *s);
        self.stripes[slot].0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.add(1);
    }

    pub fn get(&self) -> u64 {
        self.stripes.iter().map(|s| s.0.load(Ordering::Relaxed)).sum()
    }
}

#[derive(Default)]
pub struct Counters {
    pub narinfo_hits: Counter,
    pub narinfo_misses: Counter,
    pub nar_requests: Counter,
    pub uploads: Counter,
    pub upload_bytes: Counter,
    pub published_paths: Counter,
}

type KeySet = HashSet<PathKey, BuildHasherDefault<PassThroughHasher>>;

const SHARDS: usize = 64;

/// Paths served since the last flush. Sharded by hash so concurrent
/// requests rarely share a lock.
pub struct Access {
    shards: Vec<Mutex<KeySet>>,
}

impl Default for Access {
    fn default() -> Self {
        Self { shards: (0..SHARDS).map(|_| Mutex::new(KeySet::default())).collect() }
    }
}

impl Access {
    pub fn touch(&self, key: PathKey) {
        let shard = &self.shards[usize::from(key.hash[19]) % SHARDS];
        shard.lock().unwrap_or_else(PoisonError::into_inner).insert(key);
    }

    /// Takes every recorded key, leaving the tracker empty.
    pub fn drain(&self) -> Vec<PathKey> {
        let mut out = Vec::new();
        for shard in &self.shards {
            let taken = std::mem::take(&mut *shard.lock().unwrap_or_else(PoisonError::into_inner));
            out.extend(taken);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_sum_across_threads() {
        let c = std::sync::Arc::new(Counter::default());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || (0..1000).for_each(|_| c.inc()))
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        assert_eq!(c.get(), 8000);
    }

    #[test]
    fn access_deduplicates_and_drains() {
        let a = Access::default();
        let k = PathKey { cache: 1, hash: [7; 20] };
        a.touch(k);
        a.touch(k);
        a.touch(PathKey { cache: 2, hash: [7; 20] });
        assert_eq!(a.drain().len(), 2);
        assert!(a.drain().is_empty());
    }
}

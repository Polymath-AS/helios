//! Shared server state. The hot read path (narinfo lookups) is served from
//! memory: a presence index answers misses without touching SQLite, and an
//! LRU holds rendered narinfo bodies for hits.

use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use helios_core::{Compression, Signer};
use rusqlite::params;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::sync::mpsc;

use crate::audit::AuditEvent;
use crate::config::Config;
use crate::db::Db;

/// A published path: cache id plus the 20-byte decoded store path hash.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PathKey {
    pub cache: u32,
    pub hash: [u8; 20],
}

/// Per-process key for `PathKey` hashes. Store path hashes come from
/// clients, so a fixed hash would let a pusher publish paths that all
/// collide and slow every lookup to a crawl.
static HASH_KEY: std::sync::LazyLock<[u64; 3]> = std::sync::LazyLock::new(|| {
    let mut bytes = [0u8; 24];
    helios_core::random_bytes(&mut bytes);
    let word = |i: usize| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
    [word(0), word(1), word(2)]
});

/// The 128-bit product folded to 64 bits, as in foldhash and wyhash.
fn fold_mul(a: u64, b: u64) -> u64 {
    let full = u128::from(a) * u128::from(b);
    (full as u64) ^ ((full >> 64) as u64)
}

impl Hash for PathKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let k = &*HASH_KEY;
        let word = |i: usize| u64::from_le_bytes(self.hash[i..i + 8].try_into().expect("8 bytes"));
        let tail = u64::from(u32::from_le_bytes(self.hash[16..20].try_into().expect("4 bytes"))) | (u64::from(self.cache) << 32);
        state.write_u64(fold_mul(fold_mul(word(0) ^ k[0], word(8) ^ k[1]) ^ tail, k[2]));
    }
}

#[derive(Default)]
pub struct PassThroughHasher(u64);

impl Hasher for PassThroughHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

pub type PathIndex = HashSet<PathKey, BuildHasherDefault<PassThroughHasher>>;

#[derive(Clone, Copy)]
pub struct CacheInfo {
    pub id: u32,
    pub public: bool,
}

#[derive(Clone, Copy)]
pub struct TokenState {
    pub expires_at: i64,
    pub revoked: bool,
}

pub struct AppState {
    pub cfg: Config,
    pub db: Db,
    pub signer: Option<Signer>,
    pub caches: RwLock<HashMap<Box<str>, CacheInfo>>,
    pub index: RwLock<PathIndex>,
    pub narinfo: quick_cache::sync::Cache<PathKey, Bytes, quick_cache::UnitWeighter, BuildHasherDefault<PassThroughHasher>>,
    pub tokens: RwLock<HashMap<Box<str>, TokenState>>,
    pub audit: mpsc::UnboundedSender<AuditEvent>,
    pub counters: crate::stats::Counters,
    pub access: crate::stats::Access,
    pub uploads: crate::chunked::Sessions,
    pub traces: RwLock<crate::traces::Traces>,
    /// Bumped, under the index write lock, whenever paths are published or
    /// forgotten. A narinfo read from the database is cached only if this
    /// did not move meanwhile, so a body from before an eviction or re-push
    /// is never cached after it.
    pub narinfo_epoch: std::sync::atomic::AtomicU64,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn load(cfg: Config, db: Db, signer: Option<Signer>, audit: mpsc::UnboundedSender<AuditEvent>) -> anyhow::Result<Self> {
        let (caches, index, tokens, traces) = db.read(|conn| {
            let mut caches = HashMap::new();
            let mut stmt = conn.prepare("SELECT id, name, is_public FROM caches")?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let name: String = r.get(1)?;
                caches.insert(name.into_boxed_str(), CacheInfo { id: r.get(0)?, public: r.get::<_, i64>(2)? != 0 });
            }

            let count: usize = conn.query_row("SELECT count(*) FROM paths", [], |r| r.get(0))?;
            let mut index = PathIndex::with_capacity_and_hasher(count + count / 4, Default::default());
            let mut stmt = conn.prepare("SELECT cache_id, hash FROM paths")?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let hash = r.get_ref(1)?.as_blob()?;
                if let Ok(hash) = <[u8; 20]>::try_from(hash) {
                    index.insert(PathKey { cache: r.get(0)?, hash });
                }
            }

            let mut tokens = HashMap::new();
            let mut stmt = conn.prepare("SELECT jti, expires_at, revoked_at IS NOT NULL FROM tokens")?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let jti: String = r.get(0)?;
                tokens.insert(jti.into_boxed_str(), TokenState { expires_at: r.get(1)?, revoked: r.get(2)? });
            }
            Ok((caches, index, tokens, crate::traces::load(conn)?))
        })?;

        tracing::info!(caches = caches.len(), paths = index.len(), tokens = tokens.len(), "loaded state");
        let narinfo = quick_cache::sync::Cache::with(
            cfg.narinfo_cache_entries,
            cfg.narinfo_cache_entries as u64,
            quick_cache::UnitWeighter,
            Default::default(),
            quick_cache::sync::DefaultLifecycle::default(),
        );
        Ok(Self {
            cfg,
            db,
            signer,
            caches: RwLock::new(caches),
            index: RwLock::new(index),
            narinfo,
            tokens: RwLock::new(tokens),
            audit,
            counters: Default::default(),
            access: Default::default(),
            uploads: Default::default(),
            traces: RwLock::new(traces),
            narinfo_epoch: Default::default(),
        })
    }

    pub fn cache(&self, name: &str) -> Option<CacheInfo> {
        self.caches.rd().get(name).copied()
    }

    pub fn nar_path(&self, file_hash: &[u8; 32], compression: Compression) -> PathBuf {
        let name = helios_core::nix32_encode(file_hash);
        self.cfg.data_dir.join("nar").join(&name[..2]).join(format!("{name}{}", compression.extension()))
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.cfg.data_dir.join("tmp")
    }

    /// Creates `name`, or gives an existing cache the visibility `public`.
    /// Returns what changed, if anything.
    pub fn declare_cache(&self, name: &str, public: bool) -> rusqlite::Result<Option<&'static str>> {
        if self.insert_cache(name, public)?.is_some() {
            return Ok(Some("created"));
        }
        if self.cache(name).is_some_and(|c| c.public == public) {
            return Ok(None);
        }
        self.db.write(|conn| conn.execute("UPDATE caches SET is_public = ?2 WHERE name = ?1", params![name, public]))?;
        if let Some(c) = self.caches.wr().get_mut(name) {
            c.public = public;
        }
        Ok(Some(if public { "made public" } else { "made private" }))
    }

    pub fn insert_cache(&self, name: &str, public: bool) -> rusqlite::Result<Option<CacheInfo>> {
        let id = self.db.write(|conn| -> rusqlite::Result<Option<u32>> {
            conn.execute(
                "INSERT INTO caches (name, is_public, created_at) VALUES (?1, ?2, ?3) ON CONFLICT (name) DO NOTHING",
                params![name, public, crate::db::now()],
            )?;
            if conn.changes() == 0 {
                return Ok(None);
            }
            Ok(Some(conn.last_insert_rowid() as u32))
        })?;
        Ok(id.map(|id| {
            let info = CacheInfo { id, public };
            self.caches.wr().insert(name.into(), info);
            info
        }))
    }
}

/// Lock access that ignores poisoning: every critical section here leaves
/// the data consistent, so a panic elsewhere must not wedge the server.
pub trait Locked<T> {
    fn rd(&self) -> RwLockReadGuard<'_, T>;
    fn wr(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T> Locked<T> for RwLock<T> {
    fn rd(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(PoisonError::into_inner)
    }
    fn wr(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_caches_are_created_and_take_the_declared_visibility() {
        let dir = std::env::temp_dir().join(format!("helios-state-test-{}", helios_core::uuid_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = Config {
            data_dir: dir.clone(),
            jwt_secret: None,
            admin_secret: None,
            accel_redirect: None,
            trust_proxy: false,
            narinfo_cache_entries: 16,
            max_upload_bytes: 1 << 20,
            upload_grace: std::time::Duration::from_secs(1),
            gc_interval: std::time::Duration::from_secs(3600),
            audit_retention: std::time::Duration::from_secs(3600),
            compression_level: 3,
            compression_window_log: 27,
        };
        let db = Db::open(&dir.join("helios.db")).unwrap();
        let (tx, _rx) = mpsc::unbounded_channel();
        let st = AppState::load(cfg.clone(), db, None, tx).unwrap();

        assert_eq!(st.declare_cache("team", false).unwrap(), Some("created"));
        assert_eq!(st.declare_cache("team", false).unwrap(), None);
        assert_eq!(st.declare_cache("team", true).unwrap(), Some("made public"));
        assert!(st.cache("team").unwrap().public);

        // The change is in the database, not only in memory.
        let (tx, _rx) = mpsc::unbounded_channel();
        let reloaded = AppState::load(cfg, Db::open(&dir.join("helios.db")).unwrap(), None, tx).unwrap();
        assert!(reloaded.cache("team").unwrap().public);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

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

impl Hash for PathKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Store path hashes are uniformly distributed already.
        let mut word = [0u8; 8];
        word.copy_from_slice(&self.hash[..8]);
        state.write_u64(u64::from_ne_bytes(word) ^ u64::from(self.cache));
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
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn load(cfg: Config, db: Db, signer: Option<Signer>, audit: mpsc::UnboundedSender<AuditEvent>) -> anyhow::Result<Self> {
        let (caches, index, tokens) = db.read(|conn| {
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
            Ok((caches, index, tokens))
        })?;

        crate::log::info!("loaded state: {} caches, {} paths, {} tokens", caches.len(), index.len(), tokens.len());
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

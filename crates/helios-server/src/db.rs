//! SQLite in WAL mode: one writer connection behind a mutex, and one
//! read-only connection per blocking-pool thread.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{Connection, OpenFlags};
use std::sync::{Mutex, PoisonError};

const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE caches (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    is_public INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
CREATE TABLE blobs (
    id INTEGER PRIMARY KEY,
    file_hash BLOB NOT NULL UNIQUE,
    file_size INTEGER NOT NULL,
    compression TEXT NOT NULL,
    nar_hash BLOB NOT NULL,
    nar_size INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX blobs_nar_hash ON blobs (nar_hash);
CREATE TABLE paths (
    id INTEGER PRIMARY KEY,
    cache_id INTEGER NOT NULL REFERENCES caches (id),
    hash BLOB NOT NULL,
    blob_id INTEGER NOT NULL REFERENCES blobs (id),
    store_path TEXT NOT NULL,
    narinfo BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX paths_cache_hash ON paths (cache_id, hash);
CREATE INDEX paths_blob ON paths (blob_id, cache_id);
CREATE TABLE tokens (
    jti TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    caches TEXT NOT NULL,
    perms TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revoked_by TEXT,
    revocation_reason TEXT
);
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    cache TEXT,
    detail TEXT NOT NULL,
    ip TEXT,
    status INTEGER NOT NULL
);
CREATE INDEX audit_log_ts ON audit_log (ts);
"#,
    // Last narinfo hit per path, for least-recently-used eviction.
    r#"
ALTER TABLE paths ADD COLUMN accessed_at INTEGER NOT NULL DEFAULT 0;
UPDATE paths SET accessed_at = created_at;
CREATE INDEX paths_accessed ON paths (accessed_at);
"#,
    // Paths auto-GC must keep, with their closures.
    r#"
CREATE TABLE pins (
    cache_id INTEGER NOT NULL REFERENCES caches (id),
    hash BLOB NOT NULL,
    store_path TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY (cache_id, hash)
);
"#,
    // Build traces of content-addressed derivations, rendered and signed.
    r#"
CREATE TABLE build_traces (
    cache_id INTEGER NOT NULL REFERENCES caches (id),
    id TEXT NOT NULL,
    out_path TEXT NOT NULL,
    body BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (cache_id, id)
);
"#,
];

const PRAGMAS: &str = "
PRAGMA busy_timeout = 5000;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 4294967296;
PRAGMA cache_size = -65536;
";

#[derive(Clone)]
pub struct Db {
    path: Arc<PathBuf>,
    writer: Arc<Mutex<Connection>>,
}

thread_local! {
    static READER: RefCell<Option<(Arc<PathBuf>, Connection)>> = const { RefCell::new(None) };
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(PRAGMAS)?;
        migrate(&mut conn)?;
        Ok(Self { path: Arc::new(path.to_owned()), writer: Arc::new(Mutex::new(conn)) })
    }

    /// Runs `f` on the writer connection. Blocking: call from spawn_blocking.
    pub fn write<T>(&self, f: impl FnOnce(&mut Connection) -> T) -> T {
        f(&mut self.writer.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Runs `f` on this thread's read-only connection. Blocking.
    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        READER.with(|cell| {
            let mut slot = cell.borrow_mut();
            let stale = !matches!(&*slot, Some((p, _)) if Arc::ptr_eq(p, &self.path));
            if stale {
                let conn = Connection::open_with_flags(
                    &*self.path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
                )?;
                conn.execute_batch(PRAGMAS)?;
                rusqlite::vtab::array::load_module(&conn)?;
                *slot = Some((self.path.clone(), conn));
            }
            f(&slot.as_ref().expect("reader initialised").1)
        })
    }
}

fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: usize = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", i + 1)?;
        tx.commit()?;
    }
    Ok(())
}

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

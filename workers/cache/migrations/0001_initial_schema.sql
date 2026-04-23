-- Initial schema for the Odin cache metadata store.

CREATE TABLE caches (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    is_public  INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE blob_objects (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash   TEXT    NOT NULL,
    file_size   INTEGER NOT NULL,
    compression TEXT    NOT NULL,
    r2_key      TEXT    NOT NULL UNIQUE,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(file_hash, compression)
);

CREATE TABLE published_paths (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    cache_id         INTEGER NOT NULL REFERENCES caches(id),
    store_path_hash  TEXT    NOT NULL,
    store_path       TEXT    NOT NULL,
    nar_hash         TEXT    NOT NULL,
    nar_size         INTEGER NOT NULL,
    blob_object_id   INTEGER NOT NULL REFERENCES blob_objects(id),
    references_json  TEXT    NOT NULL DEFAULT '[]',
    deriver          TEXT,
    system           TEXT,
    signatures_json  TEXT    NOT NULL DEFAULT '[]',
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(cache_id, store_path_hash)
);

CREATE INDEX idx_published_paths_lookup
    ON published_paths(cache_id, store_path_hash);

CREATE TABLE upload_sessions (
    id               TEXT    PRIMARY KEY,
    cache_id         INTEGER NOT NULL REFERENCES caches(id),
    store_path_hash  TEXT    NOT NULL,
    store_path       TEXT    NOT NULL,
    nar_hash         TEXT    NOT NULL,
    nar_size         INTEGER NOT NULL,
    file_hash        TEXT    NOT NULL,
    file_size        INTEGER NOT NULL,
    compression      TEXT    NOT NULL,
    references_json  TEXT    NOT NULL DEFAULT '[]',
    deriver          TEXT,
    system           TEXT,
    status           TEXT    NOT NULL DEFAULT 'pending',
    r2_upload_key    TEXT,
    r2_upload_id     TEXT,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at       TEXT    NOT NULL
);

CREATE INDEX idx_upload_sessions_status
    ON upload_sessions(status, expires_at);

CREATE TABLE upload_parts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT    NOT NULL REFERENCES upload_sessions(id),
    part_number   INTEGER NOT NULL,
    etag          TEXT    NOT NULL,
    size          INTEGER NOT NULL,
    UNIQUE(session_id, part_number)
);

CREATE TABLE gc_marks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT    NOT NULL,
    target_id   TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    marked_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(target_type, target_id)
);

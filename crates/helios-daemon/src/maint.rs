//! SQLite upkeep, performed by the server on request: WAL checkpoints (so
//! the WAL does not grow without bound under constant reads), query
//! planner statistics, and rotated online backups.

use serde_json::{Value, json};

use crate::log;
use crate::state::{Daemon, add, now, set};

pub async fn checkpoint(d: &Daemon) -> anyhow::Result<()> {
    let r: Value = d.client.post("/v1/db/checkpoint", json!({})).await?;
    add(&d.metrics.db_checkpoints, 1);
    if r["busy"] == true {
        log::warning!("db: checkpoint could not complete while readers were active");
    }
    Ok(())
}

pub async fn optimize(d: &Daemon) -> anyhow::Result<()> {
    let _: Value = d.client.post("/v1/db/optimize", json!({})).await?;
    Ok(())
}

pub async fn backup(d: &Daemon, keep: usize) -> anyhow::Result<()> {
    let r: Value = d.client.post("/v1/db/backup", json!({ "keep": keep })).await?;
    add(&d.metrics.db_backups, 1);
    set(&d.metrics.db_last_backup, now());
    log::info!("db: backed up to {} ({} bytes)", r["path"].as_str().unwrap_or("?"), r["bytes"]);
    Ok(())
}

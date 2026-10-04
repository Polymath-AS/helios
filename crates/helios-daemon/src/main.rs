//! helios-daemon: maintenance for a helios-server, driven over its admin
//! socket. It never writes the database itself; it decides what to do and
//! the server does it, so the server's in-memory state stays consistent.

mod autogc;
mod client;
mod io;
mod maint;
mod metrics;
mod scrub;
mod state;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use clap::Parser;
use tracing::Instrument;

use crate::state::{Daemon, add};

/// Maintenance daemon for helios-server.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// helios-server's maintenance socket (its --admin-socket).
    #[arg(long, env = "HELIOS_ADMIN_SOCKET")]
    socket: PathBuf,

    /// helios-server's data directory, read for scrubbing and disk space.
    #[arg(long, env = "HELIOS_DATA_DIR", default_value = "/var/lib/helios")]
    data_dir: PathBuf,

    /// Directory for the daemon's own state, such as where an unfinished
    /// scrub resumes (default: systemd's $STATE_DIRECTORY; without either,
    /// a restart begins the scrub again).
    #[arg(long, env = "HELIOS_DAEMON_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Keep stored NARs under this size (e.g. 500G); 0 disables the quota.
    #[arg(long, env = "HELIOS_QUOTA", default_value = "0", value_parser = parse_size)]
    quota: u64,

    /// Start evicting above this fraction of the quota.
    #[arg(long, env = "HELIOS_QUOTA_HIGH", default_value_t = 0.9)]
    quota_high: f64,

    /// Evict down to this fraction of the quota.
    #[arg(long, env = "HELIOS_QUOTA_LOW", default_value_t = 0.8)]
    quota_low: f64,

    /// Also evict while the data filesystem has less free space than this (e.g. 20G); 0 disables.
    #[arg(long, env = "HELIOS_MIN_FREE", default_value = "0", value_parser = parse_size)]
    min_free: u64,

    /// Time between auto-GC checks.
    #[arg(long, env = "HELIOS_GC_INTERVAL", default_value = "5m", value_parser = parse_duration)]
    gc_interval: Duration,

    /// Time between full integrity scrubs; 0 disables.
    #[arg(long, env = "HELIOS_SCRUB_INTERVAL", default_value = "7d", value_parser = parse_duration)]
    scrub_interval: Duration,

    /// Scrub read rate limit (e.g. 64M per second); 0 is unlimited.
    #[arg(long, env = "HELIOS_SCRUB_RATE", default_value = "64M", value_parser = parse_size)]
    scrub_rate: u64,

    /// Time between WAL checkpoints.
    #[arg(long, env = "HELIOS_CHECKPOINT_INTERVAL", default_value = "15m", value_parser = parse_duration)]
    checkpoint_interval: Duration,

    /// Time between query planner statistics updates (PRAGMA optimize).
    #[arg(long, env = "HELIOS_OPTIMIZE_INTERVAL", default_value = "1d", value_parser = parse_duration)]
    optimize_interval: Duration,

    /// Time between database backups; 0 disables.
    #[arg(long, env = "HELIOS_BACKUP_INTERVAL", default_value = "1d", value_parser = parse_duration)]
    backup_interval: Duration,

    /// Database backups to keep.
    #[arg(long, env = "HELIOS_BACKUP_KEEP", default_value_t = 7)]
    backup_keep: usize,

    /// Serve Prometheus metrics on this address.
    #[arg(long, env = "HELIOS_METRICS_LISTEN")]
    metrics_listen: Option<SocketAddr>,
}

/// Bytes with an optional binary suffix: 1024, 64M, 500G, 2T.
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => {
            let mult = match c.to_ascii_uppercase() {
                'K' => 1u64 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => return Err(format!("unknown size suffix in {s}")),
            };
            (&s[..i], mult)
        }
        _ => (s, 1),
    };
    let n: f64 = num.parse().map_err(|_| format!("invalid size {s}"))?;
    if n < 0.0 {
        return Err(format!("invalid size {s}"));
    }
    Ok((n * mult as f64) as u64)
}

/// A duration with a unit: 30s, 5m, 24h, 7d. A bare 0 disables.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let split = s.find(|c: char| c.is_ascii_alphabetic()).ok_or_else(|| format!("{s}: missing unit (s, m, h or d)"))?;
    let n: u64 = s[..split].parse().map_err(|_| format!("invalid duration {s}"))?;
    let unit = match &s[split..] {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => return Err(format!("unknown duration unit {other}")),
    };
    Ok(Duration::from_secs(n * unit))
}

/// Runs `task` every `every`, logging and counting failures instead of
/// exiting: the server may be restarting.
async fn periodic<F, Fut>(name: &'static str, every: Duration, delay_first: bool, errors: &AtomicU64, mut task: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    if delay_first {
        tokio::time::sleep(every).await;
    }
    let mut interval = tokio::time::interval(every);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if let Err(e) = task().instrument(tracing::info_span!("task", name)).await {
            add(errors, 1);
            tracing::error!(task = name, error = format!("{e:#}"), "task failed");
        }
    }
}

async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
    let term = std::pin::pin!(term.recv());
    let int = std::pin::pin!(tokio::signal::ctrl_c());
    futures_util::future::select(term, int).await;
}

fn main() -> std::process::ExitCode {
    helios_log::init(helios_log::Style::Service);
    // Fatal errors go through the logger too, so JSON and journald get them.
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    anyhow::ensure!(
        (0.0..=1.0).contains(&args.quota_low) && args.quota_low < args.quota_high && args.quota_high <= 1.0,
        "watermarks must satisfy 0 <= low < high <= 1"
    );
    let policy = autogc::Policy { quota: args.quota, high: args.quota_high, low: args.quota_low, min_free: args.min_free };
    // systemd's StateDirectory= may name several directories; the first is ours.
    let state_dir = args.state_dir.clone().or_else(|| {
        let dirs = std::env::var_os("STATE_DIRECTORY")?;
        std::env::split_paths(&dirs).next().filter(|p| !p.as_os_str().is_empty())
    });
    if let Some(dir) = &state_dir {
        std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("creating {}: {e}", dir.display()))?;
    }
    let d = Arc::new(Daemon {
        client: client::Client::new(args.socket.clone()),
        data_dir: args.data_dir.clone(),
        state_dir,
        metrics: Default::default(),
        stopping: Default::default(),
    });

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let stopping = d.stopping.clone();
    let result = runtime.block_on(async move {
        let mut tasks = Vec::new();
        if policy.quota > 0 || policy.min_free > 0 {
            let d = d.clone();
            tasks.push(tokio::spawn(async move {
                periodic("auto-gc", args.gc_interval.max(Duration::from_secs(1)), false, &d.metrics.errors_gc, || autogc::run(&d, &policy)).await
            }));
        }
        if !args.scrub_interval.is_zero() {
            let d = d.clone();
            let rate = args.scrub_rate;
            // Wait a full interval first so restarts do not re-read
            // everything, unless a pass was cut short.
            let delay = !scrub::resuming(&d);
            tasks.push(tokio::spawn(
                async move { periodic("scrub", args.scrub_interval, delay, &d.metrics.errors_scrub, || scrub::run(&d, rate)).await },
            ));
        }
        {
            let d = d.clone();
            tasks.push(tokio::spawn(async move {
                periodic("checkpoint", args.checkpoint_interval.max(Duration::from_secs(1)), true, &d.metrics.errors_db, || maint::checkpoint(&d))
                    .await
            }));
        }
        {
            let d = d.clone();
            tasks.push(tokio::spawn(async move {
                periodic("optimize", args.optimize_interval.max(Duration::from_secs(1)), true, &d.metrics.errors_db, || maint::optimize(&d)).await
            }));
        }
        if !args.backup_interval.is_zero() {
            let d = d.clone();
            let keep = args.backup_keep;
            tasks.push(tokio::spawn(async move {
                periodic("backup", args.backup_interval, false, &d.metrics.errors_db, || maint::backup(&d, keep)).await
            }));
        }
        if let Some(addr) = args.metrics_listen {
            let d = d.clone();
            tasks.push(tokio::spawn(async move {
                if let Err(e) = metrics::serve(d, addr).await {
                    tracing::error!(error = format!("{e:#}"), "metrics server failed");
                }
            }));
        }
        tracing::info!(tasks = tasks.len(), "helios-daemon started");
        shutdown().await;
        tracing::info!("shutting down");
        Ok(())
    });
    // Blocking work (a scrub read) sees this and stops; do not wait long
    // for anything that does not.
    stopping.store(true, std::sync::atomic::Ordering::Relaxed);
    runtime.shutdown_timeout(Duration::from_secs(5));
    result
}

#[cfg(test)]
mod tests {
    use super::{parse_duration, parse_size};
    use std::time::Duration;

    #[test]
    fn durations_and_sizes() {
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("7d"), Ok(Duration::from_secs(7 * 86400)));
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
        assert!(parse_duration("5").is_err());
        assert!(parse_duration("5w").is_err());
        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("1024"), Ok(1024));
        assert_eq!(parse_size("64M"), Ok(64 << 20));
        assert_eq!(parse_size("1.5g"), Ok(3 << 29));
        assert!(parse_size("5X").is_err());
        assert!(parse_size("-1").is_err());
    }
}

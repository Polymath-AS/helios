mod api;
mod config;
mod nix;
mod push;
mod substituter;
mod transport;
mod watch;

use anyhow::Context;
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

/// Helios Nix binary cache CLI.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Server name from `helios login` (default: the last one logged in).
    #[arg(long, global = true, env = "HELIOS_SERVER")]
    server: Option<String>,

    /// Server URL, instead of a saved login (for services and CI).
    #[arg(long, global = true, env = "HELIOS_URL")]
    url: Option<String>,

    /// File holding the token for --url (or set HELIOS_TOKEN).
    #[arg(long, global = true, env = "HELIOS_TOKEN_FILE")]
    token_file: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Save server credentials (a push token, or the admin secret for admin commands).
    Login { name: String, url: String, token: String },
    /// Push store paths (or installables like `.#foo`) to a cache.
    Push {
        cache: String,
        #[arg(required = true)]
        installables: Vec<String>,
        /// Push the full closure.
        #[arg(long, short = 'r')]
        closure: bool,
        /// Parallel uploads.
        #[arg(long, short = 'j', default_value_t = 8)]
        jobs: usize,
        /// zstd level, 1-19, or 0 to upload uncompressed. Default: the
        /// server's (3 unless configured).
        #[arg(long, value_parser = clap::value_parser!(i32).range(0..=19))]
        level: Option<i32>,
        /// zstd window for long-distance matching, as a power of two
        /// (10-27), or 0 for the level's own. Default: the server's (27).
        #[arg(long, value_parser = parse_window_log)]
        window_log: Option<i32>,
        /// Pin the given paths afterwards, so auto-GC keeps them and their
        /// closures.
        #[arg(long)]
        pin: bool,
        /// Upload NARs in chunks of this many MiB, for proxies that cap
        /// request bodies (Cloudflare, Cloud Run). 0 sends each NAR in one
        /// request; so does a NAR that fits in one chunk.
        #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u64).range(0..=64))]
        chunk_size: u64,
    },
    /// Push paths as they are built: drain a spool filled by `queue-paths`.
    WatchStore {
        cache: String,
        /// Spool directory shared with the post-build hook.
        #[arg(long, default_value = "/var/lib/helios-watch-store/spool")]
        spool: std::path::PathBuf,
        /// Parallel uploads.
        #[arg(long, short = 'j', default_value_t = 8)]
        jobs: usize,
        /// zstd level, 1-19, or 0 to upload uncompressed. Default: the
        /// server's (3 unless configured).
        #[arg(long, value_parser = clap::value_parser!(i32).range(0..=19))]
        level: Option<i32>,
        /// zstd window for long-distance matching, as a power of two
        /// (10-27), or 0 for the level's own. Default: the server's (27).
        #[arg(long, value_parser = parse_window_log)]
        window_log: Option<i32>,
        /// Upload NARs in chunks of this many MiB, for proxies that cap
        /// request bodies (Cloudflare, Cloud Run). 0 sends each NAR in one
        /// request; so does a NAR that fits in one chunk.
        #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u64).range(0..=64))]
        chunk_size: u64,
    },
    /// Protect store paths, with their closures in the cache, from auto-GC.
    Pin {
        cache: String,
        /// Store paths, or installables to resolve with Nix.
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Remove pins.
    Unpin {
        cache: String,
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// List a cache's pins.
    Pins { cache: String },
    /// Configure Nix to substitute from a cache: its URL, signing key and,
    /// for a private cache, this login's token in netrc.
    Use {
        cache: String,
        /// Print system-wide settings (nix.conf, NixOS, netrc) instead of
        /// writing the user's nix.conf.
        #[arg(long)]
        print: bool,
    },
    /// Spool store paths for `watch-store` (Nix post-build-hook; reads $OUT_PATHS).
    QueuePaths {
        #[arg(long, default_value = "/var/lib/helios-watch-store/spool")]
        spool: std::path::PathBuf,
        /// Paths to queue; defaults to $OUT_PATHS.
        paths: Vec<String>,
    },
    /// Manage caches (admin).
    #[command(subcommand)]
    Cache(CacheCmd),
    /// Manage API tokens (admin).
    #[command(subcommand)]
    Token(TokenCmd),
}

#[derive(Subcommand)]
enum CacheCmd {
    Create {
        name: String,
        /// Require a pull token to read.
        #[arg(long)]
        private: bool,
    },
    List,
}

#[derive(Subcommand)]
enum TokenCmd {
    Create {
        subject: String,
        /// Comma-separated cache names, or "*" for all of them.
        #[arg(long)]
        caches: String,
        /// Comma-separated: pull, push. Read-only unless push is asked for;
        /// push does not imply pull, so a builder can upload without reading
        /// private caches.
        #[arg(long, default_value = "pull")]
        perms: String,
        /// Lifetime in days (1-365).
        #[arg(long, default_value_t = 90)]
        expires: i64,
    },
    List,
    Revoke {
        jti: String,
        reason: String,
    },
}

fn split(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    if let Command::Login { name, url, token } = &cli.command {
        config::login(name, url, token)?;
        tracing::info!("logged in to '{name}' at {url}");
        return Ok(());
    }
    // Runs inside the nix-daemon's post-build hook: no server needed, and it
    // must return quickly.
    if let Command::QueuePaths { spool, paths } = &cli.command {
        let joined = if paths.is_empty() { std::env::var("OUT_PATHS").unwrap_or_default() } else { paths.join(" ") };
        watch::queue(spool, &joined)?;
        return Ok(());
    }
    let server = match &cli.url {
        Some(url) => {
            let token = match &cli.token_file {
                Some(file) => std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
                None => std::env::var("HELIOS_TOKEN").context("--url needs --token-file or HELIOS_TOKEN")?,
            };
            config::Server { server: url.trim_end_matches('/').to_owned(), token: token.trim().to_owned() }
        }
        None => config::server(cli.server.as_deref())?,
    };
    let client = api::Client::new(&server)?;
    match cli.command {
        Command::Login { .. } | Command::QueuePaths { .. } => unreachable!(),
        Command::Push { cache, installables, closure, jobs, level, window_log, chunk_size, pin } => {
            let (level, window_log) = compression(&client, &cache, level, window_log).await;
            let opts = push::Options { jobs, level, window_log, closure, chunk_size: (chunk_size << 20) as usize };
            push::push(&client, &cache, &installables, opts).await?;
            if pin {
                pin_paths(&client, &cache, &installables).await?;
            }
        }
        Command::Pin { cache, paths } => pin_paths(&client, &cache, &paths).await?,
        Command::Unpin { cache, paths } => {
            for path in store_paths(&paths).await? {
                client.unpin(&cache, &path).await?;
                tracing::info!("unpinned {path}");
            }
        }
        Command::Pins { cache } => print(&client.pins(&cache).await?),
        Command::Use { cache, print } => {
            let plan = substituter::plan(&client, &server, &cache).await?;
            if print { plan.print() } else { plan.apply()? }
        }
        Command::WatchStore { cache, spool, jobs, level, window_log, chunk_size } => {
            let (level, window_log) = compression(&client, &cache, level, window_log).await;
            let opts = push::Options { jobs, level, window_log, closure: true, chunk_size: (chunk_size << 20) as usize };
            watch::watch(&client, &cache, &spool, opts).await?;
        }
        Command::Cache(CacheCmd::Create { name, private }) => {
            print(&client.admin_post("/admin/caches", json!({ "name": name, "public": !private })).await?);
        }
        Command::Cache(CacheCmd::List) => print(&client.admin_get("/admin/caches").await?),
        Command::Token(TokenCmd::Create { subject, caches, perms, expires }) => {
            let v = client
                .admin_post(
                    "/admin/tokens",
                    json!({ "subject": subject, "caches": split(&caches), "perms": split(&perms), "expiresInDays": expires }),
                )
                .await?;
            tracing::warn!("store this token now; it is not shown again");
            print(&v);
        }
        Command::Token(TokenCmd::List) => print(&client.admin_get("/admin/tokens").await?),
        Command::Token(TokenCmd::Revoke { jti, reason }) => {
            print(&client.admin_post(&format!("/admin/tokens/{jti}/revoke"), json!({ "reason": reason })).await?);
        }
    }
    Ok(())
}

fn main() {
    // Nix environments point at their CA bundle with NIX_SSL_CERT_FILE.
    if std::env::var_os("SSL_CERT_FILE").is_none()
        && let Some(file) = std::env::var_os("NIX_SSL_CERT_FILE")
    {
        // SAFETY: single-threaded; the runtime has not started yet.
        unsafe { std::env::set_var("SSL_CERT_FILE", file) };
    }
    helios_log::init(helios_log::Style::Cli);
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("starting the tokio runtime");
    if let Err(e) = runtime.block_on(run(cli)) {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

/// Store paths as given, or resolved by Nix when any is an installable.
async fn store_paths(args: &[String]) -> anyhow::Result<Vec<String>> {
    if args.iter().all(|a| a.starts_with("/nix/store/")) {
        return Ok(args.to_vec());
    }
    Ok(nix::path_infos(args, false).await?.into_iter().map(|i| i.path).collect())
}

async fn pin_paths(client: &api::Client, cache: &str, args: &[String]) -> anyhow::Result<()> {
    let paths = store_paths(args).await?;
    let r = client.pin(cache, &paths).await?;
    tracing::info!("pinned {} paths in '{cache}' ({} already were)", r["pinned"], r["alreadyPinned"]);
    Ok(())
}

fn parse_window_log(s: &str) -> Result<i32, String> {
    match s.parse::<i32>() {
        Ok(n) if n == 0 || (10..=27).contains(&n) => Ok(n),
        _ => Err("expected 0, or 10-27 (27, a 128 MiB window, is the largest a stock Nix decoder accepts)".into()),
    }
}

/// The level and window to compress with: what was asked for, else the
/// server's defaults for the cache, else level 3 with a 2^27 window.
async fn compression(client: &api::Client, cache: &str, level: Option<i32>, window_log: Option<i32>) -> (i32, i32) {
    let server = if level.is_none() || window_log.is_none() {
        match client.cache_info(cache).await {
            Ok(info) => info.compression,
            Err(e) => {
                tracing::debug!("no compression defaults from the server: {e:#}");
                None
            }
        }
    } else {
        None
    };
    let level = level.or(server.map(|c| c.level)).unwrap_or(3);
    // An uncompressed upload has no window.
    let window_log = if level == 0 { 0 } else { window_log.or(server.map(|c| c.window_log)).unwrap_or(27) };
    (level, window_log)
}

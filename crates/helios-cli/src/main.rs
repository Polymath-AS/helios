mod api;
mod config;
mod transport;
mod nix;
mod push;
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
        /// zstd compression level (1-19).
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(i32).range(1..=19))]
        level: i32,
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
        /// zstd compression level (1-19).
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(i32).range(1..=19))]
        level: i32,
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
        /// Comma-separated cache names, or "*".
        #[arg(long, default_value = "*")]
        caches: String,
        /// Comma-separated: push, pull.
        #[arg(long, default_value = "push")]
        perms: String,
        /// Lifetime in days (1-365).
        #[arg(long, default_value_t = 90)]
        expires: i64,
    },
    List,
    Revoke { jti: String, reason: String },
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
        println!("logged in to '{name}' at {url}");
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
            config::Server { server: url.clone(), token: token.trim().to_owned() }
        }
        None => config::server(cli.server.as_deref())?,
    };
    let client = api::Client::new(&server)?;
    match cli.command {
        Command::Login { .. } | Command::QueuePaths { .. } => unreachable!(),
        Command::Push { cache, installables, closure, jobs, level } => {
            push::push(&client, &cache, &installables, push::Options { jobs, level, closure }).await?;
        }
        Command::WatchStore { cache, spool, jobs, level } => {
            watch::watch(&client, &cache, &spool, push::Options { jobs, level, closure: true }).await?;
        }
        Command::Cache(CacheCmd::Create { name, private }) => {
            print(&client.admin_post("/admin/caches", json!({ "name": name, "public": !private })).await?);
        }
        Command::Cache(CacheCmd::List) => print(&client.admin_get("/admin/caches").await?),
        Command::Token(TokenCmd::Create { subject, caches, perms, expires }) => {
            let v = client
                .admin_post("/admin/tokens", json!({ "subject": subject, "caches": split(&caches), "perms": split(&perms), "expiresInDays": expires }))
                .await?;
            eprintln!("store this token now; it is not shown again");
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
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("starting the tokio runtime");
    if let Err(e) = runtime.block_on(run(cli)) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

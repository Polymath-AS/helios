use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

/// Helios Nix binary cache server.
#[derive(Parser, Debug, Clone)]
#[command(version)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Address to listen on.
    #[arg(long, env = "HELIOS_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// Directory for the database and NAR files.
    #[arg(long, env = "HELIOS_DATA_DIR", default_value = "/var/lib/helios")]
    pub data_dir: PathBuf,

    /// Nix secret key file (`nix key generate-secret`) used to sign narinfo.
    #[arg(long, env = "HELIOS_SIGNING_KEY_FILE")]
    pub signing_key_file: Option<PathBuf>,

    /// File holding the HMAC secret for API tokens (JWT HS256).
    #[arg(long, env = "HELIOS_JWT_SECRET_FILE")]
    pub jwt_secret_file: Option<PathBuf>,

    /// File holding the bearer secret for the admin API.
    #[arg(long, env = "HELIOS_ADMIN_SECRET_FILE")]
    pub admin_secret_file: Option<PathBuf>,

    /// Serve NARs by delegating to a reverse proxy (nginx X-Accel-Redirect)
    /// under this internal location, e.g. `/_nar`. The location must alias
    /// `<data-dir>/nar/`. Lets the proxy use sendfile for zero-copy downloads.
    #[arg(long, env = "HELIOS_ACCEL_REDIRECT")]
    pub accel_redirect: Option<String>,

    /// Trust X-Forwarded-For for audit log client IPs.
    #[arg(long, env = "HELIOS_TRUST_PROXY", default_value_t = false)]
    pub trust_proxy: bool,

    /// Rendered narinfo bodies kept in memory.
    #[arg(long, env = "HELIOS_NARINFO_CACHE_ENTRIES", default_value_t = 262_144)]
    pub narinfo_cache_entries: usize,

    /// Largest accepted compressed NAR upload, in bytes.
    #[arg(long, env = "HELIOS_MAX_UPLOAD_BYTES", default_value_t = 64 << 30)]
    pub max_upload_bytes: u64,

    /// Seconds an uploaded NAR is kept before it must be published. Protects
    /// pushes in flight from GC and eviction.
    #[arg(long, env = "HELIOS_UPLOAD_GRACE_SECONDS", default_value_t = 3600)]
    pub upload_grace_seconds: u64,

    /// Hours between garbage collection runs.
    #[arg(long, env = "HELIOS_GC_INTERVAL_HOURS", default_value_t = 6)]
    pub gc_interval_hours: u64,

    /// Days to keep audit log entries.
    #[arg(long, env = "HELIOS_AUDIT_RETENTION_DAYS", default_value_t = 30)]
    pub audit_retention_days: u64,

    /// Unix socket for the maintenance API used by helios-daemon. Access is
    /// controlled by the socket's permissions (created 0660).
    #[arg(long, env = "HELIOS_ADMIN_SOCKET")]
    pub admin_socket: Option<PathBuf>,

    /// Caches to create at startup, comma-separated: `name` for a public
    /// cache, `name:private` for a private one. A listed cache that exists
    /// takes the listed visibility; unlisted caches are left alone.
    #[arg(long, env = "HELIOS_CACHES", value_delimiter = ',', value_parser = parse_declared_cache)]
    pub caches: Vec<DeclaredCache>,

    /// Print the public key for `trusted-public-keys` and exit.
    #[arg(long)]
    pub print_public_key: bool,
}

#[derive(Debug, Clone)]
pub struct DeclaredCache {
    pub name: String,
    pub public: bool,
}

fn parse_declared_cache(s: &str) -> Result<DeclaredCache, String> {
    let (name, public) = match s.trim().split_once(':') {
        None => (s.trim(), true),
        Some((name, "public")) => (name, true),
        Some((name, "private")) => (name, false),
        Some((_, other)) => return Err(format!("unknown visibility {other:?}; expected public or private")),
    };
    if !crate::admin::valid_cache_name(name) {
        return Err(format!("invalid cache name {name:?}: 1-64 of a-z, 0-9 and -, not starting or ending with -"));
    }
    Ok(DeclaredCache { name: name.to_owned(), public })
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Create whichever of signing-key, jwt-secret and admin-secret are
    /// missing in DIR (mode 0600), and write public-key. Safe to rerun.
    GenerateSecrets {
        #[arg(long, env = "HELIOS_SECRETS_DIR")]
        dir: PathBuf,
        /// Name for a new signing key, as it appears in `trusted-public-keys`.
        #[arg(long, env = "HELIOS_KEY_NAME", default_value = "helios-1")]
        key_name: String,
    },
}

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub jwt_secret: Option<Vec<u8>>,
    pub admin_secret: Option<Vec<u8>>,
    pub accel_redirect: Option<String>,
    pub trust_proxy: bool,
    pub narinfo_cache_entries: usize,
    pub max_upload_bytes: u64,
    pub upload_grace: Duration,
    pub gc_interval: Duration,
    pub audit_retention: Duration,
}

pub fn read_secret(path: &Option<PathBuf>) -> anyhow::Result<Option<Vec<u8>>> {
    let Some(path) = path else { return Ok(None) };
    let raw = std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let trimmed = raw.trim_ascii().to_vec();
    anyhow::ensure!(trimmed.len() >= 16, "{} must hold at least 16 bytes", path.display());
    Ok(Some(trimmed))
}

impl Config {
    pub fn from_args(args: &Args) -> anyhow::Result<Self> {
        Ok(Self {
            data_dir: args.data_dir.clone(),
            jwt_secret: read_secret(&args.jwt_secret_file)?,
            admin_secret: read_secret(&args.admin_secret_file)?,
            accel_redirect: args.accel_redirect.as_ref().map(|s| s.trim_end_matches('/').to_owned()),
            trust_proxy: args.trust_proxy,
            narinfo_cache_entries: args.narinfo_cache_entries.max(16),
            max_upload_bytes: args.max_upload_bytes,
            upload_grace: Duration::from_secs(args.upload_grace_seconds),
            gc_interval: Duration::from_secs(args.gc_interval_hours.max(1) * 3600),
            audit_retention: Duration::from_secs(args.audit_retention_days * 86400),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_declared_cache;

    #[test]
    fn declared_caches() {
        let c = parse_declared_cache("main").unwrap();
        assert_eq!((c.name.as_str(), c.public), ("main", true));
        assert!(!parse_declared_cache("team:private").unwrap().public);
        assert!(parse_declared_cache("team:public").unwrap().public);
        assert!(parse_declared_cache("team:secret").is_err());
        assert!(parse_declared_cache("Bad_Name").is_err());
        assert!(parse_declared_cache("").is_err());
    }
}

mod admin;
mod audit;
mod auth;
mod config;
mod db;
mod error;
mod gc;
mod internal;
mod log;
mod push;
mod read;
mod state;
mod stats;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use clap::Parser;
use serde_json::json;

use crate::config::{Args, Config};
use crate::state::{AppState, Shared};

fn load_signer(args: &Args) -> anyhow::Result<Option<helios_core::Signer>> {
    let Some(path) = &args.signing_key_file else { return Ok(None) };
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let signer = helios_core::Signer::new(&text).ok_or_else(|| anyhow::anyhow!("{} is not a Nix secret key", path.display()))?;
    Ok(Some(signer))
}

pub fn router(st: Shared) -> Router {
    let api = Router::new()
        .route("/caches/{cache}/missing", post(push::missing))
        .route("/caches/{cache}/nars/known", post(push::known))
        .route("/caches/{cache}/nar", put(push::upload).layer(DefaultBodyLimit::disable()))
        .route("/caches/{cache}/paths", post(push::publish))
        .route("/admin/caches", post(admin::create_cache).get(admin::list_caches))
        .route("/admin/tokens", post(admin::create_token).get(admin::list_tokens))
        .route("/admin/tokens/{jti}/revoke", post(admin::revoke_token))
        .layer(DefaultBodyLimit::max(64 << 20));

    Router::new()
        .route("/", get(|| async { axum::Json(json!({ "service": "helios", "status": "ok" })) }))
        .route("/healthz", get(healthz))
        .nest("/_api/v2", api)
        .fallback(read::handle)
        .with_state(st)
}

async fn healthz(State(st): State<Shared>) -> (StatusCode, axum::Json<serde_json::Value>) {
    let db = st.db.clone();
    let ok = tokio::task::spawn_blocking(move || db.read(|c| c.query_row("SELECT 1", [], |_| Ok(()))).is_ok())
        .await
        .unwrap_or(false);
    let status = if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, axum::Json(json!({ "ok": ok, "service": "helios" })))
}

pub async fn build_state(args: &Args) -> anyhow::Result<Shared> {
    let cfg = Config::from_args(args)?;
    std::fs::create_dir_all(cfg.data_dir.join("nar"))?;
    std::fs::create_dir_all(cfg.data_dir.join("tmp"))?;
    let db = db::Db::open(&cfg.data_dir.join("helios.db"))?;
    let signer = load_signer(args)?;
    if signer.is_none() {
        crate::log::warning!("no signing key configured; narinfo will be unsigned");
    }
    let (audit_tx, audit_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(audit::run(db.clone(), audit_rx));
    let st = Arc::new(AppState::load(cfg, db, signer, audit_tx)?);
    tokio::spawn(gc::run_forever(st.clone()));
    tokio::spawn(gc::run_access_flush(st.clone()));
    Ok(st)
}

fn main() -> anyhow::Result<()> {
    log::init();
    let args = Args::parse();

    if let Some(config::Command::GenerateSecrets { dir, key_name }) = &args.command {
        return generate_secrets(dir, key_name);
    }
    if args.print_public_key {
        let signer = load_signer(&args)?.ok_or_else(|| anyhow::anyhow!("--signing-key-file is required"))?;
        println!("{}", signer.public_key());
        return Ok(());
    }

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(async move {
        let st = build_state(&args).await?;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = stop_tx.send(true);
        });
        let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
            let _ = rx.wait_for(|stop| *stop).await;
        };

        let admin = match &args.admin_socket {
            Some(path) => {
                let _ = std::fs::remove_file(path);
                let listener = tokio::net::UnixListener::bind(path)?;
                // Group access only: the socket directory decides who that is.
                std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o660))?;
                crate::log::info!("maintenance API on {}", path.display());
                let serve = axum::serve(listener, internal::router(st.clone())).with_graceful_shutdown(stopped(stop_rx.clone()));
                Some(tokio::spawn(async move { serve.await }))
            }
            None => None,
        };

        let listener = tokio::net::TcpListener::bind(args.listen).await?;
        crate::log::info!("listening on {}", args.listen);
        axum::serve(listener, router(st.clone()).into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(stopped(stop_rx))
            .await?;
        if let Some(admin) = admin {
            admin.await??;
        }
        // Keep the hits recorded since the last flush.
        tokio::task::spawn_blocking(move || gc::flush_access(&st)).await??;
        Ok(())
    })
}

/// SIGTERM (systemd stop) or SIGINT: finish in-flight requests, then exit.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
    let term = std::pin::pin!(term.recv());
    let int = std::pin::pin!(tokio::signal::ctrl_c());
    futures_util::future::select(term, int).await;
    crate::log::info!("shutting down");
}

/// Writes `contents` to `path` only if it does not exist, readable by the
/// owner alone. Returns whether it was created.
fn create_secret(path: &std::path::Path, contents: impl FnOnce() -> anyhow::Result<String>) -> anyhow::Result<bool> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if path.exists() {
        return Ok(false);
    }
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(contents()?.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(true)
}

fn random_hex() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    helios_core::random_bytes(&mut bytes);
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn generate_secrets(dir: &std::path::Path, key_name: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let signing = dir.join("signing-key");
    for (name, created) in [
        ("signing-key", create_secret(&signing, || Ok(helios_core::Signer::generate(key_name)?))?),
        ("jwt-secret", create_secret(&dir.join("jwt-secret"), random_hex)?),
        ("admin-secret", create_secret(&dir.join("admin-secret"), random_hex)?),
    ] {
        if created {
            log::info!("created {}", dir.join(name).display());
        }
    }
    let key = std::fs::read_to_string(&signing)?;
    let public = helios_core::Signer::new(&key).ok_or_else(|| anyhow::anyhow!("{} is not a Nix secret key", signing.display()))?.public_key();
    std::fs::write(dir.join("public-key"), format!("{public}\n"))?;
    println!("{public}");
    Ok(())
}

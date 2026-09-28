mod admin;
mod audit;
mod auth;
mod config;
mod db;
mod error;
mod gc;
mod log;
mod push;
mod read;
mod state;

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
    Ok(st)
}

fn main() -> anyhow::Result<()> {
    log::init();
    let args = Args::parse();

    if args.print_public_key {
        let signer = load_signer(&args)?.ok_or_else(|| anyhow::anyhow!("--signing-key-file is required"))?;
        println!("{}", signer.public_key());
        return Ok(());
    }

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(async move {
        let st = build_state(&args).await?;
        let listener = tokio::net::TcpListener::bind(args.listen).await?;
        crate::log::info!("listening on {}", args.listen);
        axum::serve(listener, router(st).into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown_signal())
            .await?;
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

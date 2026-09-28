//! `~/.config/helios/config.json`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Server {
    pub server: String,
    pub token: String,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_server: Option<String>,
    #[serde(default)]
    pub servers: BTreeMap<String, Server>,
}

fn path() -> anyhow::Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(base.join("helios").join("config.json"))
}

pub fn load() -> anyhow::Result<Config> {
    match std::fs::read(path()?) {
        Ok(raw) => Ok(serde_json::from_slice(&raw).context("parsing helios config")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e.into()),
    }
}

pub fn login(name: &str, server: &str, token: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut cfg = load()?;
    cfg.servers.insert(name.into(), Server { server: server.trim_end_matches('/').into(), token: token.into() });
    cfg.default_server = Some(name.into());
    let path = path()?;
    std::fs::create_dir_all(path.parent().expect("config path has a parent"))?;
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)?;
    file.write_all(&serde_json::to_vec_pretty(&cfg)?)?;
    file.write_all(b"\n")?;
    Ok(())
}

pub fn server(name: Option<&str>) -> anyhow::Result<Server> {
    let cfg = load()?;
    let Some(key) = name.map(str::to_owned).or(cfg.default_server) else {
        bail!("no server configured; run: helios login <name> <url> <token>");
    };
    cfg.servers.get(&key).cloned().with_context(|| format!("server '{key}' not found; run: helios login {key} <url> <token>"))
}

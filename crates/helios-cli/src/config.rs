//! `~/.config/helios/config.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    let mut cfg = load()?;
    cfg.servers.insert(name.into(), Server { server: server.trim_end_matches('/').into(), token: token.into() });
    cfg.default_server = Some(name.into());
    let path = path()?;
    std::fs::create_dir_all(path.parent().expect("config path has a parent"))?;
    let mut body = serde_json::to_vec_pretty(&cfg)?;
    body.push(b'\n');
    write_secret(&path, &body)
}

/// Replaces `path` with `contents`, readable by the owner only: a fresh
/// 0600 file in the same directory, synced and renamed over the old one, so
/// a crash leaves the old or the new file and never a torn or
/// world-readable one. A symlink is followed, so the file it names is
/// replaced.
pub fn write_secret(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let dir = path.parent().with_context(|| format!("{} has no directory", path.display()))?;
    let name = path.file_name().with_context(|| format!("{} has no file name", path.display()))?.to_string_lossy();
    let tmp = dir.join(format!(".{name}.{}.tmp", helios_core::uuid_v4()));
    let written = (|| {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        // The mode above is subject to the umask; this is not.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.with_context(|| format!("writing {}", path.display()))
}

pub fn server(name: Option<&str>) -> anyhow::Result<Server> {
    let cfg = load()?;
    let Some(key) = name.map(str::to_owned).or(cfg.default_server) else {
        bail!("no server configured; run: helios login <name> <url> <token>");
    };
    cfg.servers.get(&key).cloned().with_context(|| format!("server '{key}' not found; run: helios login {key} <url> <token>"))
}

#[cfg(test)]
mod tests {
    use super::write_secret;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn secrets_replace_files_privately() {
        let dir = std::env::temp_dir().join(format!("helios-config-{}", helios_core::uuid_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("netrc");
        std::fs::write(&file, "old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        write_secret(&link, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "new");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2, "no temporary files left");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

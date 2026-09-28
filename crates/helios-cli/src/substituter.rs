//! `helios use <cache>`: configure Nix to substitute from a cache.
//!
//! The substituter URL is the one given to `helios login`, never an address
//! the server reports about itself: behind a proxy the server does not know
//! the address clients reach it at (compare zhaofengli/attic#325).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::api::Client;
use crate::config::Server;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheInfo {
    pub public: bool,
    pub public_key: Option<String>,
}

pub struct Plan {
    url: String,
    public_key: Option<String>,
    /// `(host, token)` for private caches, which Nix reads from netrc.
    netrc: Option<(String, String)>,
}

pub async fn plan(client: &Client, server: &Server, cache: &str) -> anyhow::Result<Plan> {
    let info = client.cache_info(cache).await?;
    let netrc = (!info.public).then(|| Ok::<_, anyhow::Error>((host(&server.server)?.to_owned(), server.token.clone()))).transpose()?;
    Ok(Plan { url: format!("{}/{cache}", server.server), public_key: info.public_key, netrc })
}

/// The netrc `machine` for a URL: its host, without scheme, port or path.
fn host(url: &str) -> anyhow::Result<&str> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.split(':').next().unwrap_or(host),
    };
    if host.is_empty() {
        bail!("no host in server URL {url}");
    }
    Ok(host)
}

fn nix_config_dir() -> anyhow::Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(base.join("nix"))
}

impl Plan {
    fn conf_lines(&self, netrc_file: Option<&Path>) -> Vec<String> {
        let mut lines = vec![format!("extra-substituters = {}", self.url)];
        if let Some(key) = &self.public_key {
            lines.push(format!("extra-trusted-public-keys = {key}"));
        }
        if let (Some(_), Some(file)) = (&self.netrc, netrc_file) {
            lines.push(format!("netrc-file = {}", file.display()));
        }
        lines
    }

    /// Settings for a NixOS configuration or `/etc/nix/nix.conf`, which
    /// apply to every user.
    pub fn print(&self) {
        println!("# nix.conf");
        for line in self.conf_lines(self.netrc.as_ref().map(|_| Path::new("/etc/nix/netrc"))) {
            println!("{line}");
        }
        println!("\n# NixOS");
        println!("nix.settings = {{");
        println!("  extra-substituters = [ \"{}\" ];", self.url);
        if let Some(key) = &self.public_key {
            println!("  extra-trusted-public-keys = [ \"{key}\" ];");
        }
        if self.netrc.is_some() {
            println!("  netrc-file = \"/etc/nix/netrc\"; # holding the netrc entry below");
        }
        println!("}};");
        if let Some((host, token)) = &self.netrc {
            println!("\n# netrc (keep it readable by root only)\nmachine {host}\nlogin helios\npassword {token}");
        }
    }

    /// Adds the settings to the user's nix.conf (and netrc), leaving lines
    /// already there alone.
    pub fn apply(&self) -> anyhow::Result<()> {
        let dir = nix_config_dir()?;
        std::fs::create_dir_all(&dir)?;
        let conf = dir.join("nix.conf");
        let existing =
            std::fs::read_to_string(&conf).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(String::new()) } else { Err(e) })?;

        let mut netrc_file = None;
        if let Some((host, token)) = &self.netrc {
            // An existing netrc-file setting wins; Nix reads only one file.
            let file = existing
                .lines()
                .find_map(|l| l.trim().strip_prefix("netrc-file")?.trim_start().strip_prefix('=').map(|v| PathBuf::from(v.trim())))
                .unwrap_or_else(|| dir.join("netrc"));
            add_netrc(&file, host, token)?;
            netrc_file = Some(file);
        }

        let missing: Vec<String> = self
            .conf_lines(netrc_file.as_deref())
            .into_iter()
            .filter(|line| {
                let key = line.split('=').next().unwrap_or("").trim();
                // netrc-file is single-valued: keep the one that is there.
                !existing.lines().any(|l| l.trim() == line || (key == "netrc-file" && l.trim().starts_with("netrc-file")))
            })
            .collect();
        if !missing.is_empty() {
            let mut out = std::fs::OpenOptions::new().append(true).create(true).open(&conf)?;
            if !existing.is_empty() && !existing.ends_with('\n') {
                writeln!(out)?;
            }
            for line in &missing {
                writeln!(out, "{line}")?;
            }
        }
        tracing::info!("configured {} in {}", self.url, conf.display());
        if self.public_key.is_none() {
            tracing::warn!("the server has no signing key; Nix refuses its paths unless require-sigs is off");
        }
        if !nix_trusts_user() {
            tracing::warn!(
                "the Nix daemon does not trust this user, so it ignores substituters set here; \
                 add them system-wide instead (helios use --print shows how) or list this user in trusted-users"
            );
        }
        Ok(())
    }
}

/// Appends `machine host` to a netrc, replacing an earlier entry for it.
fn add_netrc(file: &Path, host: &str, token: &str) -> anyhow::Result<()> {
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    // netrc entries are whitespace-separated tokens; drop the one for this
    // host so a new login replaces its token.
    let mut kept = String::new();
    let mut tokens = existing.split_whitespace().peekable();
    while let Some(t) = tokens.next() {
        if t == "machine" && tokens.peek() == Some(&host) {
            tokens.next();
            while let Some(&next) = tokens.peek() {
                if next == "machine" || next == "default" {
                    break;
                }
                tokens.next();
            }
            continue;
        }
        kept.push_str(if t == "machine" || t == "default" { "\n" } else { " " });
        kept.push_str(t);
    }
    let body = format!("{}\nmachine {host} login helios password {token}\n", kept.trim());
    let mut out = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(file)?;
    out.write_all(body.trim_start().as_bytes())?;
    Ok(())
}

fn nix_trusts_user() -> bool {
    let Ok(out) = std::process::Command::new("nix").args(["--extra-experimental-features", "nix-command", "store", "info", "--json"]).output() else {
        return true; // No way to tell; do not warn.
    };
    serde_json::from_slice::<serde_json::Value>(&out.stdout).map_or(true, |v| v["trusted"] != false && v["trusted"] != 0)
}

#[cfg(test)]
mod tests {
    use super::host;

    #[test]
    fn hosts() {
        assert_eq!(host("https://cache.example.com").unwrap(), "cache.example.com");
        assert_eq!(host("http://127.0.0.1:8080/").unwrap(), "127.0.0.1");
        assert_eq!(host("http://[::1]:8080").unwrap(), "::1");
        assert_eq!(host("https://u@cache.example.com:443/x").unwrap(), "cache.example.com");
        assert!(host("http://").is_err());
    }
}

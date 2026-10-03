//! `helios use <cache>`: configure Nix to substitute from a cache.
//!
//! The substituter URL is the one given to `helios login`, never an address
//! the server reports about itself: behind a proxy the server does not know
//! the address clients reach it at (compare zhaofengli/attic#325).

use std::io::Write;
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
    /// The server's compression defaults; absent from older servers.
    #[serde(default)]
    pub compression: Option<Compression>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct Compression {
    pub level: i32,
    pub window_log: i32,
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
            netrc_file = self.write_netrc(&dir, &existing, host, token)?;
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

    /// Adds the token to the netrc file Nix reads. Nix reads only one, so
    /// pointing it at a new one would hide the entries of the one it reads
    /// now (by default `/etc/nix/netrc`). Returns the file to name in the
    /// user's nix.conf, if any.
    fn write_netrc(&self, dir: &Path, conf: &str, host: &str, token: &str) -> anyhow::Result<Option<PathBuf>> {
        // One set in the user's nix.conf already is the one.
        if let Some(file) = conf.lines().find_map(conf_netrc_file) {
            add_netrc(&file, None, host, token)?;
            tracing::info!("added the token for {host} to {}", file.display());
            return Ok(Some(file));
        }
        let effective = effective_netrc_file();
        if let Some(file) = &effective
            && std::fs::OpenOptions::new().append(true).open(file).is_ok()
        {
            add_netrc(file, None, host, token)?;
            tracing::info!("added the token for {host} to {}", file.display());
            return Ok(None);
        }
        let own = dir.join("netrc");
        let mut base = None;
        if let Some(file) = effective.filter(|f| *f != own) {
            match std::fs::read_to_string(&file) {
                Ok(text) if !own.exists() => {
                    tracing::info!("copying the entries of {} to {}, which Nix reads instead from now on", file.display(), own.display());
                    base = Some(text);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    tracing::warn!("Nix reads {} instead of {} from now on; copy over any entries it still needs", own.display(), file.display())
                }
                Err(e) => tracing::warn!(
                    "Nix reads {} instead of {} from now on, which could not be read to copy its entries over ({e}); \
                     copy any it still needs by hand",
                    own.display(),
                    file.display()
                ),
            }
        }
        add_netrc(&own, base, host, token)?;
        tracing::info!("added the token for {host} to {}", own.display());
        Ok(Some(own))
    }
}

/// Sets the token for `host` in a netrc file. `base` is the content to
/// start from instead of the file's own, when the file is new.
fn add_netrc(file: &Path, base: Option<String>, host: &str, token: &str) -> anyhow::Result<()> {
    let existing = match base {
        Some(base) => base,
        None => match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
        },
    };
    crate::config::write_secret(file, edit_netrc(&existing, host, token).as_bytes())
}

/// `netrc` with the entry for `machine host` set to the token. The old
/// entry's lines go (its usual forms: on one line, or `login`, `password`
/// and `account` on lines of their own), the new entry takes their place,
/// or comes before any `default` entry, which ends the entries curl reads.
/// Every other line, with comments, macros and quoting, stays as it was.
fn edit_netrc(netrc: &str, host: &str, token: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut at: Option<usize> = None;
    let (mut removing, mut in_macro) = (false, false);
    for line in netrc.split_inclusive('\n') {
        let words: Vec<&str> = line.split_whitespace().collect();
        if in_macro {
            // A macro body runs to the next empty line.
            if words.is_empty() {
                (in_macro, removing) = (false, false);
                kept.push(line);
            } else if !removing {
                kept.push(line);
            }
            continue;
        }
        match words.first().copied() {
            None => {}
            Some(w) if w.starts_with('#') => {}
            Some(first @ ("machine" | "default")) => {
                removing = false;
                if first == "default" {
                    at.get_or_insert(kept.len());
                }
                // Only an entry alone on its line; one sharing a line with
                // others is left alone.
                let ours = first == "machine" && words.get(1) == Some(&host) && !words[2..].iter().any(|w| matches!(*w, "machine" | "default"));
                if ours {
                    at.get_or_insert(kept.len());
                    removing = true;
                    in_macro = words.contains(&"macdef");
                    continue;
                }
            }
            Some("login" | "password" | "account" | "macdef") if removing => {
                in_macro = words.contains(&"macdef");
                continue;
            }
            Some(_) => removing = false,
        }
        in_macro = words.contains(&"macdef") && !words[0].starts_with('#');
        kept.push(line);
    }
    let at = at.unwrap_or(kept.len());
    let mut out: String = kept[..at].concat();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("machine {host} login helios password {token}\n"));
    out.push_str(&kept[at..].concat());
    out
}

/// The netrc file Nix reads, as `nix config show` reports it with every
/// configuration file applied.
fn effective_netrc_file() -> Option<PathBuf> {
    let nix = |args: &[&str]| {
        let out = std::process::Command::new("nix")
            .args(["--extra-experimental-features", "nix-command"])
            .args(args)
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let value = match nix(&["config", "show", "netrc-file"]) {
        Some(v) => v.trim().to_owned(),
        // Before `nix config show`.
        None => nix(&["show-config"])?.lines().find_map(conf_netrc_file)?.to_string_lossy().into_owned(),
    };
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// The value of a `netrc-file = ...` line.
fn conf_netrc_file(line: &str) -> Option<PathBuf> {
    line.trim().strip_prefix("netrc-file")?.trim_start().strip_prefix('=').map(|v| PathBuf::from(v.trim()))
}

fn nix_trusts_user() -> bool {
    let Ok(out) = std::process::Command::new("nix").args(["--extra-experimental-features", "nix-command", "store", "info", "--json"]).output() else {
        return true; // No way to tell; do not warn.
    };
    serde_json::from_slice::<serde_json::Value>(&out.stdout).map_or(true, |v| v["trusted"] != false && v["trusted"] != 0)
}

#[cfg(test)]
mod tests {
    use super::{edit_netrc, host};

    #[test]
    fn hosts() {
        assert_eq!(host("https://cache.example.com").unwrap(), "cache.example.com");
        assert_eq!(host("http://127.0.0.1:8080/").unwrap(), "127.0.0.1");
        assert_eq!(host("http://[::1]:8080").unwrap(), "::1");
        assert_eq!(host("https://u@cache.example.com:443/x").unwrap(), "cache.example.com");
        assert!(host("http://").is_err());
    }

    #[test]
    fn netrc_entries_go_before_default() {
        let netrc = "machine a login x password y\ndefault login anonymous password me@example.com\n";
        assert_eq!(
            edit_netrc(netrc, "h", "T"),
            "machine a login x password y\nmachine h login helios password T\ndefault login anonymous password me@example.com\n"
        );
        // An entry stranded after `default` by an older helios moves up.
        let stale = "default login x password y\nmachine h login helios password old\n";
        assert_eq!(edit_netrc(stale, "h", "T"), "machine h login helios password T\ndefault login x password y\n");
        assert_eq!(edit_netrc("", "h", "T"), "machine h login helios password T\n");
        assert_eq!(edit_netrc("machine a login x password y", "h", "T"), "machine a login x password y\nmachine h login helios password T\n");
    }

    #[test]
    fn netrc_edits_leave_other_lines_alone() {
        let netrc = "# tokens\nmachine h\n  login old\n  # rotated yearly\n  password old\n\nmachine o login l password \"a b\"\n";
        assert_eq!(
            edit_netrc(netrc, "h", "T"),
            "# tokens\nmachine h login helios password T\n  # rotated yearly\n\nmachine o login l password \"a b\"\n"
        );
        let macros = "machine o login l password p macdef init\nmachine h is not an entry here\n\nmachine h login a password b\n";
        assert_eq!(
            edit_netrc(macros, "h", "T"),
            "machine o login l password p macdef init\nmachine h is not an entry here\n\nmachine h login helios password T\n"
        );
        let own_macro = "machine h login a password b\nmacdef init\ncd /x\n\nmachine o login l password p\n";
        assert_eq!(edit_netrc(own_macro, "h", "T"), "machine h login helios password T\n\nmachine o login l password p\n");
    }
}

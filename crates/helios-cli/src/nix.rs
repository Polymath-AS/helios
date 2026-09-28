//! Store path metadata from `nix path-info`: one process for the whole set.

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use serde::Deserialize;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path: String,
    pub hash: String,
    pub nar_hash: String,
    pub nar_size: u64,
    /// Full store paths.
    pub references: Vec<String>,
    pub deriver: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawInfo {
    #[serde(default)]
    path: Option<String>,
    nar_hash: String,
    nar_size: u64,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    deriver: Option<String>,
}

const STORE_DIR: &str = "/nix/store/";

fn full(p: &str) -> String {
    if p.starts_with('/') { p.to_owned() } else { format!("{STORE_DIR}{p}") }
}

async fn run(args: &[&str], installables: &[String]) -> anyhow::Result<std::process::Output> {
    Command::new("nix")
        .args(["--extra-experimental-features", "nix-command flakes", "path-info"])
        .args(args)
        .arg("--")
        .args(installables)
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .context("running nix path-info (is nix on PATH?)")
}

pub async fn path_infos(installables: &[String], closure: bool) -> anyhow::Result<Vec<PathInfo>> {
    let mut args = vec!["--json", "--json-format", "1"];
    if closure {
        args.push("--recursive");
    }
    let mut out = run(&args, installables).await?;
    if !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("json-format") {
        // Older Nix without --json-format.
        args.retain(|a| *a != "--json-format" && *a != "1");
        out = run(&args, installables).await?;
    }
    if !out.status.success() {
        bail!("nix path-info failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    parse(&out.stdout)
}

fn parse(stdout: &[u8]) -> anyhow::Result<Vec<PathInfo>> {
    let value: serde_json::Value = serde_json::from_slice(stdout).context("parsing nix path-info output")?;
    let mut raw: BTreeMap<String, RawInfo> = BTreeMap::new();
    match value {
        serde_json::Value::Object(map) => {
            for (path, info) in map {
                if info.is_null() {
                    bail!("{path} is not a valid store path");
                }
                raw.insert(full(&path), serde_json::from_value(info)?);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                let info: RawInfo = serde_json::from_value(item)?;
                let path = info.path.clone().context("path-info entry without a path")?;
                raw.insert(full(&path), info);
            }
        }
        _ => bail!("unexpected nix path-info output"),
    }
    raw.into_iter()
        .map(|(path, info)| {
            let base = path.strip_prefix(STORE_DIR).with_context(|| format!("{path} is not in /nix/store"))?;
            let hash = base.get(..32).with_context(|| format!("{path} has no store hash"))?.to_owned();
            Ok(PathInfo {
                hash,
                nar_hash: info.nar_hash,
                nar_size: info.nar_size,
                references: info.references.iter().map(|r| full(r)).collect(),
                deriver: info.deriver.map(|d| full(&d)),
                path,
            })
        })
        .collect()
}

/// Dependencies before dependents, so a partially pushed closure never
/// exposes a path whose references are missing.
pub fn topo_order(infos: Vec<PathInfo>) -> Vec<PathInfo> {
    use std::collections::HashMap;
    let index: HashMap<String, usize> = infos.iter().enumerate().map(|(i, p)| (p.path.clone(), i)).collect();
    let mut pending: Vec<usize> = vec![0; infos.len()];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); infos.len()];
    for (i, info) in infos.iter().enumerate() {
        for r in &info.references {
            if let Some(&j) = index.get(r)
                && j != i
            {
                pending[i] += 1;
                dependents[j].push(i);
            }
        }
    }
    let mut ready: Vec<usize> = (0..infos.len()).filter(|&i| pending[i] == 0).collect();
    let mut order = Vec::with_capacity(infos.len());
    while let Some(i) = ready.pop() {
        order.push(i);
        for &d in &dependents[i] {
            pending[d] -= 1;
            if pending[d] == 0 {
                ready.push(d);
            }
        }
    }
    // Cycles cannot occur in a valid store; keep anything left over anyway.
    let placed: std::collections::HashSet<usize> = order.iter().copied().collect();
    order.extend((0..infos.len()).filter(|i| !placed.contains(i)));
    let mut slots: Vec<Option<PathInfo>> = infos.into_iter().map(Some).collect();
    order.into_iter().map(|i| slots[i].take().expect("each index placed once")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(name: &str, refs: &[&str]) -> PathInfo {
        PathInfo {
            path: format!("{STORE_DIR}{name}"),
            hash: String::new(),
            nar_hash: String::new(),
            nar_size: 0,
            references: refs.iter().map(|r| format!("{STORE_DIR}{r}")).collect(),
            deriver: None,
        }
    }

    #[test]
    fn dependencies_come_first() {
        let order = topo_order(vec![info("app", &["lib", "app"]), info("lib", &["libc"]), info("libc", &[])]);
        let names: Vec<_> = order.iter().map(|p| p.path.trim_start_matches(STORE_DIR)).collect();
        assert_eq!(names, ["libc", "lib", "app"]);
    }

    #[test]
    fn parses_both_json_formats() {
        let obj = br#"{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x":{"narHash":"sha256-AAAA","narSize":8,"references":[],"deriver":null}}"#;
        assert_eq!(parse(obj).unwrap()[0].hash, "a".repeat(32));
        let arr = br#"[{"path":"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-y","narHash":"sha256:x","narSize":8,"references":["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-y"]}]"#;
        assert_eq!(parse(arr).unwrap()[0].references.len(), 1);
    }
}

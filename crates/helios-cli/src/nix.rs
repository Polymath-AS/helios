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
    /// Set for content-addressed paths, such as CA derivation outputs.
    pub ca: Option<String>,
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
    #[serde(default)]
    ca: Option<String>,
}

const STORE_DIR: &str = "/nix/store/";

fn full(p: &str) -> String {
    if p.starts_with('/') { p.to_owned() } else { format!("{STORE_DIR}{p}") }
}

/// Installables beyond this many go to Nix on stdin rather than argv,
/// which the kernel caps (E2BIG).
const MAX_ARGS: usize = 1_000;

/// Runs `cmd` with `installables` as arguments, or on stdin (`--stdin`)
/// when there are too many for one command line.
async fn output(mut cmd: Command, installables: &[String]) -> std::io::Result<std::process::Output> {
    use tokio::io::AsyncWriteExt;
    cmd.stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    if installables.len() <= MAX_ARGS {
        // Not our stdin: nothing should wait on whatever the caller left open.
        return cmd.arg("--").args(installables).stdin(std::process::Stdio::null()).output().await;
    }
    let mut child = cmd.arg("--stdin").stdin(std::process::Stdio::piped()).spawn()?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let input = installables.join("\n") + "\n";
    // Feed stdin while collecting the output, or a full pipe deadlocks both.
    let (written, out) = futures_util::future::join(
        async move {
            let r = stdin.write_all(input.as_bytes()).await;
            drop(stdin);
            r
        },
        child.wait_with_output(),
    )
    .await;
    let out = out?;
    // Nix closes the pipe early when it fails; its stderr says why.
    if out.status.success() {
        written?;
    }
    Ok(out)
}

async fn run(args: &[&str], installables: &[String]) -> anyhow::Result<std::process::Output> {
    let mut cmd = Command::new("nix");
    cmd.args(["--extra-experimental-features", "nix-command flakes", "path-info"]).args(args);
    output(cmd, installables).await.context("running nix path-info (is nix on PATH?)")
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
                ca: info.ca,
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

/// Build trace entries (realisations) for these derivations' outputs, as
/// this Nix prints them: `{"key", "value"}` from 2.35 on, `{"id", "outPath"}`
/// before. Empty when this Nix has CA derivations disabled.
pub async fn build_traces(derivers: &[String]) -> anyhow::Result<Vec<serde_json::Value>> {
    let outputs: Vec<String> = derivers.iter().map(|d| format!("{d}^*")).collect();
    let mut out = None;
    // `store build-trace` is the current name; `realisation` the old one.
    for sub in [&["store", "build-trace", "info"][..], &["realisation", "info"][..]] {
        let mut cmd = Command::new("nix");
        cmd.args(["--extra-experimental-features", "nix-command ca-derivations"]).args(sub).arg("--json");
        let o = output(cmd, &outputs).await.context("running nix store build-trace info")?;
        if o.status.success() {
            out = Some(o);
            break;
        }
        tracing::debug!("nix {}: {}", sub.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    let Some(out) = out else { return Ok(Vec::new()) };
    let entries: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).context("parsing build trace entries")?;
    // Store paths given as installables come back as `{"opaquePath"}`.
    Ok(entries.into_iter().filter(|e| e.get("key").is_some() || e.get("id").is_some()).collect())
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
            ca: None,
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

    #[test]
    fn many_installables_go_on_stdin() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let run = |n: usize| {
            let mut cmd = Command::new("sh");
            cmd.args(["-c", r#"printf '%s ' "$@"; cat | wc -l"#, "sh"]);
            let args: Vec<String> = (0..n).map(|i| format!("p{i}")).collect();
            let out = rt.block_on(output(cmd, &args)).unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(run(2).split_whitespace().collect::<Vec<_>>(), ["--", "p0", "p1", "0"]);
        assert_eq!(run(MAX_ARGS + 1).split_whitespace().collect::<Vec<_>>(), ["--stdin", &(MAX_ARGS + 1).to_string()]);
    }
}

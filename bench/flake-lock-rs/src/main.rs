//! Reference side of bench/flake-lock.sh.
//!
//! - `canon <file>...`: for each file print `== <file>` then either the
//!   canonical bytes plus `-- valid` / `-- invalid`, or `-- parse error`.
//! - `bench <file>...`: `<op>:<file> <iters> <best-round-ns>` lines.
//! - `gen <dir>`: write the large / adversarial fixtures from upstream's benches.
//! - `fuzz <dir> <n> <seed> <file>...`: write `n` mutated copies of the inputs.

use std::fmt::Write as _;
use std::hint::black_box;
use std::io::Write as _;
use std::time::Instant;

use nix_flake_lock::LockFile;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

pub fn iterations(len: usize) -> usize {
    (4_000_000 / len.max(1)).clamp(3, 200_000)
}

fn best<F: FnMut()>(iters: usize, mut f: F) -> u128 {
    for _ in 0..iters.min(1000) {
        f();
    }
    (0..7)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            t.elapsed().as_nanos()
        })
        .min()
        .unwrap()
}

fn large(nodes: usize, reverse: bool) -> String {
    let idx = |p: usize| if reverse { nodes - p - 1 } else { p };
    let mut json = String::from("{\"nodes\":{\"root\":{\"inputs\":{");
    for p in 0..nodes {
        if p != 0 {
            json.push(',');
        }
        let i = idx(p);
        write!(json, "\"n{i:06}\":\"n{i:06}\"").unwrap();
    }
    json.push_str("}}");
    for p in 0..nodes {
        let i = idx(p);
        write!(json, ",\"n{i:06}\":{{\"locked\":{{\"path\":\"x\",\"type\":\"path\"}},\"original\":{{\"path\":\"x\",\"type\":\"path\"}}}}").unwrap();
    }
    json.push_str("},\"root\":\"root\",\"version\":7}");
    json
}

fn colliding(n: usize) -> String {
    let mut json = String::from("{\"nodes\":{\"root\":{\"inputs\":{");
    for i in 0..n {
        if i != 0 {
            json.push(',');
        }
        write!(json, "\"dep{i:06}\":\"dep{i:06}\"").unwrap();
    }
    json.push_str("}}");
    for i in 0..n {
        write!(json, ",\"dep{i:06}\":{{\"inputs\":{{\"systems\":\"systems{i:06}\"}},\"locked\":{{\"path\":\"x\",\"type\":\"path\"}},\"original\":{{\"path\":\"x\",\"type\":\"path\"}}}},\"systems{i:06}\":{{\"locked\":{{\"path\":\"x\",\"type\":\"path\"}},\"original\":{{\"path\":\"x\",\"type\":\"path\"}}}}").unwrap();
    }
    json.push_str("},\"root\":\"root\",\"version\":7}");
    json
}

/// xorshift64*: deterministic mutations shared by nothing but this tool.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, mut doc: Vec<u8>) -> Vec<u8> {
    const TOKENS: &[&[u8]] = &[
        b"\"", b"\\", b"\\u00e9", b"\\ud83d\\ude00", b"\\ud800", b"{", b"}", b"[", b"]", b",", b":",
        b"null", b"true", b"false", b"0", b"01", b"1.5", b"-1", b"18446744073709551616", b"\"root\"",
        b"\"inputs\"", b"\"follows\"", b"[\"a\"]", b"\"version\"", b"\xc3\xa9", b"\xff", b"\x01", b" ", b"\n",
    ];
    for _ in 0..1 + rng.below(3) {
        let at = rng.below(doc.len() + 1);
        match rng.below(4) {
            0 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                doc.splice(at..at, t.iter().copied());
            }
            1 if !doc.is_empty() => {
                let end = (at + 1 + rng.below(8)).min(doc.len());
                doc.drain(at.min(doc.len())..end);
            }
            2 if at < doc.len() => doc[at] = TOKENS[rng.below(TOKENS.len())][0],
            _ => {
                // Duplicate a slice (duplicate keys, repeated members).
                if doc.len() > 2 {
                    let a = rng.below(doc.len());
                    let b = (a + rng.below(64)).min(doc.len());
                    let piece = doc[a..b].to_vec();
                    doc.splice(at..at, piece);
                }
            }
        }
    }
    doc
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = std::io::stdout();
    let mut out = std::io::BufWriter::new(out.lock());
    match args.first().map(String::as_str) {
        Some("canon") => {
            for f in &args[1..] {
                let bytes = read(f);
                writeln!(out, "== {f}").unwrap();
                match LockFile::parse(&bytes) {
                    Ok(lock) => {
                        out.write_all(&lock.to_nix_bytes()).unwrap();
                        writeln!(out, "-- {}", if lock.validate().is_ok() { "valid" } else { "invalid" }).unwrap();
                    }
                    Err(_) => writeln!(out, "-- parse error").unwrap(),
                }
            }
        }
        Some("bench") => {
            for f in &args[1..] {
                let bytes = read(f);
                let name = std::path::Path::new(f).file_name().unwrap().to_string_lossy().into_owned();
                let iters = iterations(bytes.len());
                let lock = LockFile::parse(&bytes).expect("bench inputs parse");
                let ns = best(iters, || {
                    black_box(LockFile::parse(black_box(&bytes)).unwrap());
                });
                writeln!(out, "parse:{name} {iters} {ns}").unwrap();
                let ns = best(iters, || {
                    black_box(black_box(&lock).to_nix_bytes());
                });
                writeln!(out, "serialize:{name} {iters} {ns}").unwrap();
                let ns = best(iters, || {
                    black_box(black_box(&lock).validate()).ok();
                });
                writeln!(out, "validate:{name} {iters} {ns}").unwrap();
            }
        }
        Some("gen") => {
            let dir = &args[1];
            std::fs::write(format!("{dir}/large-sorted-8000.lock"), large(8000, false)).unwrap();
            std::fs::write(format!("{dir}/large-reverse-8000.lock"), large(8000, true)).unwrap();
            std::fs::write(format!("{dir}/colliding-4000.lock"), colliding(4000)).unwrap();
        }
        Some("fuzz") => {
            let dir = &args[1];
            let n: usize = args[2].parse().unwrap();
            let mut rng = Rng(args[3].parse::<u64>().unwrap() | 1);
            let seeds: Vec<Vec<u8>> = args[4..].iter().map(|f| read(f)).collect();
            for i in 0..n {
                let seed = seeds[rng.below(seeds.len())].clone();
                std::fs::write(format!("{dir}/fuzz-{i:05}.lock"), mutate(&mut rng, seed)).unwrap();
            }
        }
        _ => {
            eprintln!("usage: flake-lock-rs canon|bench|gen|fuzz ...");
            std::process::exit(2);
        }
    }
}

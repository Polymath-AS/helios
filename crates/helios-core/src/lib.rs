//! Safe bindings to libhelios, the Zig core: the compressing NAR pipeline,
//! the upload verifier, nix32, narinfo rendering and Ed25519 signing.

use std::ffi::{CStr, CString, c_int, c_void};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

mod sys {
    use std::ffi::{c_char, c_int, c_void};

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Digest {
        pub file_hash: [u8; 32],
        pub file_size: u64,
        pub nar_hash: [u8; 32],
        pub nar_size: u64,
    }

    #[repr(C)]
    pub struct DumpOptions {
        pub level: c_int,
        pub threads: c_int,
        pub size_hint: u64,
    }

    #[repr(C)]
    pub struct Str {
        pub ptr: *const u8,
        pub len: usize,
    }

    #[repr(C)]
    pub struct NarinfoInput {
        pub store_path: Str,
        pub nar_hash: *const [u8; 32],
        pub nar_size: u64,
        pub file_hash: *const [u8; 32],
        pub file_size: u64,
        pub compression: Str,
        pub references: Str,
        pub deriver: Str,
        pub system: Str,
    }

    pub type WriteFn = unsafe extern "C" fn(ctx: *mut c_void, buf: *const u8, len: usize) -> c_int;

    pub enum Compressor {}
    pub enum Verifier {}
    pub enum Signer {}

    unsafe extern "C" {
        pub fn hl_strerror(rc: c_int) -> *const c_char;
        pub fn hl_last_errno() -> c_int;
        pub fn hl_nix32_encode(bytes: *const u8, len: usize, out: *mut u8) -> usize;
        pub fn hl_nix32_decode(text: *const u8, text_len: usize, out: *mut u8, out_len: usize) -> c_int;
        pub fn hl_store_basename_valid(base: *const u8, len: usize) -> bool;
        pub fn hl_nar_dump(path: *const c_char, opts: *const DumpOptions, write: WriteFn, ctx: *mut c_void, out: *mut Digest) -> c_int;
        pub fn hl_compressor_new(opts: *const DumpOptions, write: WriteFn, ctx: *mut c_void) -> *mut Compressor;
        pub fn hl_compressor_update(c: *mut Compressor, data: *const u8, len: usize) -> c_int;
        pub fn hl_compressor_finish(c: *mut Compressor, out: *mut Digest) -> c_int;
        pub fn hl_compressor_free(c: *mut Compressor);
        pub fn hl_verifier_new(compression: c_int) -> *mut Verifier;
        pub fn hl_verifier_update(v: *mut Verifier, data: *const u8, len: usize) -> c_int;
        pub fn hl_verifier_finish(v: *mut Verifier, out: *mut Digest) -> c_int;
        pub fn hl_verifier_free(v: *mut Verifier);
        pub fn hl_signer_new(key: *const u8, len: usize) -> *mut Signer;
        pub fn hl_signer_free(s: *mut Signer);
        pub fn hl_signer_public_key(s: *const Signer, out: *mut u8, cap: usize, out_len: *mut usize) -> c_int;
        pub fn hl_signer_generate(name: *const u8, name_len: usize, out: *mut u8, cap: usize, out_len: *mut usize) -> c_int;
        pub fn hl_narinfo_render(input: *const NarinfoInput, signer: *const Signer, out: *mut *mut u8, out_len: *mut usize) -> c_int;
        pub fn hl_free(ptr: *mut u8, len: usize);
        pub fn hl_sha256(data: *const u8, len: usize, out: *mut [u8; 32]);
        pub fn hl_hmac_sha256(key: *const u8, key_len: usize, msg: *const u8, msg_len: usize, out: *mut [u8; 32]);
        pub fn hl_random(buf: *mut u8, len: usize) -> c_int;
    }
}

pub const HL_E_IO: i32 = -1;
pub const HL_E_ABORTED: i32 = -4;
pub const HL_E_INVALID: i32 = -5;
pub const HL_E_UNSUPPORTED_OS: i32 = -8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub code: i32,
    /// OS errno for I/O failures, 0 otherwise.
    pub errno: i32,
}

impl Error {
    fn from_rc(code: c_int) -> Self {
        let errno = if code == HL_E_IO { unsafe { sys::hl_last_errno() } } else { 0 };
        Self { code, errno }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = unsafe { CStr::from_ptr(sys::hl_strerror(self.code)) };
        write!(f, "{}", msg.to_string_lossy())?;
        if self.errno != 0 {
            write!(f, ": {}", std::io::Error::from_raw_os_error(self.errno))?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

fn check(rc: c_int) -> Result<(), Error> {
    if rc == 0 { Ok(()) } else { Err(Error::from_rc(rc)) }
}

// ── nix32 ──

pub fn nix32_encode(bytes: &[u8]) -> String {
    let len = if bytes.is_empty() { 0 } else { (bytes.len() * 8 - 1) / 5 + 1 };
    let mut out = vec![0u8; len];
    unsafe { sys::hl_nix32_encode(bytes.as_ptr(), bytes.len(), out.as_mut_ptr()) };
    // The nix32 alphabet is ASCII.
    unsafe { String::from_utf8_unchecked(out) }
}

pub fn nix32_decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    let rc = unsafe { sys::hl_nix32_decode(text.as_ptr(), text.len(), out.as_mut_ptr(), N) };
    (rc == 0).then_some(out)
}

/// `<32 nix32 chars>-<name>` with only the characters Nix allows.
pub fn store_basename_valid(base: &str) -> bool {
    unsafe { sys::hl_store_basename_valid(base.as_ptr(), base.len()) }
}

// ── Pipeline ──

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Digest {
    pub file_hash: [u8; 32],
    pub file_size: u64,
    pub nar_hash: [u8; 32],
    pub nar_size: u64,
}

impl From<sys::Digest> for Digest {
    fn from(d: sys::Digest) -> Self {
        Self { file_hash: d.file_hash, file_size: d.file_size, nar_hash: d.nar_hash, nar_size: d.nar_size }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DumpOptions {
    /// zstd level; 0 disables compression.
    pub level: i32,
    /// zstd worker threads; 0 compresses on the calling thread.
    pub threads: i32,
    /// Expected NAR size, 0 if unknown.
    pub size_hint: u64,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self { level: 3, threads: 0, size_hint: 0 }
    }
}

impl DumpOptions {
    fn raw(&self) -> sys::DumpOptions {
        sys::DumpOptions { level: self.level, threads: self.threads, size_hint: self.size_hint }
    }
}

unsafe extern "C" fn trampoline<F: FnMut(&[u8]) -> bool>(ctx: *mut c_void, buf: *const u8, len: usize) -> c_int {
    let f = unsafe { &mut *(ctx as *mut F) };
    let chunk = unsafe { std::slice::from_raw_parts(buf, len) };
    // Never unwind into Zig.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(chunk))) {
        Ok(true) => 0,
        _ => 1,
    }
}

/// Serialise `path` as a NAR, compress it and stream the output to `write`.
/// Return `false` from `write` to abort. Blocking; Linux only.
pub fn dump_nar<F: FnMut(&[u8]) -> bool>(path: &Path, opts: &DumpOptions, mut write: F) -> Result<Digest, Error> {
    let cpath = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error { code: HL_E_INVALID, errno: 0 })?;
    let mut out = sys::Digest::default();
    let rc = unsafe {
        sys::hl_nar_dump(cpath.as_ptr(), &opts.raw(), trampoline::<F>, &mut write as *mut F as *mut c_void, &mut out)
    };
    check(rc)?;
    Ok(out.into())
}

/// The same pipeline, fed with NAR bytes produced elsewhere.
pub struct Compressor<F: FnMut(&[u8]) -> bool> {
    raw: *mut sys::Compressor,
    // Boxed so the pointer handed to Zig stays stable.
    _write: Box<F>,
}

impl<F: FnMut(&[u8]) -> bool> Compressor<F> {
    pub fn new(opts: &DumpOptions, write: F) -> Result<Self, Error> {
        let mut write = Box::new(write);
        let ctx = &mut *write as *mut F as *mut c_void;
        let raw = unsafe { sys::hl_compressor_new(&opts.raw(), trampoline::<F>, ctx) };
        if raw.is_null() {
            return Err(Error { code: -6, errno: 0 });
        }
        Ok(Self { raw, _write: write })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        check(unsafe { sys::hl_compressor_update(self.raw, data.as_ptr(), data.len()) })
    }

    pub fn finish(self) -> Result<Digest, Error> {
        let mut out = sys::Digest::default();
        check(unsafe { sys::hl_compressor_finish(self.raw, &mut out) })?;
        Ok(out.into())
    }
}

impl<F: FnMut(&[u8]) -> bool> Drop for Compressor<F> {
    fn drop(&mut self) {
        unsafe { sys::hl_compressor_free(self.raw) }
    }
}

// ── Verifier ──

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Zstd,
}

impl Compression {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "zstd" => Some(Self::Zstd),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Zstd => "zstd",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::None => ".nar",
            Self::Zstd => ".nar.zst",
        }
    }
}

/// Hashes an uploaded compressed NAR and the NAR it decompresses to.
pub struct Verifier {
    raw: *mut sys::Verifier,
}

// The verifier owns its state exclusively; it is only ever used from one thread at a time.
unsafe impl Send for Verifier {}

impl Verifier {
    pub fn new(compression: Compression) -> Result<Self, Error> {
        let kind = match compression {
            Compression::None => 0,
            Compression::Zstd => 1,
        };
        let raw = unsafe { sys::hl_verifier_new(kind) };
        if raw.is_null() {
            return Err(Error { code: -6, errno: 0 });
        }
        Ok(Self { raw })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        check(unsafe { sys::hl_verifier_update(self.raw, data.as_ptr(), data.len()) })
    }

    pub fn finish(self) -> Result<Digest, Error> {
        let mut out = sys::Digest::default();
        check(unsafe { sys::hl_verifier_finish(self.raw, &mut out) })?;
        Ok(out.into())
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        unsafe { sys::hl_verifier_free(self.raw) }
    }
}

// ── Signing and narinfo ──

pub struct Signer {
    raw: *mut sys::Signer,
}

// Immutable after construction; signing only reads the key pair.
unsafe impl Send for Signer {}
unsafe impl Sync for Signer {}

impl Signer {
    /// Parses a Nix secret key (`nix key generate-secret` output).
    pub fn new(secret_key: &str) -> Option<Self> {
        let raw = unsafe { sys::hl_signer_new(secret_key.as_ptr(), secret_key.len()) };
        (!raw.is_null()).then_some(Self { raw })
    }

    /// A new Nix secret key named `name`, in `nix key generate-secret` format.
    pub fn generate(name: &str) -> Result<String, Error> {
        let mut buf = vec![0u8; 256];
        let mut len = 0usize;
        check(unsafe { sys::hl_signer_generate(name.as_ptr(), name.len(), buf.as_mut_ptr(), buf.len(), &mut len) })?;
        buf.truncate(len);
        Ok(String::from_utf8(buf).expect("key name was valid UTF-8"))
    }

    /// `<name>:<base64>`, the value for `trusted-public-keys`.
    pub fn public_key(&self) -> String {
        let mut buf = vec![0u8; 256];
        let mut len = 0usize;
        let rc = unsafe { sys::hl_signer_public_key(self.raw, buf.as_mut_ptr(), buf.len(), &mut len) };
        assert_eq!(rc, 0, "public key fits in 256 bytes");
        buf.truncate(len);
        String::from_utf8(buf).expect("key name was valid UTF-8")
    }
}

impl Drop for Signer {
    fn drop(&mut self) {
        unsafe { sys::hl_signer_free(self.raw) }
    }
}

pub struct NarinfoInput<'a> {
    pub store_path: &'a str,
    pub nar_hash: &'a [u8; 32],
    pub nar_size: u64,
    pub file_hash: &'a [u8; 32],
    pub file_size: u64,
    pub compression: &'a str,
    /// Space-separated basenames.
    pub references: &'a str,
    pub deriver: &'a str,
    pub system: &'a str,
}

fn s(v: &str) -> sys::Str {
    sys::Str { ptr: v.as_ptr(), len: v.len() }
}

/// Validates every field and renders the narinfo, signed if `signer` is set.
pub fn render_narinfo(input: &NarinfoInput<'_>, signer: Option<&Signer>) -> Result<Vec<u8>, Error> {
    let raw = sys::NarinfoInput {
        store_path: s(input.store_path),
        nar_hash: input.nar_hash,
        nar_size: input.nar_size,
        file_hash: input.file_hash,
        file_size: input.file_size,
        compression: s(input.compression),
        references: s(input.references),
        deriver: s(input.deriver),
        system: s(input.system),
    };
    let mut ptr: *mut u8 = std::ptr::null_mut();
    let mut len = 0usize;
    let signer_ptr = signer.map_or(std::ptr::null(), |s| s.raw as *const sys::Signer);
    check(unsafe { sys::hl_narinfo_render(&raw, signer_ptr, &mut ptr, &mut len) })?;
    let text = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
    unsafe { sys::hl_free(ptr, len) };
    Ok(text)
}

// ── Primitives ──

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { sys::hl_sha256(data.as_ptr(), data.len(), &mut out) };
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { sys::hl_hmac_sha256(key.as_ptr(), key.len(), msg.as_ptr(), msg.len(), &mut out) };
    out
}

/// Constant-time equality for equal-length byte strings.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// Fills `buf` from the OS CSPRNG.
pub fn random_bytes(buf: &mut [u8]) {
    let rc = unsafe { sys::hl_random(buf.as_mut_ptr(), buf.len()) };
    assert_eq!(rc, 0, "the OS random number generator failed");
}

/// A random (version 4) UUID in canonical hyphenated form.
pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    random_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "test-1:suJsWimvBNFUIc0JJE18OfOMygH/f2GuTC2/XwD6rPKkV+1VKilMIkXl6Ax9hqeKpUF/BSOH+Fqng4tqZlirhw==";

    /// A scratch directory removed on drop (keeps tempfile out of the tree).
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("helios-core-test-{}", uuid_v4()));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn primitives() {
        // RFC 4231 test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(nix32_encode(&mac).len(), 52);
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            sha256(b"abc").iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(ct_eq(b"same", b"same") && !ct_eq(b"same", b"diff") && !ct_eq(b"a", b"ab"));
        let (a, b) = (uuid_v4(), uuid_v4());
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
    }

    #[test]
    fn nix32_round_trip() {
        let bytes = [7u8; 20];
        let text = nix32_encode(&bytes);
        assert_eq!(text.len(), 32);
        assert_eq!(nix32_decode::<20>(&text), Some(bytes));
        assert_eq!(nix32_decode::<20>("not-valid"), None);
    }

    #[test]
    fn generated_keys_round_trip() {
        let key = Signer::generate("gen-1").unwrap();
        assert!(key.starts_with("gen-1:"));
        assert_ne!(key, Signer::generate("gen-1").unwrap());
        assert!(Signer::new(&key).unwrap().public_key().starts_with("gen-1:"));
        assert!(Signer::generate("bad:name").is_err());
    }

    #[test]
    fn signer_public_key() {
        let signer = Signer::new(KEY).unwrap();
        assert!(signer.public_key().starts_with("test-1:"));
        assert!(Signer::new("garbage").is_none());
    }

    #[test]
    fn dump_matches_compressor_and_verifier() {
        let dir = TempDir::new();
        let root = dir.path().join("pkg");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("bin/hello"), b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(root.join("bin/hello"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        std::fs::write(root.join("big"), vec![b'a'; 5 << 20]).unwrap();
        std::os::unix::fs::symlink("bin/hello", root.join("link")).unwrap();

        let mut compressed = Vec::new();
        let digest = dump_nar(&root, &DumpOptions { level: 3, threads: 2, size_hint: 0 }, |c| {
            compressed.extend_from_slice(c);
            true
        })
        .unwrap();
        assert_eq!(digest.file_size, compressed.len() as u64);

        let mut v = Verifier::new(Compression::Zstd).unwrap();
        for chunk in compressed.chunks(65536) {
            v.update(chunk).unwrap();
        }
        let verified = v.finish().unwrap();
        assert_eq!(verified, digest);

        let aborted = dump_nar(&root, &DumpOptions::default(), |_| false);
        assert_eq!(aborted.unwrap_err().code, HL_E_ABORTED);
    }

    /// Our NAR serialiser must agree byte-for-byte with Nix: compare NAR
    /// hashes against the Nix database for a real closure.
    #[test]
    fn nar_hash_matches_nix_store() {
        use std::process::Command;
        let Ok(out) = Command::new("nix-store").args(["-qR", "/run/current-system/sw/bin/nix"]).output() else {
            eprintln!("nix-store not available; skipping");
            return;
        };
        if !out.status.success() {
            eprintln!("no local system closure; skipping");
            return;
        }
        let paths: Vec<String> = String::from_utf8(out.stdout).unwrap().lines().map(str::to_owned).collect();
        assert!(!paths.is_empty());
        let hashes = Command::new("nix-store").args(["-q", "--hash"]).args(&paths).output().unwrap();
        let hashes = String::from_utf8(hashes.stdout).unwrap();
        for (path, expected) in paths.iter().zip(hashes.lines()) {
            let digest = dump_nar(Path::new(path), &DumpOptions { level: 1, threads: 0, size_hint: 0 }, |_| true)
                .unwrap_or_else(|e| panic!("{path}: {e}"));
            assert_eq!(format!("sha256:{}", nix32_encode(&digest.nar_hash)), expected, "{path}");
        }
    }
}

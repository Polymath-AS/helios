//! C ABI for libhelios. See include/helios.h for the contract.

const std = @import("std");
const nix32 = @import("nix-base32");
const store_path = @import("nix-store-path");
const archive = @import("nix-archive");

const narinfo = @import("nix-narinfo");

const Sink = archive.Sink;
const Digest = archive.Digest;
const WriteFn = archive.WriteFn;
const gpa = std.heap.c_allocator;

pub const HL_OK: c_int = 0;
pub const HL_E_IO: c_int = -1;
pub const HL_E_UNSUPPORTED_FILE: c_int = -2;
pub const HL_E_ZSTD: c_int = -3;
pub const HL_E_ABORTED: c_int = -4;
pub const HL_E_INVALID: c_int = -5;
pub const HL_E_NOMEM: c_int = -6;
pub const HL_E_CHANGED: c_int = -7;
pub const HL_E_UNSUPPORTED_OS: c_int = -8;
pub const HL_E_TRUNCATED: c_int = -9;
pub const HL_E_NOT_NAR: c_int = -10;
pub const HL_E_BUFFER: c_int = -11;

fn code(err: anyerror) c_int {
    return switch (err) {
        error.Io, error.NameTooLong => HL_E_IO,
        error.UnsupportedFileType => HL_E_UNSUPPORTED_FILE,
        error.Zstd => HL_E_ZSTD,
        error.Aborted => HL_E_ABORTED,
        error.OutOfMemory => HL_E_NOMEM,
        error.FileChanged => HL_E_CHANGED,
        error.Truncated => HL_E_TRUNCATED,
        error.NotNar => HL_E_NOT_NAR,
        else => HL_E_INVALID,
    };
}

export fn hl_strerror(rc: c_int) [*:0]const u8 {
    return switch (rc) {
        HL_OK => "ok",
        HL_E_IO => "I/O error",
        HL_E_UNSUPPORTED_FILE => "unsupported file type in store path",
        HL_E_ZSTD => "zstd error",
        HL_E_ABORTED => "aborted by write callback",
        HL_E_INVALID => "invalid input",
        HL_E_NOMEM => "out of memory",
        HL_E_CHANGED => "file changed while reading",
        HL_E_UNSUPPORTED_OS => "NAR dumping is not supported on this OS",
        HL_E_TRUNCATED => "compressed stream is truncated",
        HL_E_NOT_NAR => "not a NAR archive",
        HL_E_BUFFER => "output buffer too small",
        else => "unknown error",
    };
}

export fn hl_last_errno() c_int {
    return archive.lastErrno();
}

// ── nix32 ──

export fn hl_nix32_encode(bytes: [*]const u8, len: usize, out: [*]u8) usize {
    const n = nix32.encodedLen(len);
    nix32.encode(out[0..n], bytes[0..len]);
    return n;
}

export fn hl_nix32_decode(text: [*]const u8, text_len: usize, out: [*]u8, out_len: usize) c_int {
    nix32.decode(out[0..out_len], text[0..text_len]) catch return HL_E_INVALID;
    return HL_OK;
}

export fn hl_store_basename_valid(base: [*]const u8, len: usize) bool {
    return store_path.isValidBaseName(base[0..len]);
}

// ── Compressing NAR pipeline ──

pub const DumpOptions = extern struct {
    level: c_int,
    threads: c_int,
    nar_size: u64,
    window_log: c_int,
};

fn sinkOptions(opts: *const DumpOptions) archive.Options {
    return .{ .level = opts.level, .threads = opts.threads, .nar_size = opts.nar_size, .window_log = opts.window_log };
}

export fn hl_nar_dump(path: [*:0]const u8, opts: *const DumpOptions, write: WriteFn, ctx: ?*anyopaque, out: *Digest) c_int {
    if (comptime !archive.supported) return HL_E_UNSUPPORTED_OS;
    var sink = Sink.init(gpa, sinkOptions(opts), write, ctx) catch |e| return code(e);
    defer sink.deinit(gpa);
    archive.dump(&sink, path) catch |e| return code(e);
    out.* = sink.finish() catch |e| return code(e);
    return HL_OK;
}

export fn hl_compressor_new(opts: *const DumpOptions, write: WriteFn, ctx: ?*anyopaque) ?*Sink {
    const sink = gpa.create(Sink) catch return null;
    sink.* = Sink.init(gpa, sinkOptions(opts), write, ctx) catch {
        gpa.destroy(sink);
        return null;
    };
    return sink;
}

export fn hl_compressor_update(sink: *Sink, data: [*]const u8, len: usize) c_int {
    sink.write(data[0..len]) catch |e| return code(e);
    return HL_OK;
}

export fn hl_compressor_finish(sink: *Sink, out: *Digest) c_int {
    out.* = sink.finish() catch |e| return code(e);
    return HL_OK;
}

export fn hl_compressor_free(sink: ?*Sink) void {
    const s = sink orelse return;
    s.deinit(gpa);
    gpa.destroy(s);
}

// ── Upload verifier ──

export fn hl_verifier_new(compression: c_int) ?*archive.Verifier {
    const kind = std.enums.fromInt(archive.Compression, compression) orelse return null;
    const v = gpa.create(archive.Verifier) catch return null;
    v.* = archive.Verifier.init(gpa, kind) catch {
        gpa.destroy(v);
        return null;
    };
    return v;
}

export fn hl_verifier_update(v: *archive.Verifier, data: [*]const u8, len: usize) c_int {
    v.update(data[0..len]) catch |e| return code(e);
    return HL_OK;
}

export fn hl_verifier_finish(v: *archive.Verifier, out: *Digest) c_int {
    out.* = v.finish() catch |e| return code(e);
    return HL_OK;
}

export fn hl_verifier_free(v: ?*archive.Verifier) void {
    const p = v orelse return;
    p.deinit(gpa);
    gpa.destroy(p);
}

// ── Signing and narinfo ──

export fn hl_signer_new(key: [*]const u8, len: usize) ?*narinfo.Signer {
    return narinfo.Signer.parse(gpa, key[0..len]) catch null;
}

export fn hl_signer_free(s: ?*narinfo.Signer) void {
    if (s) |p| p.destroy(gpa);
}

/// Generates a Nix secret key named `name` from the OS CSPRNG.
export fn hl_signer_generate(name: [*]const u8, name_len: usize, out: ?[*]u8, cap: usize, out_len: *usize) c_int {
    var seed: [32]u8 = undefined;
    const rc = hl_random(&seed, seed.len);
    if (rc != HL_OK) return rc;
    defer std.crypto.secureZero(u8, &seed);
    var list: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, list.items);
        list.deinit(gpa);
    }
    narinfo.Signer.generate(&list, gpa, name[0..name_len], seed) catch |e| return code(e);
    return copyOut(list.items, out, cap, out_len);
}

fn copyOut(bytes: []const u8, out: ?[*]u8, cap: usize, out_len: *usize) c_int {
    out_len.* = bytes.len;
    if (bytes.len > cap or out == null) return HL_E_BUFFER;
    @memcpy(out.?[0..bytes.len], bytes);
    return HL_OK;
}

export fn hl_signer_public_key(s: *const narinfo.Signer, out: ?[*]u8, cap: usize, out_len: *usize) c_int {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    s.publicKey(&list, gpa) catch |e| return code(e);
    return copyOut(list.items, out, cap, out_len);
}

/// A detached signature over `msg`, as `<name>:<base64>`.
export fn hl_signer_sign(s: *const narinfo.Signer, msg: ?[*]const u8, msg_len: usize, out: ?[*]u8, cap: usize, out_len: *usize) c_int {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const m: []const u8 = if (msg) |p| p[0..msg_len] else "";
    s.sign(&list, gpa, m) catch |e| return code(e);
    return copyOut(list.items, out, cap, out_len);
}

pub const Str = extern struct {
    ptr: ?[*]const u8,
    len: usize,

    fn slice(self: Str) []const u8 {
        return if (self.ptr) |p| p[0..self.len] else "";
    }
};

pub const NarinfoInput = extern struct {
    store_path: Str,
    nar_hash: *const [32]u8,
    nar_size: u64,
    file_hash: *const [32]u8,
    file_size: u64,
    compression: Str,
    references: Str,
    deriver: Str,
    system: Str,
};

/// Renders into a heap buffer released with hl_free.
export fn hl_narinfo_render(in: *const NarinfoInput, signer: ?*const narinfo.Signer, out: *?[*]u8, out_len: *usize) c_int {
    const text = narinfo.render(gpa, .{
        .store_path = in.store_path.slice(),
        .nar_hash = in.nar_hash,
        .nar_size = in.nar_size,
        .file_hash = in.file_hash,
        .file_size = in.file_size,
        .compression = in.compression.slice(),
        .references = in.references.slice(),
        .deriver = in.deriver.slice(),
        .system = in.system.slice(),
    }, signer) catch |e| return code(e);
    out.* = text.ptr;
    out_len.* = text.len;
    return HL_OK;
}

export fn hl_free(ptr: ?[*]u8, len: usize) void {
    if (ptr) |p| gpa.free(p[0..len]);
}


// ── Small primitives for the Rust side (keeps hmac/sha2/uuid crates out) ──

const builtin = @import("builtin");

export fn hl_sha256(data: [*]const u8, len: usize, out: *[32]u8) void {
    archive.Sha256.hash(data[0..len], out, .{});
}

export fn hl_hmac_sha256(key: [*]const u8, key_len: usize, msg: [*]const u8, msg_len: usize, out: *[32]u8) void {
    std.crypto.auth.hmac.sha2.HmacSha256.create(out, msg[0..msg_len], key[0..key_len]);
}

/// Fills `buf` from the OS CSPRNG.
export fn hl_random(buf: [*]u8, len: usize) c_int {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var off: usize = 0;
        while (off < len) {
            const rc = linux.getrandom(buf + off, len - off, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => off += rc,
                .INTR => {},
                else => return HL_E_IO,
            }
        }
    } else {
        std.c.arc4random_buf(buf, len);
    }
    return HL_OK;
}

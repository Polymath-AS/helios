//! Constant-time fixed-base scalar multiplication for Ed25519 signing, using
//! the comb method from ref10 (SUPERCOP's ge_scalarmult_base):
//!
//!   s = sum e_i 16^i, e_i in [-8, 8]
//!   s*B = sum_{odd i} e_i 16^i B  * 16  +  sum_{even i} e_i 16^i B
//!
//! with a table of j * 256^k * B (j = 1..8, k = 0..31) in affine "Niels"
//! form. That is 64 mixed additions and 4 doublings, against 252 doublings
//! and 64 additions for std's 4-bit window. Table entries are selected with
//! conditional moves over all 8 candidates, so memory access and timing do
//! not depend on the (secret) scalar.

const std = @import("std");
const Curve = std.crypto.ecc.Edwards25519;
const Fe = Curve.Fe;

const Niels = struct {
    yplusx: Fe,
    yminusx: Fe,
    xy2d: Fe,

    const identity: Niels = .{ .yplusx = Fe.one, .yminusx = Fe.one, .xy2d = Fe.zero };

    fn fromPoint(p: Curve) Niels {
        const zinv = p.z.invert();
        const x = p.x.mul(zinv);
        const y = p.y.mul(zinv);
        return .{ .yplusx = y.add(x), .yminusx = y.sub(x), .xy2d = x.mul(y).mul(Fe.edwards25519d2) };
    }

    fn cMov(self: *Niels, other: Niels, c: u64) void {
        self.yplusx.cMov(other.yplusx, c);
        self.yminusx.cMov(other.yminusx, c);
        self.xy2d.cMov(other.xy2d, c);
    }
};

pub const Table = [32][8]Niels;

/// Builds the comb table for the Ed25519 base point (~1 ms; do it once).
pub fn table() Table {
    var t: Table = undefined;
    var base = Curve.basePoint;
    for (0..32) |k| {
        var acc = base;
        for (0..8) |j| {
            t[k][j] = Niels.fromPoint(acc);
            acc = acc.add(base);
        }
        for (0..8) |_| base = base.dbl();
    }
    return t;
}

/// Mixed addition: p + q with q affine (ref10 ge_madd), 7 multiplications.
fn madd(p: Curve, q: Niels) Curve {
    const a = p.y.sub(p.x).mul(q.yminusx);
    const b = p.y.add(p.x).mul(q.yplusx);
    const c = p.t.mul(q.xy2d);
    const d = p.z.add(p.z);
    const x = b.sub(a);
    const y = b.add(a);
    const z = d.add(c);
    const t = d.sub(c);
    return .{ .x = x.mul(t), .y = y.mul(z), .z = z.mul(t), .t = x.mul(y) };
}

fn select(row: *const [8]Niels, digit: i8) Niels {
    const negative: u8 = @intFromBool(digit < 0);
    const abs: u8 = @intCast(@as(i16, digit) * (1 - 2 * @as(i16, negative)));
    var out = Niels.identity;
    for (row, 1..) |entry, j| {
        const eq: u64 = ((@as(u64, abs ^ @as(u8, @intCast(j))) -% 1) >> 63) & 1;
        out.cMov(entry, eq);
    }
    // -(x, y) = (-x, y): swap y+x with y-x and negate 2dxy.
    const neg: Niels = .{ .yplusx = out.yminusx, .yminusx = out.yplusx, .xy2d = out.xy2d.neg() };
    out.cMov(neg, negative);
    return out;
}

/// s * B for a scalar `s` < 2^255 (already reduced mod L).
pub fn mulBase(t: *const Table, s: [32]u8) Curve {
    var e: [64]i8 = undefined;
    for (s, 0..) |byte, i| {
        e[2 * i] = @intCast(byte & 15);
        e[2 * i + 1] = @intCast(byte >> 4);
    }
    var carry: i8 = 0;
    for (e[0..63]) |*d| {
        d.* += carry;
        carry = (d.* + 8) >> 4;
        d.* -= carry << 4;
    }
    e[63] += carry;

    var h = Curve.identityElement;
    var i: usize = 1;
    while (i < 64) : (i += 2) h = madd(h, select(&t[i / 2], e[i]));
    h = h.dbl().dbl().dbl().dbl();
    i = 0;
    while (i < 64) : (i += 2) h = madd(h, select(&t[i / 2], e[i]));
    return h;
}

test "comb multiplication matches std for random scalars" {
    const t = table();
    var prng: std.Random.DefaultPrng = .init(5);
    for (0..300) |_| {
        var wide: [64]u8 = undefined;
        prng.random().bytes(&wide);
        const s = Curve.scalar.reduce64(wide);
        const expected = try Curve.basePoint.mul(s);
        try std.testing.expectEqualSlices(u8, &expected.toBytes(), &mulBase(&t, s).toBytes());
    }
}

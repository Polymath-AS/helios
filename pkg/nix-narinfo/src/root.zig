//! Narinfo: parsing, validated rendering, and fingerprint signing.

const render_mod = @import("render.zig");
const parse_mod = @import("parse.zig");

pub const Signer = render_mod.Signer;
pub const Input = render_mod.Input;
pub const RenderError = render_mod.Error;
pub const render = render_mod.render;

pub const NarInfo = parse_mod.NarInfo;
pub const ParseError = parse_mod.Error;
pub const parse = parse_mod.parse;

test {
    _ = render_mod;
    _ = parse_mod;
    _ = @import("basemul.zig");
}

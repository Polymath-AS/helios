//! Leveled logging to stderr, with journald priorities under systemd.
//! Same format as helios-server; HELIOS_LOG sets the level.

use std::sync::atomic::{AtomicU8, Ordering};

pub const ERROR: u8 = 3;
pub const WARN: u8 = 4;
pub const INFO: u8 = 6;
pub const DEBUG: u8 = 7;

static LEVEL: AtomicU8 = AtomicU8::new(INFO);
static JOURNAL: AtomicU8 = AtomicU8::new(0);

pub fn init() {
    let level = match std::env::var("HELIOS_LOG").as_deref() {
        Ok("error") => ERROR,
        Ok("warn") => WARN,
        Ok("debug") => DEBUG,
        _ => INFO,
    };
    LEVEL.store(level, Ordering::Relaxed);
    JOURNAL.store(u8::from(std::env::var_os("JOURNAL_STREAM").is_some()), Ordering::Relaxed);
}

pub fn enabled(level: u8) -> bool {
    level <= LEVEL.load(Ordering::Relaxed)
}

pub fn emit(level: u8, args: std::fmt::Arguments<'_>) {
    let label = match level {
        ERROR => "error",
        WARN => "warn",
        INFO => "info",
        _ => "debug",
    };
    if JOURNAL.load(Ordering::Relaxed) == 1 {
        eprintln!("<{level}>{args}");
    } else {
        eprintln!("{label}: {args}");
    }
}

macro_rules! log {
    ($level:expr, $($arg:tt)*) => {
        if $crate::log::enabled($level) {
            $crate::log::emit($level, format_args!($($arg)*));
        }
    };
}
macro_rules! error { ($($arg:tt)*) => { $crate::log::log!($crate::log::ERROR, $($arg)*) }; }
macro_rules! warning { ($($arg:tt)*) => { $crate::log::log!($crate::log::WARN, $($arg)*) }; }
macro_rules! info { ($($arg:tt)*) => { $crate::log::log!($crate::log::INFO, $($arg)*) }; }

pub(crate) use {error, info, log, warning};

//! Logging setup shared by the helios binaries, over `tracing`.
//!
//! `HELIOS_LOG` filters events: a level (`error`, `warn`, `info`, `debug`,
//! `trace`; default `info`), optionally with per-target directives such as
//! `info,helios_server=debug`. `HELIOS_LOG_FORMAT` picks the output:
//!
//! - `journald`: structured entries with priorities, event fields and span
//!   fields as journal fields. The default when stderr is the journal.
//! - `json`: one object per line on stderr, for container log collectors.
//! - `text`: human-readable lines on stderr. The default otherwise.

use std::io::IsTerminal;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{self, FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::{LookupSpan, Registry};
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// A long-running service: text lines carry a timestamp, level, spans
    /// and target.
    Service,
    /// A command run by hand: text lines are the message alone, prefixed
    /// with `warning:` or `error:` the way command-line tools report.
    Cli,
}

type Output = Box<dyn Layer<Registry> + Send + Sync>;

/// Installs the global subscriber. Call once, first thing in `main`.
pub fn init(style: Style) {
    let (filter, bad_filter) = match std::env::var("HELIOS_LOG") {
        Ok(spec) if !spec.trim().is_empty() => match spec.parse::<Targets>() {
            Ok(filter) => (filter, None),
            Err(e) => (default_filter(), Some(format!("ignoring HELIOS_LOG={spec:?}: {e}"))),
        },
        _ => (default_filter(), None),
    };

    let format = std::env::var("HELIOS_LOG_FORMAT").unwrap_or_default();
    let (output, fallback) = match format.as_str() {
        "json" => (json(), None),
        "text" => (text(style), None),
        "journald" => journald().map_or_else(|e| (text(style), Some(format!("journald unavailable, logging to stderr: {e}"))), |j| (j, None)),
        "" | "auto" if stderr_is_journal() => journald().map_or_else(|_| (text(style), None), |j| (j, None)),
        "" | "auto" => (text(style), None),
        other => (text(style), Some(format!("unknown HELIOS_LOG_FORMAT {other:?}; expected text, json or journald"))),
    };

    let _ = tracing_subscriber::registry().with(output.with_filter(filter)).try_init();
    for problem in [bad_filter, fallback].into_iter().flatten() {
        tracing::warn!("{problem}");
    }
}

/// Whether stderr is the journal: systemd sets JOURNAL_STREAM to its
/// `device:inode`, but children inherit the variable, such as a shell
/// started from a service, so only a match counts.
fn stderr_is_journal() -> bool {
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    let Some((dev, ino)) = std::env::var("JOURNAL_STREAM").ok().and_then(|s| s.split_once(':').map(|(d, i)| (d.parse::<u64>(), i.parse::<u64>())))
    else {
        return false;
    };
    let Ok(stderr) = std::io::stderr().as_fd().try_clone_to_owned() else { return false };
    let Ok(meta) = std::fs::File::from(stderr).metadata() else { return false };
    dev == Ok(meta.dev()) && ino == Ok(meta.ino())
}

fn default_filter() -> Targets {
    Targets::new().with_default(LevelFilter::INFO)
}

fn journald() -> std::io::Result<Output> {
    Ok(Box::new(tracing_journald::layer()?))
}

fn json() -> Output {
    Box::new(fmt::layer().json().flatten_event(true).with_current_span(true).with_span_list(false).with_writer(std::io::stderr))
}

fn text(style: Style) -> Output {
    let ansi = std::io::stderr().is_terminal();
    match style {
        Style::Service => Box::new(fmt::layer().with_ansi(ansi).with_writer(std::io::stderr)),
        Style::Cli => Box::new(fmt::layer().event_format(CliFormat).with_ansi(ansi).with_writer(std::io::stderr)),
    }
}

/// `message key=value`, with a level prefix except on `info`.
struct CliFormat;

impl<S, N> FormatEvent<S, N> for CliFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(&self, ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> std::fmt::Result {
        match *event.metadata().level() {
            Level::ERROR => write!(writer, "error: ")?,
            Level::WARN => write!(writer, "warning: ")?,
            Level::INFO => {}
            Level::DEBUG => write!(writer, "debug: ")?,
            Level::TRACE => write!(writer, "trace: ")?,
        }
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

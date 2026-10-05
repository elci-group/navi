//! `realm` — compile a Navi state document into the cyber-realm and render it.

use clap::{Parser, Subcommand, ValueEnum};
use navi_graph::{LoadError, SemanticGraph};
use realm_core::{Primitive, Realm, GRAMMAR_VERSION};
use std::path::PathBuf;
use std::process::ExitCode;

/// Stdout that tolerates a closed pipe (`navi … | head`): a reader going
/// away is not an error worth panicking over.
macro_rules! out {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = write!(std::io::stdout().lock(), $($t)*);
    }};
}
macro_rules! outln {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), $($t)*);
    }};
}

#[derive(Parser)]
#[command(
    name = "realm",
    version,
    about = "The Navi cyber-realm (Phase 1: deterministic 2D realm)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Svg,
    Html,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Compile a navi state document into Realm IR (JSON).
    Compile {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate Realm IR as a renderer would before drawing it.
    Check { file: PathBuf },
    /// Render a state document or Realm IR.
    Render {
        file: PathBuf,
        #[arg(short, long, value_enum, default_value = "text")]
        format: Format,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Navi's trajectory: each event, the route attention took, and the brief.
    Trace { file: PathBuf },
    /// The realm at one instant of an incident log (REWIND / STEP to any point).
    Replay {
        log: PathBuf,
        /// Instant in milliseconds; defaults to the latest.
        #[arg(long, allow_negative_numbers = true)]
        at: Option<i64>,
        #[arg(short, long, value_enum, default_value = "text")]
        format: Format,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// The security DVR: an HTML page with LIVE/PAUSE/STEP/REWIND/REPLAY/COMPARE.
    Dvr {
        log: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Snapshot + ordered deltas for clients (§22), with per-frame digests.
    Stream {
        log: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Rebuild every frame of a stream and verify each digest.
    Reconstruct { stream: PathBuf },
    /// What changed between two instants — or between reality and a branch.
    Compare {
        log: PathBuf,
        #[arg(allow_negative_numbers = true)]
        from: i64,
        #[arg(allow_negative_numbers = true)]
        to: i64,
        /// Take the `to` state from this (counterfactual) branch log instead.
        #[arg(long)]
        against: Option<PathBuf>,
    },
    /// Print the realm grammar (§3).
    Grammar,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(1)
}

/// Accept either a navi state document (compiled here) or Realm IR.
fn read_log(file: &PathBuf) -> Result<navi_events::IncidentLog, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    navi_events::IncidentLog::from_json(&text)
        .map_err(|e| format!("{}: not an incident log: {e}", file.display()))
}

fn replay(file: &PathBuf) -> Result<realm_replay::Replay, String> {
    let log = read_log(file)?;
    realm_replay::Replay::build(&log).map_err(|v| {
        let lines: Vec<String> = v.iter().map(|x| format!("  {x}")).collect();
        format!(
            "{}: incident log invalid; refusing to replay\n{}",
            file.display(),
            lines.join("\n")
        )
    })
}

/// Accept a navi state document or incident log (compiled here), or Realm IR.
fn load(file: &PathBuf) -> Result<Realm, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    if value.get("grammar_version").is_some() {
        return serde_json::from_value(value)
            .map_err(|e| format!("{}: not Realm IR: {e}", file.display()));
    }
    if value.get("log_version").is_some() {
        let r = replay(file)?;
        return r
            .frames
            .last()
            .map(|f| f.realm.clone())
            .ok_or_else(|| format!("{}: empty incident log", file.display()));
    }
    let g = SemanticGraph::from_json(&text).map_err(|e| match e {
        LoadError::Invalid(v) => {
            let lines: Vec<String> = v.iter().map(|x| format!("  {x}")).collect();
            format!(
                "{}: semantic graph invalid; refusing to compile\n{}",
                file.display(),
                lines.join("\n")
            )
        }
        e => format!("{}: {e}", file.display()),
    })?;
    Ok(realm_compiler::compile(&g))
}

fn emit(output: Option<PathBuf>, content: &str) -> ExitCode {
    match output {
        Some(p) => match std::fs::write(&p, content) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(format!("{}: {e}", p.display())),
        },
        None => {
            out!("{content}");
            ExitCode::SUCCESS
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Compile { file, output } => match load(&file) {
            Ok(r) => emit(
                output,
                &(serde_json::to_string_pretty(&r).expect("serializable") + "\n"),
            ),
            Err(e) => fail(e),
        },
        Command::Check { file } => match load(&file) {
            Ok(r) => {
                let v = r.validate();
                if v.is_empty() {
                    outln!(
                        "ok  {} ({}, {} entities, {} edges, {} hazards)",
                        file.display(),
                        r.grammar_version,
                        r.entities.len(),
                        r.edges.len(),
                        r.hazards.len()
                    );
                    ExitCode::SUCCESS
                } else {
                    eprintln!("refused  {}: {} violation(s)", file.display(), v.len());
                    for x in v {
                        eprintln!("  {x}");
                    }
                    ExitCode::from(1)
                }
            }
            Err(e) => fail(e),
        },
        Command::Render {
            file,
            format,
            output,
        } => {
            let realm = match load(&file) {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            let out = match format {
                Format::Text => realm_render::text(&realm),
                Format::Svg => realm_render::svg(&realm),
                Format::Html => realm_render::html(&realm),
                Format::Json => {
                    let l = realm_layout::layout(&realm);
                    match realm.validate().is_empty() {
                        true => Ok(serde_json::to_string_pretty(&l).expect("serializable") + "\n"),
                        false => Err(realm_render::Refused(realm.validate())),
                    }
                }
            };
            match out {
                Ok(s) => emit(output, &s),
                Err(e) => fail(e),
            }
        }
        Command::Trace { file } => match load(&file) {
            Ok(r) => match realm_render::trace(&r) {
                Ok(s) => emit(None, &s),
                Err(e) => fail(e),
            },
            Err(e) => fail(e),
        },
        Command::Replay {
            log,
            at,
            format,
            output,
        } => {
            let r = match replay(&log) {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            let frame = match at {
                Some(t) => r.at(navi_ontology::Timestamp(t)),
                None => r.frames.last(),
            };
            let Some(frame) = frame else {
                return fail(format!(
                    "{}: nothing had happened yet at that instant",
                    log.display()
                ));
            };
            let out = match format {
                Format::Text => realm_render::text(&frame.realm).map(|s| {
                    let lines: Vec<String> = frame.lines.iter().map(|l| format!("  {l}")).collect();
                    format!("AT {}\n{}\n\n{s}", frame.at, lines.join("\n"))
                }),
                Format::Svg => realm_render::svg(&frame.realm),
                Format::Html => realm_render::html(&frame.realm),
                Format::Json => {
                    Ok(serde_json::to_string_pretty(&frame.realm).expect("serializable") + "\n")
                }
            };
            match out {
                Ok(s) => emit(output, &s),
                Err(e) => fail(e),
            }
        }
        Command::Dvr { log, output } => match replay(&log) {
            Ok(r) => {
                let frames: Vec<realm_render::DvrFrame> = r
                    .frames
                    .iter()
                    .map(|f| realm_render::DvrFrame {
                        at: f.at,
                        lines: &f.lines,
                        realm: &f.realm,
                    })
                    .collect();
                match realm_render::dvr(&frames) {
                    Ok(s) => emit(output, &s),
                    Err(e) => fail(e),
                }
            }
            Err(e) => fail(e),
        },
        Command::Stream { log, output } => match replay(&log) {
            Ok(r) => emit(
                output,
                &(serde_json::to_string_pretty(&r.stream()).expect("serializable") + "\n"),
            ),
            Err(e) => fail(e),
        },
        Command::Reconstruct { stream } => {
            let s: realm_replay::Stream = match std::fs::read_to_string(&stream)
                .map_err(|e| e.to_string())
                .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
            {
                Ok(s) => s,
                Err(e) => return fail(format!("{}: {e}", stream.display())),
            };
            match realm_replay::reconstruct(&s) {
                Ok(frames) => {
                    let deltas: usize = s.frames.iter().map(|f| f.deltas.len()).sum();
                    outln!("ok  {}: {} frames rebuilt from 1 snapshot + {deltas} deltas, every digest matches", stream.display(), frames.len());
                    ExitCode::SUCCESS
                }
                Err(e) => fail(format!("reconstruction failed: {e}")),
            }
        }
        Command::Compare {
            log,
            from,
            to,
            against,
        } => {
            let base = match replay(&log) {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            let other = match &against {
                Some(b) => match replay(b) {
                    Ok(r) => {
                        let fork_of = r
                            .frames
                            .last()
                            .and_then(|f| f.realm.branch.as_ref())
                            .map(|x| x.fork_of.clone());
                        if fork_of.as_deref() != Some(base.log_digest.as_str()) {
                            return fail(format!(
                                "{} is not a branch forked from {}",
                                b.display(),
                                log.display()
                            ));
                        }
                        r
                    }
                    Err(e) => return fail(e),
                },
                None => base.clone(),
            };
            let (Some(a), Some(b)) = (
                base.at(navi_ontology::Timestamp(from)),
                other.at(navi_ontology::Timestamp(to)),
            ) else {
                return fail("one of the instants precedes the incident");
            };
            let label = |r: &realm_core::Realm| {
                r.branch
                    .as_ref()
                    .map_or("reality".to_string(), |b| format!("branch \"{}\"", b.label))
            };
            outln!(
                "COMPARE  A = {} at {}  ·  B = {} at {}",
                label(&a.realm),
                a.at,
                label(&b.realm),
                b.at
            );
            let changes = realm_replay::compare(&a.realm, &b.realm);
            if changes.is_empty() {
                outln!("  no differences");
            }
            for c in changes {
                let mark = match c.kind {
                    realm_replay::ChangeKind::Added => "+",
                    realm_replay::ChangeKind::Removed => "-",
                    realm_replay::ChangeKind::Changed => "~",
                };
                outln!("  {mark} {}", c.realm_id.trim_start_matches("realm:"));
                for d in c.details {
                    outln!("      {d}");
                }
            }
            ExitCode::SUCCESS
        }
        Command::Grammar => {
            outln!("{GRAMMAR_VERSION}");
            for p in Primitive::ALL {
                outln!(
                    "  {} {:<15} {}",
                    realm_core::contract::glyph(p),
                    realm_core::wire(&p),
                    p.meaning()
                );
            }
            ExitCode::SUCCESS
        }
    }
}

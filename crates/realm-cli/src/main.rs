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
    /// Print the realm grammar (§3).
    Grammar,
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(1)
}

/// Accept either a navi state document (compiled here) or Realm IR.
fn load(file: &PathBuf) -> Result<Realm, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    if value.get("grammar_version").is_some() {
        return serde_json::from_value(value)
            .map_err(|e| format!("{}: not Realm IR: {e}", file.display()));
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

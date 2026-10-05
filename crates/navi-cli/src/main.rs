//! `navi` — Phase 0 command line over canonical security-state documents.

use clap::{Parser, Subcommand};
use navi_graph::{LoadError, SemanticGraph};
use navi_ontology::{AuthorityLevel, AuthorityPolicy, ONTOLOGY_VERSION};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "navi",
    version,
    about = "Navi: provenance-preserving security state (Phase 0: ontology)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate a state document against every ontology and graph invariant.
    Validate {
        file: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the canonical digest (identical canonical state => identical digest).
    Digest { file: PathBuf },
    /// Print the canonical form of a document.
    Canonical { file: PathBuf },
    /// Reverse-resolve an object down to the raw observations behind it.
    Explain {
        file: PathBuf,
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the default production authority policy.
    Policy,
}

fn load(file: &PathBuf) -> Result<SemanticGraph, (String, Option<Vec<navi_graph::Violation>>)> {
    let text =
        std::fs::read_to_string(file).map_err(|e| (format!("{}: {e}", file.display()), None))?;
    SemanticGraph::from_json(&text).map_err(|e| match e {
        LoadError::Parse(p) => (format!("{}: rejected at parse: {p}", file.display()), None),
        LoadError::Invalid(v) => (
            format!("{}: {} violation(s)", file.display(), v.len()),
            Some(v),
        ),
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Validate { file, json } => match load(&file) {
            Ok(g) => {
                if json {
                    let out = serde_json::json!({
                        "valid": true, "ontology_version": ONTOLOGY_VERSION,
                        "digest": g.digest(), "counts": g.summary(),
                    });
                    println!("{out:#}");
                } else {
                    println!("valid  {}  ({ONTOLOGY_VERSION})", file.display());
                    println!("digest {}", g.digest());
                    for (k, n) in g.summary() {
                        println!("  {k:<14} {n}");
                    }
                }
                ExitCode::SUCCESS
            }
            Err((msg, violations)) => {
                if json {
                    let out = serde_json::json!({ "valid": false, "error": msg, "violations": violations.unwrap_or_default() });
                    println!("{out:#}");
                } else {
                    eprintln!("invalid {msg}");
                    for v in violations.unwrap_or_default() {
                        eprintln!("  {v}");
                    }
                }
                ExitCode::from(1)
            }
        },
        Command::Digest { file } => with_graph(&file, |g| println!("{}", g.digest())),
        Command::Canonical { file } => with_graph(&file, |g| println!("{}", g.canonical_json())),
        Command::Explain { file, id, json } => {
            let Ok(g) = load(&file) else {
                return with_graph(&file, |_| ());
            };
            match g.explain(&id) {
                Some(tree) if json => println!(
                    "{}",
                    serde_json::to_string_pretty(&tree).expect("serializable")
                ),
                Some(tree) => print!("{}", tree.render()),
                None => {
                    eprintln!("no object {id:?} in {}", file.display());
                    return ExitCode::from(2);
                }
            }
            ExitCode::SUCCESS
        }
        Command::Policy => {
            let p = AuthorityPolicy::default_production();
            println!("authority policy {}", p.version);
            for l in AuthorityLevel::ALL {
                let mark = if l.mutates_reality() {
                    "mutates"
                } else {
                    "reads"
                };
                println!("  {:<24} {:<8} {}", wire(&l), mark, wire(&p.gate(l)));
            }
            ExitCode::SUCCESS
        }
    }
}

fn with_graph(file: &PathBuf, f: impl FnOnce(&SemanticGraph)) -> ExitCode {
    match load(file) {
        Ok(g) => {
            f(&g);
            ExitCode::SUCCESS
        }
        Err((msg, violations)) => {
            eprintln!("invalid {msg}");
            for v in violations.unwrap_or_default() {
                eprintln!("  {v}");
            }
            ExitCode::from(1)
        }
    }
}

fn wire<T: serde::Serialize>(t: &T) -> String {
    serde_json::to_value(t)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "?".into())
}

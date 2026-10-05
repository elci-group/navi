//! `navi` — Phase 0 command line over canonical security-state documents.

use clap::{Parser, Subcommand};
use navi_graph::{LoadError, SemanticGraph};
use navi_ontology::{AuthorityLevel, AuthorityPolicy, ONTOLOGY_VERSION};
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
    /// Explain an agent at one of its events: where, why, what, confidence, next.
    Brief {
        file: PathBuf,
        agent: String,
        /// Event sequence number (default: latest).
        #[arg(long)]
        at: Option<u64>,
        /// Brief every event in order.
        #[arg(long, conflicts_with = "at")]
        all: bool,
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
                    outln!("{out:#}");
                } else {
                    outln!("valid  {}  ({ONTOLOGY_VERSION})", file.display());
                    outln!("digest {}", g.digest());
                    for (k, n) in g.summary() {
                        outln!("  {k:<14} {n}");
                    }
                }
                ExitCode::SUCCESS
            }
            Err((msg, violations)) => {
                if json {
                    let out = serde_json::json!({ "valid": false, "error": msg, "violations": violations.unwrap_or_default() });
                    outln!("{out:#}");
                } else {
                    eprintln!("invalid {msg}");
                    for v in violations.unwrap_or_default() {
                        eprintln!("  {v}");
                    }
                }
                ExitCode::from(1)
            }
        },
        Command::Digest { file } => with_graph(&file, |g| outln!("{}", g.digest())),
        Command::Canonical { file } => with_graph(&file, |g| outln!("{}", g.canonical_json())),
        Command::Explain { file, id, json } => {
            let Ok(g) = load(&file) else {
                return with_graph(&file, |_| ());
            };
            match g.explain(&id) {
                Some(tree) if json => outln!(
                    "{}",
                    serde_json::to_string_pretty(&tree).expect("serializable")
                ),
                Some(tree) => out!("{}", tree.render()),
                None => {
                    eprintln!("no object {id:?} in {}", file.display());
                    return ExitCode::from(2);
                }
            }
            ExitCode::SUCCESS
        }
        Command::Brief {
            file,
            agent,
            at,
            all,
            json,
        } => {
            let Ok(g) = load(&file) else {
                return with_graph(&file, |_| ());
            };
            let Ok(id) = navi_ontology::AgentId::new(agent.clone()) else {
                eprintln!("{agent:?} is not an agent id (agent:...)");
                return ExitCode::from(2);
            };
            let seqs: Vec<Option<u64>> = if all {
                g.agent_seqs(&id).into_iter().map(Some).collect()
            } else {
                vec![at]
            };
            let mut briefs = vec![];
            for s in seqs {
                match g.brief(&id, s) {
                    Some(b) => briefs.push(b),
                    None => {
                        eprintln!(
                            "no event {} for {id} in {}",
                            s.map_or("(any)".into(), |s| format!("#{s}")),
                            file.display()
                        );
                        return ExitCode::from(2);
                    }
                }
            }
            if json {
                outln!(
                    "{}",
                    serde_json::to_string_pretty(&briefs).expect("serializable")
                );
            } else {
                let text: Vec<String> = briefs.iter().map(|b| b.render(&g)).collect();
                out!("{}", text.join("\n"));
            }
            ExitCode::SUCCESS
        }
        Command::Policy => {
            let p = AuthorityPolicy::default_production();
            outln!("authority policy {}", p.version);
            for l in AuthorityLevel::ALL {
                let mark = if l.mutates_reality() {
                    "mutates"
                } else {
                    "reads"
                };
                outln!("  {:<24} {:<8} {}", wire(&l), mark, wire(&p.gate(l)));
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

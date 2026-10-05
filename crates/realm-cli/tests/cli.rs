use std::path::PathBuf;
use std::process::Command;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn scenario(name: &str) -> String {
    fixtures()
        .join(format!("scenarios/{name}.json"))
        .display()
        .to_string()
}

fn realm(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_realm"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("realm-{}-{name}", std::process::id()))
}

#[test]
fn compile_check_render_pipeline() {
    let rir = tmp("rir.json");
    let (code, _, err) = realm(&[
        "compile",
        &scenario("repo-runtime"),
        "-o",
        rir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");
    let (code, out, _) = realm(&["check", rir.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(out.starts_with("ok"));
    // Rendering from the RIR and from the source document is identical.
    let (_, from_rir, _) = realm(&["render", rir.to_str().unwrap()]);
    let (_, from_doc, _) = realm(&["render", &scenario("repo-runtime")]);
    assert_eq!(from_rir, from_doc);
    assert!(from_doc.contains("?SUSPICIOUS"));
    assert!(from_doc.contains("actor ? → api-5d2b-2"));
    std::fs::remove_file(rir).ok();
}

#[test]
fn tampered_rir_is_refused_by_check_and_render() {
    let (_, json, _) = realm(&["compile", &scenario("repo-runtime")]);
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    for h in v["hazards"].as_array_mut().unwrap() {
        h["semantic_type"] = serde_json::json!("enemy");
    }
    let bad = tmp("bad.json");
    std::fs::write(&bad, v.to_string()).unwrap();
    let (code, _, err) = realm(&["check", bad.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("SemanticMismatch"));
    for fmt in ["text", "svg", "json"] {
        let (code, out, _) = realm(&["render", bad.to_str().unwrap(), "-f", fmt]);
        assert_eq!(code, 1, "{fmt} rendered a refused realm");
        assert!(out.is_empty());
    }
    std::fs::remove_file(bad).ok();
}

#[test]
fn invalid_state_is_never_compiled() {
    for entry in std::fs::read_dir(fixtures().join("adversarial")).unwrap() {
        let path = entry.unwrap().path().display().to_string();
        let (code, out, err) = realm(&["render", &path]);
        assert_eq!(code, 1, "{path}");
        assert!(out.is_empty());
        assert!(err.contains("refusing to compile"), "{err}");
    }
}

#[test]
fn svg_carries_provenance_on_every_element() {
    let (code, svg, _) = realm(&["render", &scenario("repo-runtime"), "-f", "svg"]);
    assert_eq!(code, 0);
    let (_, json, _) = realm(&["compile", &scenario("repo-runtime")]);
    let r: serde_json::Value = serde_json::from_str(&json).unwrap();
    for coll in ["entities", "edges", "controls", "hazards", "agents"] {
        for x in r[coll].as_array().unwrap() {
            let id = x["realm_id"].as_str().unwrap();
            assert!(
                svg.contains(&format!("data-realm-id=\"{id}\"")),
                "{id} not drawn"
            );
        }
    }
    // Every drawn group other than the universe frame names its sources.
    for g in svg.split("<g data-realm-id=").skip(1) {
        if g.starts_with("\"realm:universe\"") {
            continue;
        }
        let head = &g[..g.find('>').unwrap()];
        assert!(
            head.contains("data-source-ids=\"") && !head.contains("data-source-ids=\"\""),
            "{head}"
        );
        assert!(g.contains("<title>"), "{head}");
    }
}

#[test]
fn layouts_nest_and_never_overlap() {
    for name in ["credential-stuffing", "repo-runtime"] {
        let (_, json, _) = realm(&["compile", &scenario(name)]);
        let r: realm_core::Realm = serde_json::from_str(&json).unwrap();
        realm_layout::check(&r, &realm_layout::layout(&r)).unwrap();
    }
}

#[test]
fn grammar_lists_all_primitives() {
    let (code, out, _) = realm(&["grammar"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("realm-grammar/0.1"));
    assert_eq!(out.lines().count(), 1 + realm_core::Primitive::ALL.len());
}

#[test]
fn readme_sample_is_current() {
    // docs/realm-repo-runtime.svg is embedded in the README; it must be
    // exactly what the renderer produces today.
    let (_, svg, _) = realm(&["render", &scenario("repo-runtime"), "-f", "svg"]);
    let doc =
        std::fs::read_to_string(fixtures().join("../../docs/realm-repo-runtime.svg")).unwrap();
    assert!(svg == doc, "docs/realm-repo-runtime.svg is stale: regenerate with `realm render tests/fixtures/scenarios/repo-runtime.json -f svg -o docs/realm-repo-runtime.svg`");
}

#[test]
fn trace_shows_movement_and_briefs() {
    let (code, out, _) = realm(&["trace", &scenario("repo-runtime")]);
    assert_eq!(code, 0);
    assert!(out.contains("TRAJECTORY  LC-DEFENCE-01"));
    assert!(out.contains("move  api-5d2b-2 ─bridge(rel:pod2-egress)→ 203.0.113.47"));
    assert!(out.contains("NEXT        ACT → api-5d2b-2"));
}

#[test]
fn html_render_is_self_contained() {
    let (code, html, _) = realm(&["render", &scenario("credential-stuffing"), "-f", "html"]);
    assert_eq!(code, 0);
    assert!(html.starts_with("<!doctype html>"));
    assert!(
        !html.contains("src=\"http"),
        "page must not load remote resources"
    );
    assert!(html.contains("const DATA = {"));
}

fn log_fixture(name: &str) -> String {
    fixtures()
        .join(format!("logs/{name}.log.json"))
        .display()
        .to_string()
}

#[test]
fn replay_and_dvr_from_a_log() {
    let (code, out, _) = realm(&["replay", &log_fixture("repo-runtime"), "--at", "3200"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("AT t+3200ms"));
    assert!(out.contains("?ANOMALOUS"));
    let (code, html, _) = realm(&["dvr", &log_fixture("credential-stuffing")]);
    assert_eq!(code, 0);
    assert!(html.contains("SECURITY DVR"));
    let (code, _, err) = realm(&["replay", &log_fixture("repo-runtime"), "--at", "-1"]);
    assert_eq!(code, 1);
    assert!(err.contains("nothing had happened yet"));
}

#[test]
fn stream_then_reconstruct() {
    let out = tmp("stream.json");
    let (code, _, _) = realm(&[
        "stream",
        &log_fixture("repo-runtime"),
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0);
    let (code, msg, _) = realm(&["reconstruct", out.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(msg.contains("every digest matches"));
    std::fs::remove_file(out).ok();
}

#[test]
fn compare_against_a_branch_requires_its_parent() {
    let branch = fixtures()
        .join("forks/repo-runtime-approve-isolation.branch.json")
        .display()
        .to_string();
    let (code, out, _) = realm(&[
        "compare",
        &log_fixture("repo-runtime"),
        "7100",
        "7100",
        "--against",
        &branch,
    ]);
    assert_eq!(code, 0);
    assert!(out.contains("action act:isolate: PROPOSED → VERIFIED"));
    let (code, _, err) = realm(&[
        "compare",
        &log_fixture("credential-stuffing"),
        "0",
        "0",
        "--against",
        &branch,
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("is not a branch forked from"));
}

#[test]
fn attention_view_from_the_cli() {
    let (code, out, _) = realm(&["render", &scenario("token-theft"), "--lod", "attention"]);
    assert_eq!(code, 0);
    assert!(out.contains("VIEW   attention payments-gateway"));
    assert!(out.contains("LENS   iam"));
    let (code, json, _) = realm(&[
        "render",
        &scenario("repo-runtime"),
        "--lod",
        "attention",
        "-f",
        "json",
    ]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["focus"][0], "realm:ent:api-pod-2");
    let (code, _, err) = realm(&[
        "render",
        &scenario("repo-runtime"),
        "--lod",
        "attention",
        "--focus",
        "ent:nope",
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("not in this realm"));
    let (code, out, _) = realm(&[
        "replay",
        &log_fixture("repo-runtime"),
        "--at",
        "3200",
        "--lod",
        "attention",
        "--depth",
        "1",
    ]);
    assert_eq!(code, 0);
    assert!(out.starts_with("AT t+3200ms"));
    assert!(out.contains("VIEW"));
}

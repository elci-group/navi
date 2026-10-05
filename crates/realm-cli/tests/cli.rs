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

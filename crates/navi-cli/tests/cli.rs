use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn navi(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_navi"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scenario() -> String {
    root()
        .join("scenarios/credential-stuffing.json")
        .display()
        .to_string()
}

#[test]
fn validate_accepts_scenario() {
    let (code, out, _) = navi(&["validate", &scenario(), "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["valid"], true);
    assert!(v["digest"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn every_adversarial_fixture_is_rejected() {
    let dir = root().join("adversarial");
    let mut n = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path().display().to_string();
        let (code, out, _) = navi(&["validate", &path, "--json"]);
        assert_eq!(code, 1, "{path} was accepted");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["valid"], false);
        assert!(!v["violations"].as_array().unwrap().is_empty(), "{path}");
        n += 1;
    }
    assert!(n >= 4);
}

#[test]
fn digest_is_stable_across_canonicalisation() {
    let (_, d1, _) = navi(&["digest", &scenario()]);
    let (_, canon, _) = navi(&["canonical", &scenario()]);
    let tmp = std::env::temp_dir().join(format!("navi-canon-{}.json", std::process::id()));
    std::fs::write(&tmp, canon).unwrap();
    let (code, d2, _) = navi(&["digest", tmp.to_str().unwrap()]);
    std::fs::remove_file(&tmp).ok();
    assert_eq!(code, 0);
    assert_eq!(d1, d2);
}

#[test]
fn explain_descends_to_raw_observations() {
    let (code, out, _) = navi(&["explain", &scenario(), "thr:stuffing"]);
    assert_eq!(code, 0);
    assert!(out.contains("[hypothesis] hyp:cred-stuffing"));
    assert!(out.contains("[observation] obs:req-rate"));
    let (code, _, _) = navi(&["explain", &scenario(), "thr:nonexistent"]);
    assert_eq!(code, 2);
}

#[test]
fn brief_explains_navi_headlessly() {
    let f = root()
        .join("scenarios/repo-runtime.json")
        .display()
        .to_string();
    let (code, out, _) = navi(&["brief", &f, "agent:navi-01"]);
    assert_eq!(code, 0);
    for k in ["WHERE", "WHY", "WHAT", "CONFIDENCE", "NEXT"] {
        assert!(out.contains(k), "{k} missing");
    }
    let (code, out, _) = navi(&["brief", &f, "agent:navi-01", "--all", "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 7);
    let (code, _, _) = navi(&["brief", &f, "agent:navi-01", "--at", "42"]);
    assert_eq!(code, 2);
}

#[test]
fn log_derive_check_dvr_fork() {
    let snap = root()
        .join("scenarios/credential-stuffing.json")
        .display()
        .to_string();
    let out = std::env::temp_dir().join(format!("navi-log-{}.json", std::process::id()));
    let (code, _, notes) = navi(&["log", "derive", &snap, "-o", out.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(notes.contains("note  ent:public-auth: split"));
    let (code, ok, _) = navi(&["log", "check", out.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(ok.contains("every prefix valid"));
    let (code, dvr, _) = navi(&["log", "dvr", out.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert!(dvr.contains("act:shield verified"));
    std::fs::remove_file(&out).ok();

    let base = root()
        .join("logs/repo-runtime.log.json")
        .display()
        .to_string();
    let spec = root()
        .join("forks/repo-runtime-approve-isolation.json")
        .display()
        .to_string();
    let (code, branch, _) = navi(&["log", "fork", &base, &spec]);
    assert_eq!(code, 0);
    assert!(branch.contains("\"branch\""));
    let (code, state, _) = navi(&["log", "at", &base, "3200"]);
    assert_eq!(code, 0);
    assert!(state.contains("\"hyp:c2\""));
}

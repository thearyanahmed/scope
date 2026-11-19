#![allow(clippy::unwrap_used)]
use std::process::Command;

fn fixture() -> String {
    format!("{}/../fixtures/host/two-vms", env!("CARGO_MANIFEST_DIR"))
}

fn scope(args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_scope")).args(args).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn once_json_against_fixture() {
    let v = scope(&["--root", &fixture(), "top", "--once", "--json", "--interval", "50ms"]);
    assert_eq!(v["header"]["vm_count"], 2);
    let vms = v["vms"].as_array().unwrap();
    assert_eq!(vms[1]["id"], "vm-b");
    assert_eq!(vms[1]["jailed"], true);
    // a static fixture has zero rates, but they must be measured, not missing.
    assert_eq!(vms[1]["cpu_pct"], 0.0);
    assert_eq!(vms[1]["vcpus"].as_array().unwrap().len(), 2);
    // 512 MiB of 576 MiB memory.max
    assert_eq!(vms[1]["level"], "warn");
}

#[test]
fn record_then_replay_gives_same_rows() {
    let dir = tempfile::tempdir().unwrap();
    let rec = dir.path().join("s.jsonl");
    let rec = rec.to_str().unwrap();
    let live = scope(&["--root", &fixture(), "top", "--once", "--json", "--interval", "50ms", "--record", rec]);
    let replayed = scope(&["top", "--once", "--json", "--replay", rec]);
    assert_eq!(live["vms"].as_array().unwrap().len(), replayed["vms"].as_array().unwrap().len());
    assert_eq!(live["vms"][1]["rss_bytes"], replayed["vms"][1]["rss_bytes"]);
    // uptime needs a wall clock, which a replay does not have.
    assert!(replayed["vms"][0]["uptime_s"].is_null());
}

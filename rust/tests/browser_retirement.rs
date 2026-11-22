use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, process::Command};
use vorda::{
    domain::Package,
    scanner::feeds::{CFT, KEV, RELEASES},
    store::{asset, identity, now, Store},
};
#[test]
fn cli_retires_only_known_supported_fixed_chrome_advisory() {
    for mode in ["fresh", "offline", "stale-inventory", "future-advisory"] {
        let offline = mode == "offline";
        let t = tempfile::tempdir().unwrap();
        let project = t.path().join("project");
        fs::create_dir(&project).unwrap();
        let inventory = t.path().join("inventory.json");
        let state = t.path().join("state");
        let scope = identity(&json!([[project], false, false, false, inventory])).unwrap();
        let old:Package=serde_json::from_value(json!({"name":"chrome","version":"107.0.0.0","ecosystem":"Chromium","path":"/selected/chrome","scope":"runtime"})).unwrap();
        let mut current = old.clone();
        current.version = "110.0.0.0".into();
        fs::write(
            &inventory,
            json!({"status":"complete","observed":now()-if mode == "stale-inventory" {259200.0}else{0.0},"packages":[current]}).to_string(),
        )
        .unwrap();
        let mut s = Store::open(&state).unwrap();
        let rows=[("fixed",scope.as_str(),"CVE-2026-10001"), ("unsupported",scope.as_str(),"CVE-2026-10002"), ("historical",scope.as_str(),"CVE-2000-10003"), ("other-scope","unselected","CVE-2026-10001")].map(|(key,sc,id)|json!({"key":key,"asset":asset(&old).unwrap(),"package":old,"advisory":id,"scan_scope":sc,"title":key}).as_object().unwrap().clone());
        s.reconcile(&rows, &BTreeSet::new(), &[]).unwrap();
        drop(s);
        let cache = state.join("cache");
        fs::create_dir_all(cache.join("chromium")).unwrap();
        fs::write(cache.join("chromium/data.json"),json!({"nvd_at":now()+if mode == "future-advisory" {86400.0}else{0.0},"cves":[
      {"id":"CVE-2026-10001","applicability":"supported","ranges":[{"versionStartIncluding":"105.0.0.0","versionEndExcluding":"110.0.0.0"}]},
      {"id":"CVE-2026-10002","applicability":"unsupported","ranges":[{"versionEndExcluding":"110.0.0.0"}]}
    ]}).to_string()).unwrap();
        for (url, data) in [
            (KEV, json!({"vulnerabilities":[]})),
            (CFT, json!({})),
            (RELEASES, json!({})),
        ] {
            fs::write(
                cache.join(format!("{}.json", identity(&json!([url, null])).unwrap())),
                json!({"source_url":url,"checked":now(),"data":data}).to_string(),
            )
            .unwrap();
        }
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vorda"));
        cmd.env("VORDA_ADVISORIES", "online");
        cmd.arg("--state")
            .arg(&state)
            .args(["scan", "--json", "--root"])
            .arg(&project)
            .arg("--inventory-file")
            .arg(&inventory);
        if offline {
            cmd.arg("--offline");
        }
        let output = cmd.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["covered"], json!([]));
        let s = Store::open(&state).unwrap();
        let active = s.active().unwrap();
        for key in ["unsupported", "historical", "other-scope"] {
            assert!(active.iter().any(|f| f["key"] == key), "{key}");
        }
        assert_eq!(
            active.iter().any(|f| f["key"] == "fixed"),
            mode != "fresh",
            "{mode}"
        );
    }
}

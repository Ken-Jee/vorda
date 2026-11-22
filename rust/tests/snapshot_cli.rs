use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

fn invoke(root: &Path, paths: &[String], clock: &str) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args([
            "--state",
            root.join("state").to_str().unwrap(),
            "snapshot-read",
        ])
        .args(paths)
        .arg(clock)
        .env("HOME", root)
        .env("VORDA_HOME", root.join("unused-state"))
        .output()
        .unwrap();
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    assert!(!root.join("unused-state").exists());
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

fn inputs(root: &Path, bytes: &[Vec<u8>]) -> Vec<String> {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let p = root.join(format!("input-{i}.json"));
            fs::write(&p, b).unwrap();
            p.to_str().unwrap().to_owned()
        })
        .collect()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/snapshot-reader.json")).unwrap()
}

#[test]
fn scoped_command_and_unchanged_inputs() {
    let f = fixture();
    let selected = [
        "A-list",
        "A-count",
        "A-detail",
        "A-evidence",
        "denial-detail-record-b",
        "denial-detail-missing",
        "denial-evidence-evidence-b",
        "denial-evidence-missing",
        "package-absent",
        "widening",
        "cross-clause-no-union",
    ];
    for id in selected {
        let root = tempfile::tempdir().unwrap();
        let c = f["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap();
        let bytes: Vec<Vec<u8>> = vec![
            f["snapshots"][c["snapshot_index"].as_u64().unwrap() as usize]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
            f["grants"][c["grant_index"].as_u64().unwrap() as usize]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec(),
            c["query"].as_str().unwrap().as_bytes().to_vec(),
        ];
        let paths = inputs(root.path(), &bytes);
        let (code, actual) = invoke(root.path(), &paths, "1793898330");
        let expected = &c["expected"];
        assert_eq!(
            code,
            if expected.get("error").is_some() {
                2
            } else {
                0
            },
            "{id}"
        );
        if expected.get("error").is_some() {
            assert_eq!(&actual, expected, "{id}");
        } else {
            for (k, v) in expected.as_object().unwrap() {
                if !k.starts_with("forbidden_") {
                    assert_eq!(&actual[k], v, "{id}: {k}");
                }
            }
            assert!(!actual.to_string().contains("B-SENTINEL"), "{id}");
            assert_eq!(actual["global_clean"], false);
            assert_eq!(actual["fix_verified"], false);
        }
        assert!(!root.path().join("state").exists(), "{id}");
        for (path, before) in paths.iter().zip(&bytes) {
            assert_eq!(fs::read(path).unwrap(), *before, "{id}");
        }
    }
}

#[test]
fn bounded_file_failures_and_no_store_access() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("state"), b"state sentinel").unwrap();
    let f = fixture();
    let c = &f["cases"][0];
    let base: Vec<Vec<u8>> = vec![
        f["snapshots"][c["snapshot_index"].as_u64().unwrap() as usize]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
        f["grants"][c["grant_index"].as_u64().unwrap() as usize]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
        b"{\"op\":\"list\"}".to_vec(),
    ];
    for (i, limit, error) in [
        (0, 4 * 1024 * 1024, "integrity_failure"),
        (1, 64 * 1024, "invalid_grant"),
        (2, 16 * 1024, "invalid_query"),
    ] {
        for bad in [None, Some(b"{".to_vec()), Some(vec![b' '; limit + 1])] {
            let paths = inputs(root.path(), &base);
            match bad {
                None => fs::remove_file(&paths[i]).unwrap(),
                Some(b) => fs::write(&paths[i], b).unwrap(),
            }
            assert_eq!(
                invoke(root.path(), &paths, "1793898330"),
                (2, json!({"error": error, "data": null}))
            );
        }
    }
    let paths = inputs(root.path(), &base);
    assert_eq!(
        invoke(root.path(), &paths, "bad-clock"),
        (2, json!({"error":"invalid_query","data":null}))
    );
    assert_eq!(invoke(root.path(), &paths, "1793898330").0, 0);
    assert_eq!(
        fs::read(root.path().join("state")).unwrap(),
        b"state sentinel"
    );
}

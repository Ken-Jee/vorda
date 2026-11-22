use serde_json::{json, Value};
use vorda::snapshot::read;
fn cases() -> Vec<Value> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/snapshot-reader.json")).unwrap();
    fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .cloned()
        .map(|mut c| {
            c["snapshot"] =
                fixture["snapshots"][c["snapshot_index"].as_u64().unwrap() as usize].clone();
            c["grant"] = fixture["grants"][c["grant_index"].as_u64().unwrap() as usize].clone();
            c
        })
        .collect()
}
fn response(c: &Value) -> Value {
    read(
        c["snapshot"].as_str().unwrap().as_bytes(),
        c["grant"].as_str().unwrap().as_bytes(),
        c["query"].as_str().unwrap().as_bytes(),
        "1793898330",
    )
    .map(|v| serde_json::to_value(v).unwrap())
    .unwrap_or_else(|e| json!({"error":e,"data":null}))
}
fn assert_expected(actual: &Value, expected: &Value, case: &str) {
    let wire = serde_json::to_string(actual).unwrap();
    for (k, v) in expected.as_object().unwrap() {
        match k.as_str() {
            "forbidden_keys" => {
                fn absent(v: &Value, k: &str) -> bool {
                    match v {
                        Value::Object(m) => !m.contains_key(k) && m.values().all(|v| absent(v, k)),
                        Value::Array(a) => a.iter().all(|v| absent(v, k)),
                        _ => true,
                    }
                }
                for k in v.as_array().unwrap() {
                    assert!(
                        absent(actual, k.as_str().unwrap()),
                        "{case}: forbidden key {k}"
                    );
                }
            }
            "forbidden_text" | "forbidden_record_ids" => {
                for s in v.as_array().unwrap() {
                    assert!(
                        !wire.contains(s.as_str().unwrap()),
                        "{case}: forbidden text {s}"
                    );
                }
            }
            _ => assert_eq!(&actual[k], v, "{case}: {k}"),
        }
    }
    if expected.get("error").is_some() {
        assert_eq!(actual, expected, "{case}: diagnostic leak");
    } else {
        for k in [
            "contract_version",
            "effective_scope",
            "as_of",
            "snapshot_id",
            "snapshot_revision",
            "coverage_basis",
            "authorized_coverage",
            "warnings",
            "global_clean",
            "fix_verified",
        ] {
            assert!(actual.get(k).is_some(), "{case}: missing {k}");
        }
        assert_eq!(actual["global_clean"], false);
        assert_eq!(actual["fix_verified"], false);
        if case != "explicit-owner-snapshot" {
            assert!(!wire.contains("B-SENTINEL"), "{case}: B leaked");
        }
        if case == "A-count" {
            assert!(actual.get("record_ids").is_none());
        }
    }
}
#[test]
fn accepted_71_vectors() {
    let cases = cases();
    assert_eq!(cases.len(), 71);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        assert_expected(&response(&c), &c["expected"], id);
        println!("{id}: PASS");
    }
}
#[test]
fn malformed_limits_and_precedence() {
    let c = &cases()[0];
    let s = c["snapshot"].as_str().unwrap();
    let g = c["grant"].as_str().unwrap();
    for bad in [
        "{\"op\":\"list\",\"op\":\"count\"}".to_string(),
        " ".repeat(16385),
        "{\"op\":\"list\",\"unknown\":1}".to_string(),
        "{\"op\":\"list\",\"package\":false}".to_string(),
    ] {
        assert_eq!(
            read(s.as_bytes(), g.as_bytes(), bad.as_bytes(), "1793898330").unwrap_err(),
            vorda::snapshot::ReadError::InvalidQuery
        );
    }
    let duplicate = s.replacen("{", "{\"contract_version\":\"m0b-derived-1\",", 1);
    for bad in [duplicate, " ".repeat(4 * 1024 * 1024 + 1)] {
        assert_eq!(
            read(bad.as_bytes(), b"{}", b"{}", "1793898330").unwrap_err(),
            vorda::snapshot::ReadError::IntegrityFailure
        );
    }
    assert_eq!(
        read(s.as_bytes(), &vec![b' '; 65537], b"{}", "1793898330").unwrap_err(),
        vorda::snapshot::ReadError::InvalidGrant
    );
}

#[test]
fn cross_clause_policy_control() {
    let c = cases()
        .into_iter()
        .find(|c| c["id"] == "cross-clause-no-union")
        .unwrap();
    assert_expected(&response(&c), &c["expected"], "cross-clause-no-union");
}
#[test]
fn unknown_coverage_and_validation_before_output() {
    let mut c = cases().remove(0);
    let mut snapshot: Value = serde_json::from_str(c["snapshot"].as_str().unwrap()).unwrap();
    snapshot["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("coverage");
    c["snapshot"] = json!(snapshot.to_string());
    let result = response(&c);
    assert_eq!(
        result["records"][0]["coverage"]["inventory"],
        json!({"state":"unknown","reason":"producer_coverage_unavailable"})
    );
    assert_eq!(result["records"][0]["coverage"]["kev"], "unknown");
    assert!(result["records"][0]["coverage"]["epss"].is_null());
    snapshot["records"][3]["times"]["observed_at"]
        .as_object_mut()
        .unwrap()
        .remove("null_reason");
    c["snapshot"] = json!(snapshot.to_string());
    // Invalid data outside A's grant still invalidates the entire snapshot.
    assert_eq!(
        response(&c),
        json!({"error":"integrity_failure","data":null})
    );
}

#[test]
fn integrity_and_nondisclosure_controls() {
    let base = cases().remove(0);
    let original: Value = serde_json::from_str(base["snapshot"].as_str().unwrap()).unwrap();
    for defect in [
        "version",
        "catalog",
        "assessment",
        "false_fix",
        "false_clean",
        "wrong_time_type",
        "unknown_field",
    ] {
        let mut s = original.clone();
        match defect {
            "version" => s["contract_version"] = json!("unsupported"),
            "catalog" => {
                s["catalog_tuples"].as_array_mut().unwrap().pop();
            }
            "assessment" => s["assessment_bindings"][0]["input_sha256"] = json!("0".repeat(64)),
            "false_fix" => s["records"][3]["coverage"]["fix_verified"] = json!(true),
            "false_clean" => s["records"][3]["coverage"]["global_clean"] = json!(true),
            "wrong_time_type" => {
                s["records"][3]["times"]["observed_at"]["value"] = json!(1793898285)
            }
            "unknown_field" => s["records"][3]["unexpected"] = json!("B-SENTINEL"),
            _ => unreachable!(),
        }
        let mut c = base.clone();
        c["snapshot"] = json!(s.to_string());
        assert_eq!(
            response(&c),
            json!({"error":"integrity_failure","data":null}),
            "{defect}"
        );
    }
}

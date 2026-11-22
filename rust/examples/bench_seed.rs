//! Seeds a hub database for the skill bench through the hub's real ingest paths.
//!
//! `bench_seed FIXTURE.json DB WORKDIR` reads the `fixture` object of a scenario (synthetic data
//! only), enrolls its devices, delivers their saved findings over the version 1 path, upgrades the
//! hub to schema 2 and admits their native assessments. It prints the device ids the hub assigned
//! as JSON. Ages are seconds before the moment this program runs; the hub's own clock then
//! decides freshness. Reader grants are made afterwards with `vorda link reader-grant`.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
use vorda::{
    link::{
        native::{self, Admission, TrustedCapture},
        storage::Hub,
    },
    store::{capture, now, Store},
};

fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

fn canonical(v: &Value) -> Vec<u8> {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => json!(m
                .iter()
                .map(|(k, v)| (k, sorted(v)))
                .collect::<BTreeMap<_, _>>()),
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sorted(v)).unwrap()
}

fn secret(kind: &str, tag: &str) -> String {
    format!("synthetic-{kind}-{tag}-bench-fixture-only-0000000")
}

fn lock_text(packages: &Value) -> String {
    let mut map = serde_json::Map::new();
    for (name, version) in packages.as_object().into_iter().flatten() {
        map.insert(format!("node_modules/{name}"), json!({"version": version}));
    }
    json!({"lockfileVersion":3,"packages":map}).to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let spec: Value = serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    let db_path = Path::new(&args[2]);
    let work = Path::new(&args[3]);
    fs::create_dir_all(work).unwrap();
    let work = work.canonicalize().unwrap();
    let org = spec["org"].as_str().unwrap_or("org-bench");
    let t0 = now();
    let hub = Hub::open(db_path).unwrap();
    let mut ids: BTreeMap<String, Value> = BTreeMap::new();
    let devices = spec["devices"].as_array().unwrap();

    // Version 1 path: enroll each device and deliver its saved findings.
    for d in devices {
        let name = d["name"].as_str().unwrap();
        let site = d["site"].as_str().unwrap();
        hub.invite(&secret("invite", name), org, site, 600.0)
            .unwrap();
        let identity = hub
            .enroll(&secret("invite", name), &secret("ingest", name))
            .unwrap();
        if let Some(v1) = d.get("v1").filter(|v| !v.is_null()) {
            let age = v1["age_s"].as_f64().unwrap_or(60.0);
            let scope = v1["scope"].as_str().unwrap_or("project-a");
            let mut batch: Value =
                serde_json::from_str(include_str!("../../fixtures/link-v1.json")).unwrap();
            batch["device"] = identity["device"].clone();
            batch["generation"] = identity["generation"].clone();
            batch["scan"] = json!(uuid::Uuid::new_v4().to_string());
            batch["observed"] = json!(t0 - age);
            batch["coverage"] = json!({ scope: v1["coverage"].as_str().unwrap_or("complete") });
            batch["findings"] = json!(v1["findings"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .enumerate()
                .map(|(i, f)| json!({
                    "advisory": f["advisory"],
                    "ecosystem": f["ecosystem"].as_str().unwrap_or("npm"),
                    "key": format!("finding-{name}-{i}"),
                    "location": hash(format!("{name}-{i}").as_bytes()),
                    "name": f["name"],
                    "scope": scope,
                    "source": f["source"].as_str().unwrap_or("api.osv.dev"),
                    "version": f["version"].as_str().unwrap_or("1.0.0"),
                }))
                .collect::<Vec<_>>());
            hub.ingest(&secret("ingest", name), &batch).unwrap();
            // Receipt time is the hub's clock at ingest; age it as the scenario says.
            let db = rusqlite::Connection::open(db_path).unwrap();
            db.execute(
                "UPDATE devices SET received=? WHERE id=?",
                rusqlite::params![t0 - age, identity["device"].as_str().unwrap()],
            )
            .unwrap();
        }
        ids.insert(name.to_string(), identity);
    }

    // Native path: upgrade the hub, then admit each assessment in the order listed.
    native::migrate(db_path).unwrap();
    let mut sequences: BTreeMap<String, i64> = BTreeMap::new();
    for d in devices {
        let name = d["name"].as_str().unwrap();
        let site = d["site"].as_str().unwrap();
        let device = ids[name]["device"].as_str().unwrap();
        let generation = ids[name]["generation"].clone();
        for (n, nat) in d["native"].as_array().unwrap_or(&vec![]).iter().enumerate() {
            let scope = nat["scope"].as_str().unwrap_or("scope-1");
            let source = nat["source"].as_str().unwrap();
            let age = nat["age_s"].as_f64().unwrap_or(60.0);
            let sequence = sequences
                .entry(format!("{device}/{scope}/{source}"))
                .and_modify(|s| *s += 1)
                .or_insert(1);
            let binding = json!({"tenant":org,"site":site,"device":device,"generation":generation,"scope":scope,"source":source});
            let tag = format!("{name}-{scope}-{source}-{n}");
            let root = work.join(format!("root-{tag}"));
            fs::create_dir_all(&root).unwrap();
            let mut inputs = vec![];
            for input in nat["inputs"].as_array().unwrap() {
                let dir = input["dir"].as_str().unwrap();
                inputs.push(format!("{dir}/package-lock.json"));
                fs::create_dir_all(root.join(dir)).unwrap();
                // An input without packages is not written, so reading it fails: partial coverage.
                if let Some(packages) = input.get("packages").filter(|p| !p.is_null()) {
                    fs::write(
                        root.join(dir).join("package-lock.json"),
                        lock_text(packages),
                    )
                    .unwrap();
                }
            }
            let mut store = Store::open(&work.join(format!("producer-{tag}"))).unwrap();
            let request = json!({"token":format!("token-{tag}"),"binding":binding,"root":root,
                "inputs":inputs,"completed_at":format!("{:.4}", t0 - age),
                "observed_at":format!("{:.4}", t0 - age)});
            let outcome =
                capture::capture(&mut store, &serde_json::to_vec(&request).unwrap()).unwrap();
            let export = work.join(format!("export-{tag}.json"));
            capture::export(
                &mut store,
                outcome["snapshot_id"].as_str().unwrap(),
                &export,
            )
            .unwrap();
            let view: Value = serde_json::from_slice(&fs::read(export).unwrap()).unwrap();
            let evidence = view["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["assessment_id"] == outcome["assessment_id"])
                .and_then(|r| r["dimensions"]["evidence"].as_str())
                .unwrap()
                .to_string();
            let raw = view["retained_payload_utf8"][&evidence]
                .as_str()
                .unwrap()
                .to_string();
            let wire = canonical(
                &json!({"schema":2,"binding":binding,"sequence":*sequence,"evidence_id":evidence,
                "artifact_sha256":hash(raw.as_bytes()),"artifact_byte_length":raw.len(),"artifact_utf8":raw}),
            );
            let received = format!("{:.9}", t0 - age);
            Admission::open(
                db_path,
                vec![TrustedCapture {
                    binding,
                    evidence_id: evidence,
                    artifact_utf8: raw,
                }],
            )
            .unwrap()
            .admit_at(&wire, &received)
            .unwrap();
        }
    }
    println!("{}", json!({"seeded_at": t0, "devices": ids}));
}

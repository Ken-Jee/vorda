use serde_json::{json, Value};
use std::{
    io::{self, Read},
    path::Path,
};
use vorda::link::native::{self, Admission, TrustedCapture};
fn main() {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s).unwrap();
    let q: Value = serde_json::from_str(&s).unwrap();
    let started = std::time::Instant::now();
    let result = (|| -> vorda::Result<Value> {
        let path = Path::new(q["path"].as_str().unwrap());
        match q["op"].as_str().unwrap() {
            "v1-drain" => {
                let o = vorda::link::client::Outbox::open(path)?;
                Ok(json!(o.drain(
                    q["url"].as_str().unwrap(),
                    "fixture-credential",
                    None
                )?))
            }
            "v1-enqueue" => {
                let o = vorda::link::client::Outbox::open(path)?;
                Ok(o.enqueue(&q["batch"])?)
            }
            "migrate" => {
                native::migrate(path)?;
                Ok(json!(true))
            }
            "restore" => {
                native::restore(path)?;
                Ok(json!(true))
            }
            "ack" => {
                native::validate_ack(
                    q["request"].as_str().unwrap().as_bytes(),
                    q["ack"].as_str().unwrap().as_bytes(),
                )?;
                Ok(json!(true))
            }
            _ => {
                let cs = q["captures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| TrustedCapture {
                        binding: v["binding"].clone(),
                        evidence_id: v["evidence_id"].as_str().unwrap().into(),
                        artifact_utf8: v["artifact_utf8"].as_str().unwrap().into(),
                    })
                    .collect();
                let a = Admission::open(path, cs)?;
                let b = match q["op"].as_str().unwrap() {
                    "view" => a.saved_view(&q["binding"])?,
                    "http" => a.http_trial(q["request"].as_str().unwrap().as_bytes())?,
                    _ => a.admit_at(
                        q["request"].as_str().unwrap().as_bytes(),
                        q["clock"].as_str().unwrap_or("1793898320"),
                    )?,
                };
                Ok(json!(String::from_utf8(b).unwrap()))
            }
        }
    })();
    eprintln!(
        "{}",
        json!({"trial_api_elapsed_ns":started.elapsed().as_nanos().to_string()})
    );
    match result {
        Ok(v) => println!("{}", json!({"ok":v})),
        Err(e) => {
            println!("{}", json!({"error":e.message,"status":e.http_status}));
            std::process::exit(1)
        }
    }
}

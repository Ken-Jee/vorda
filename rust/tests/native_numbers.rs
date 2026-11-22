//! Only plain integers pass the native admission as numbers: a float, an exponent, `-0`, an
//! integer past `u64` or below `i64` min is refused with a 400, and an integer that fits `u64`
//! but not `i64` is refused with a 400 of its own, whichever field carries it.
use vorda::link::{
    native::{self, Admission},
    storage::Hub,
};

const BINDING: &str =
    r#"{"device":"d","generation":"g","scope":"s","site":"s","source":"x","tenant":"t"}"#;
const NOT_PLAIN: [&str; 5] = [
    "1.5",
    "1e2",
    "-0",
    "18446744073709551616",
    "-9223372036854775809",
];
// Fits `u64` but not `i64`: it takes the `visit_u64` path and `bounds` refuses it.
const U64_ONLY: &str = "9223372036854775808";
// How serde_json's `arbitrary_precision` spells a number inside a map; it is not a number here.
const PRIVATE_NUMBER: &str = r#"{"$serde_json::private::Number":"1"}"#;

fn admit(admission: &Admission, sequence: &str, revision: &str) -> (Option<u16>, String) {
    let artifact = format!(
        r#"{{"assessment_id":"a","binding":{BINDING},"capture_token":"c","coverage":[],"inputs":[],"legacy_import":false,"producer":{{"name":"p","source_pin":"s"}},"provider":null,"records":[],"revision":{revision},"times":{{}}}}"#
    );
    let artifact = serde_json::to_string(&artifact).unwrap();
    let request = format!(
        r#"{{"artifact_byte_length":0,"artifact_sha256":"0","artifact_utf8":{artifact},"binding":{BINDING},"evidence_id":"e","schema":2,"sequence":{sequence}}}"#
    );
    match admission.admit(request.as_bytes()) {
        Ok(_) => (None, "accepted".into()),
        Err(e) => (e.http_status, e.message),
    }
}

#[test]
fn only_plain_integers_pass_as_numbers() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("hub.db");
    Hub::open(&db).unwrap();
    native::migrate(&db).unwrap();
    let admission = Admission::open(&db, vec![]).unwrap();

    // A plain integer clears both number checks and is stopped later, by the empty artifact.
    assert_eq!(
        admit(&admission, "1", "1"),
        (Some(422), "zero_fresh".into())
    );

    for token in NOT_PLAIN {
        let request_level = admit(&admission, token, "1");
        assert_eq!(
            request_level,
            (Some(400), "noncanonical_request".into()),
            "sequence {token}"
        );
        let artifact_level = admit(&admission, "1", token);
        assert_eq!(
            artifact_level,
            (Some(400), "invalid_integer".into()),
            "revision {token}"
        );
    }

    for (sequence, revision) in [(U64_ONLY, "1"), ("1", U64_ONLY)] {
        assert_eq!(
            admit(&admission, sequence, revision),
            (Some(400), "invalid_number".into()),
            "sequence {sequence} revision {revision}"
        );
    }

    let spelled = admit(&admission, PRIVATE_NUMBER, "1");
    assert_eq!(spelled, (Some(400), "invalid_integer".into()));
    let spelled = admit(&admission, "1", PRIVATE_NUMBER);
    assert_eq!(spelled, (Some(400), "invalid_integer".into()));
}

//! Reader credentials and grants: a reader secret resolves to an `AuthorizedScope` that names the
//! organization-qualified sites and devices it may see, and to nothing else. Synthetic fixtures only.
mod common;
use common::*;

const READER_C: &str = "synthetic-reader-c-tests-only-000000";
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};
use vorda::fleet::auth::ReaderStore;

fn store_path(w: &World) -> String {
    format!("{}.readers", w.db.display())
}
fn link(db: &Path, args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args(["link", "--db", db.to_str().unwrap()])
        .args(args)
        .envs(envs.iter().copied())
        .output()
        .unwrap()
}
/// A well-formed next batch from `device`, so that only its credential can make an ingest fail.
fn next_batch(w: &World, device: &str) -> Value {
    let mut batch: Value = serde_json::from_str(include_str!("fixtures/link-v1.json")).unwrap();
    let snapshot = w.hub.snapshot(device).unwrap();
    batch["device"] = snapshot["device"]["id"].clone();
    batch["generation"] = snapshot["device"]["generation"].clone();
    batch["sequence"] = json!(99);
    batch["scan"] = json!(uuid::Uuid::new_v4().to_string());
    batch["observed"] = json!(vorda::store::now());
    batch
}
fn finding_count(w: &World, device: &str) -> usize {
    w.hub.snapshot(device).unwrap()["findings"]
        .as_array()
        .unwrap()
        .len()
}

#[test]
fn a_grant_resolves_to_its_organization_qualified_sites_and_listed_devices() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let whole_site = authorize(&w, READER_A).unwrap();
    assert_eq!(
        whole_site.sites().iter().cloned().collect::<Vec<_>>(),
        sites(&[(ORG, "site-a")]),
        "site-a of org-other is a different site"
    );
    assert!(whole_site.devices().is_none(), "every device of the site");

    grant(&w, READER_B, &["site-a", "site-b"], &[&w.a1], 3600.0);
    let listed = authorize(&w, READER_B).unwrap();
    assert_eq!(listed.sites().len(), 2);
    assert_eq!(
        listed.devices().unwrap().iter().collect::<Vec<_>>(),
        [&w.a1]
    );
}

#[test]
fn expired_revoked_and_unknown_credentials_are_refused_identically() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 0.05);
    let revoked = grant(&w, READER_B, &["site-a"], &[], 3600.0);
    assert!(authorize(&w, READER_B).is_ok());
    ReaderStore::open(&w.db).unwrap().revoke(&revoked).unwrap();
    // Observe expiry through the default product clock, rather than assuming a 150 ms
    // sleep advances wall time. Five seconds is a test guard for clock adjustments and
    // scheduling under load, not a longer credential TTL.
    let start = Instant::now();
    let expired = loop {
        match authorize(&w, READER_A) {
            Err(error) => break error,
            Ok(_) => {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "default clock never expired the reader"
                );
                thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let answers: Vec<_> = [
        expired,
        authorize(&w, READER_B).unwrap_err(),
        authorize(&w, "synthetic-never-granted-000000000000").unwrap_err(),
    ]
    .into_iter()
    .map(|e| (e.http_status, e.message))
    .collect();
    assert_eq!(answers[0].0, Some(401));
    assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");
}

#[test]
fn a_reader_expires_exactly_at_its_product_clock_deadline() {
    let w = world();
    let expiring = grant(&w, READER_A, &["site-a"], &[], 4.0);
    let (created, expires): (f64, f64) = rusqlite::Connection::open(store_path(&w))
        .unwrap()
        .query_row(
            "SELECT created,expires FROM readers WHERE id=?",
            [&expiring],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(expires - created, 4.0);
    let store = ReaderStore::open(&w.db).unwrap();
    assert!(store
        .authorize_with_clock(READER_A, || expires - 0.001)
        .is_ok());
    let at = store
        .authorize_with_clock(READER_A, || expires)
        .unwrap_err();
    let after = store
        .authorize_with_clock(READER_A, || expires + 1.0)
        .unwrap_err();
    assert_eq!(at.http_status, Some(401));
    assert_eq!(
        (at.http_status, at.message),
        (after.http_status, after.message)
    );
}

#[test]
fn ingest_and_reader_credentials_do_not_work_in_each_others_role() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    assert_eq!(
        authorize(&w, &ingest_secret("a1")).unwrap_err().http_status,
        Some(401)
    );
    assert_eq!(
        authorize(&w, &invite_secret("a1")).unwrap_err().http_status,
        Some(401)
    );

    assert_eq!(
        w.hub
            .ingest(READER_A, &next_batch(&w, &w.a1))
            .unwrap_err()
            .http_status,
        Some(401)
    );
    assert_eq!(finding_count(&w, &w.a1), 2);

    let one = sites(&[(ORG, "site-a")]);
    assert_eq!(
        try_grant(&w, &ingest_secret("a1"), &one, None, 60.0)
            .unwrap_err()
            .http_status,
        Some(400)
    );
    let pending = "synthetic-pending-invite-tests-0000";
    w.hub.invite(pending, ORG, "site-a", 600.0).unwrap();
    assert_eq!(
        try_grant(&w, pending, &one, None, 60.0)
            .unwrap_err()
            .http_status,
        Some(400)
    );
}

#[test]
fn the_store_never_holds_the_ingest_hash_of_a_reader_secret() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let stored: String = rusqlite::Connection::open(store_path(&w))
        .unwrap()
        .query_row("SELECT verifier FROM readers", [], |r| r.get(0))
        .unwrap();
    assert_ne!(stored, hash(READER_A.as_bytes()));
    assert!(!fs::read(store_path(&w))
        .unwrap()
        .windows(READER_A.len())
        .any(|p| p == READER_A.as_bytes()));
}

#[test]
fn one_secret_cannot_be_two_readers() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let again = try_grant(&w, READER_A, &sites(&[(ORG, "site-b")]), None, 3600.0);
    assert_eq!(again.unwrap_err().http_status, Some(400));
    let scope = authorize(&w, READER_A).unwrap();
    assert_eq!(scope.sites().len(), 1, "the first grant is unchanged");
}

#[test]
fn a_grant_must_name_real_sites_and_devices_inside_them_and_a_bounded_lifetime() {
    let w = world();
    let refused = |pairs: &[(&str, &str)], devices: &[&String], ttl: f64| {
        let listed: Vec<String> = devices.iter().map(|d| d.to_string()).collect();
        try_grant(
            &w,
            READER_A,
            &sites(pairs),
            (!listed.is_empty()).then_some(&listed[..]),
            ttl,
        )
        .unwrap_err()
        .http_status
    };
    assert_eq!(refused(&[], &[], 60.0), Some(400), "no wildcard grant");
    assert_eq!(refused(&[(ORG, "site-typo")], &[], 60.0), Some(400));
    assert_eq!(
        refused(&[("org-typo", "site-a")], &[], 60.0),
        Some(400),
        "the site exists, but not in that organization"
    );
    assert_eq!(
        refused(&[(ORG, "site-a")], &[&w.b1], 60.0),
        Some(400),
        "device belongs to another site"
    );
    assert_eq!(
        refused(&[(ORG, "site-a")], &[&w.x1], 60.0),
        Some(400),
        "device belongs to another organization"
    );
    assert_eq!(refused(&[(ORG, "site-a")], &[], 0.0), Some(400));
    assert_eq!(refused(&[(ORG, "site-a")], &[], 91.0 * 86400.0), Some(400));
    assert!(
        authorize(&w, READER_A).is_err(),
        "a refused grant leaves no reader behind"
    );
    assert!(
        !Path::new(&store_path(&w)).exists(),
        "a refused grant leaves no store behind"
    );
}

#[test]
fn an_empty_explicit_device_list_is_refused_instead_of_meaning_every_device() {
    let w = world();
    let refused = try_grant(&w, READER_A, &sites(&[(ORG, "site-a")]), Some(&[]), 3600.0);
    assert_eq!(refused.unwrap_err().http_status, Some(400));
    assert!(authorize(&w, READER_A).is_err());
}

#[test]
fn a_device_restricted_grant_that_lost_its_device_rows_names_no_devices_not_the_whole_site() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[&w.a1], 3600.0);
    assert_eq!(authorize(&w, READER_A).unwrap().devices().unwrap().len(), 1);

    let store = rusqlite::Connection::open(store_path(&w)).unwrap();
    store.execute("DELETE FROM reader_devices", []).unwrap();
    drop(store);

    let scope = authorize(&w, READER_A).unwrap();
    assert!(
        scope.devices().is_some_and(|d| d.is_empty()),
        "a lost row narrows the grant to nothing"
    );
}

#[test]
fn the_owner_cli_grants_and_revokes_a_reader_under_the_shared_hub_lock() {
    let w = world();
    let grant_args = [
        "reader-grant",
        "--reader-env",
        "SYNTHETIC_READER",
        "--label",
        "cli reader",
        "--org",
        ORG,
        "--site",
        "site-a",
        "--ttl",
        "3600",
    ];
    let envs = [("SYNTHETIC_READER", READER_A)];

    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(format!("{}.serve-lock", w.db.display()))
        .unwrap();
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    let blocked = link(&w.db, &grant_args, &envs);
    assert!(
        !blocked.status.success()
            && String::from_utf8_lossy(&blocked.stderr).contains("being migrated or restored")
    );
    drop(lock);
    assert!(authorize(&w, READER_A).is_err());

    let nothing = link(&w.db, &["reader-revoke", "--reader", "any"], &[]);
    assert!(String::from_utf8_lossy(&nothing.stderr).contains("no reader store for this hub"));

    let out = link(&w.db, &grant_args, &envs);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let printed = String::from_utf8(out.stdout).unwrap();
    assert!(!printed.contains(READER_A), "the secret is never printed");
    let reader = serde_json::from_str::<Value>(&printed).unwrap()["reader"]
        .as_str()
        .unwrap()
        .to_string();
    let scope = authorize(&w, READER_A).unwrap();
    assert_eq!(scope.reader(), reader);
    assert_eq!(
        scope.sites().iter().cloned().collect::<Vec<_>>(),
        sites(&[(ORG, "site-a")])
    );

    let out = link(&w.db, &["reader-revoke", "--reader", &reader], &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(authorize(&w, READER_A).unwrap_err().http_status, Some(401));
    let actions: Vec<String> = rusqlite::Connection::open(store_path(&w))
        .unwrap()
        .prepare("SELECT action FROM reader_audit WHERE reader=? ORDER BY at")
        .unwrap()
        .query_map([&reader], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(actions, ["grant", "revoke"]);

    let other_org = link(
        &w.db,
        &[
            "reader-grant",
            "--reader-env",
            "SYNTHETIC_READER",
            "--label",
            "other organization",
            "--org",
            "org-other",
            "--site",
            "site-a",
            "--ttl",
            "60",
        ],
        &[("SYNTHETIC_READER", READER_B)],
    );
    assert!(other_org.status.success());
    assert_eq!(
        authorize(&w, READER_B)
            .unwrap()
            .sites()
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        sites(&[("org-other", "site-a")])
    );

    let typo = link(
        &w.db,
        &[
            "reader-grant",
            "--reader-env",
            "SYNTHETIC_READER",
            "--label",
            "x",
            "--org",
            ORG,
            "--site",
            "site-typo",
            "--ttl",
            "60",
        ],
        &[("SYNTHETIC_READER", READER_C)],
    );
    assert!(!typo.status.success(), "a site the hub has never seen");
    let bare = link(
        &w.db,
        &[
            "reader-grant",
            "--reader-env",
            "SYNTHETIC_READER",
            "--label",
            "x",
            "--site",
            "site-a",
            "--ttl",
            "60",
        ],
        &[("SYNTHETIC_READER", READER_C)],
    );
    assert!(!bare.status.success(), "a bare site name is not a grant");
    assert!(authorize(&w, READER_C).is_err());
}

#[test]
fn the_owner_cannot_later_register_an_existing_reader_secret_as_an_ingest_secret() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);

    let invite = w.hub.invite(READER_A, ORG, "site-a", 600.0).unwrap_err();
    assert_eq!(invite.http_status, Some(400));
    let rotate = w.hub.rotate(&w.a1, READER_A, 60.0).unwrap_err();
    assert_eq!(rotate.http_status, Some(400));
    assert!(
        w.hub
            .enroll(READER_A, "synthetic-fresh-credential-000000000")
            .is_err(),
        "the refused secret was not stored as an invite"
    );
    assert_eq!(
        w.hub
            .ingest(READER_A, &next_batch(&w, &w.a1))
            .unwrap_err()
            .http_status,
        Some(401),
        "nor as a credential"
    );

    let local_invite = "synthetic-local-invite-tests-000000";
    w.hub.invite(local_invite, ORG, "site-a", 600.0).unwrap();
    let out = link(
        &w.db,
        &[
            "enroll-local",
            "--invite-env",
            "SYNTHETIC_INVITE",
            "--credential-env",
            "SYNTHETIC_CREDENTIAL",
        ],
        &[
            ("SYNTHETIC_INVITE", local_invite),
            ("SYNTHETIC_CREDENTIAL", READER_A),
        ],
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already a reader credential"),
        "enroll-local is an owner path too: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let id = authorize(&w, READER_A).unwrap().reader().to_string();
    ReaderStore::open(&w.db).unwrap().revoke(&id).unwrap();
    assert_eq!(
        w.hub
            .invite(READER_A, ORG, "site-a", 600.0)
            .unwrap_err()
            .http_status,
        Some(400),
        "a revoked reader's secret stays reserved"
    );

    // The network enrollment endpoint does not check: that would let any invite holder test
    // guesses against the reader secrets.
    let guess = "synthetic-guess-invite-tests-0000000";
    w.hub.invite(guess, ORG, "site-a", 600.0).unwrap();
    assert!(w.hub.enroll(guess, READER_B).is_ok());
}

#[test]
fn a_reader_store_belongs_to_one_hub_and_is_refused_beside_another() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    assert!(authorize(&w, READER_A).is_ok());

    // A different hub appears at the same path: the old grants name organizations and sites, and
    // must not start applying to its devices.
    let other = world();
    fs::copy(&other.db, &w.db).unwrap();
    assert_eq!(authorize(&w, READER_A).unwrap_err().http_status, Some(401));
    assert!(
        ReaderStore::create(&w.db).is_err(),
        "the owner is not silently re-bound either"
    );
}

#[test]
fn restoring_the_hubs_own_older_copy_keeps_its_readers() {
    let w = world();
    let older = w.db.with_extension("older");
    fs::copy(&w.db, &older).unwrap();
    enroll(&w.hub, ORG, "site-a", "late", &["finding-late"]);
    grant(&w, READER_A, &["site-a"], &[], 3600.0);

    fs::copy(&older, &w.db).unwrap();
    assert!(authorize(&w, READER_A).is_ok());
}

#[test]
fn a_store_of_another_layout_is_refused_with_an_error_that_names_the_file() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    rusqlite::Connection::open(store_path(&w))
        .unwrap()
        .pragma_update(None, "user_version", 1)
        .unwrap();
    for refused in [
        ReaderStore::open(&w.db).err().unwrap(),
        ReaderStore::create(&w.db).err().unwrap(),
    ] {
        assert!(
            refused.message.contains(&store_path(&w)),
            "{}",
            refused.message
        );
        assert!(refused.message.contains("remove it and grant again"));
    }
}

#[test]
fn an_empty_store_file_blocks_nothing_and_a_damaged_one_names_itself() {
    let w = world();
    // `create` leaves an empty file if it dies before the schema is written.
    fs::write(store_path(&w), b"").unwrap();
    w.hub
        .invite(
            "synthetic-invite-empty-tests-0000000000",
            ORG,
            "site-a",
            600.0,
        )
        .unwrap();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    assert!(
        authorize(&w, READER_A).is_ok(),
        "the next grant fills it in"
    );

    fs::write(store_path(&w), b"this is not a database".repeat(200)).unwrap();
    let refused = w
        .hub
        .invite(
            "synthetic-invite-damaged-tests-000000000",
            ORG,
            "site-a",
            600.0,
        )
        .unwrap_err();
    assert!(
        refused.message.contains(&store_path(&w)),
        "{}",
        refused.message
    );
}

#[cfg(unix)]
#[test]
fn the_reader_store_is_private_even_when_it_already_existed_with_wider_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let mode = || fs::metadata(store_path(&w)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(), 0o600);
    let opens: [fn(&World); 2] = [
        |w| {
            authorize(w, READER_A).unwrap();
        },
        |w| {
            grant(w, READER_B, &["site-a"], &[], 60.0);
        },
    ];
    for open in opens {
        fs::set_permissions(store_path(&w), fs::Permissions::from_mode(0o644)).unwrap();
        open(&w);
        assert_eq!(mode(), 0o600);
    }
}

#[test]
fn a_damaged_or_foreign_reader_store_never_authorizes_anyone() {
    let w = world();
    grant(&w, READER_A, &["site-a"], &[], 3600.0);
    let good = fs::read(store_path(&w)).unwrap();

    fs::write(store_path(&w), b"").unwrap();
    assert!(authorize(&w, READER_A).is_err(), "empty file");

    fs::write(store_path(&w), b"this is not a database".repeat(200)).unwrap();
    assert!(authorize(&w, READER_A).is_err(), "garbage");
    assert!(
        ReaderStore::create(&w.db).is_err(),
        "garbage is not silently replaced"
    );

    fs::write(store_path(&w), &good).unwrap();
    rusqlite::Connection::open(store_path(&w))
        .unwrap()
        .pragma_update(None, "user_version", 7)
        .unwrap();
    assert!(authorize(&w, READER_A).is_err(), "a newer store version");
    assert!(ReaderStore::create(&w.db).is_err());

    fs::write(store_path(&w), &good).unwrap();
    assert!(
        authorize(&w, READER_A).is_ok(),
        "the undamaged copy still works"
    );
}

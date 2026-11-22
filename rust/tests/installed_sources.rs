use serde_json::json;
use std::fs;
use vorda::{
    domain::InventoryOptions,
    scanner::{
        self,
        inventory::installed::{registry_inventory, RegistryEntry, RegistrySnapshot},
    },
};

#[test]
fn registry_views_keep_duplicate_names_and_unknown_versions_without_claiming_coverage() {
    let result = registry_inventory(&[
        RegistrySnapshot {
            hive: "HKCU".into(),
            view: 32,
            outcome: "complete".into(),
            entries: vec![RegistryEntry {
                key: "user-app".into(),
                name: "Same name".into(),
                version: "1.2.3".into(),
                publisher: "Publisher".into(),
                install_location: "C:\\Apps\\One".into(),
                errors: vec![],
            }],
            errors: vec![],
        },
        RegistrySnapshot {
            hive: "HKLM".into(),
            view: 64,
            outcome: "partial".into(),
            entries: vec![RegistryEntry {
                key: "machine-app".into(),
                name: "Same name".into(),
                version: "beta".into(),
                publisher: String::new(),
                install_location: String::new(),
                errors: vec![],
            }],
            errors: vec!["denied subkey".into()],
        },
        RegistrySnapshot {
            hive: "HKLM".into(),
            view: 32,
            outcome: "denied".into(),
            entries: vec![],
            errors: vec!["access denied".into()],
        },
        RegistrySnapshot {
            hive: "HKCU".into(),
            view: 64,
            outcome: "missing".into(),
            entries: vec![],
            errors: vec![],
        },
    ]);
    assert_eq!(result.packages.len(), 2);
    assert_ne!(result.packages[0].path, result.packages[1].path);
    assert_eq!(result.packages[0].extra["publisher"], "Publisher");
    assert_eq!(result.packages[1].version, "unknown");
    assert_eq!(result.packages[1].extra["raw_version"], "beta");
    assert_eq!(result.packages[0].extra["advisory_mapping"], "unsupported");
    assert_eq!(result.outcomes[1]["outcome"], "partial");
    assert_eq!(result.outcomes[2]["outcome"], "denied");
    assert_eq!(result.outcomes[3]["outcome"], "missing");
    let empty = registry_inventory(&[RegistrySnapshot {
        hive: "HKCU".into(),
        view: 32,
        outcome: "complete".into(),
        entries: vec![],
        errors: vec![],
    }]);
    assert!(empty.packages.is_empty());
    assert_eq!(empty.outcomes[0]["outcome"], "complete");
}

fn inventory(path: &std::path::Path) -> serde_json::Map<String, serde_json::Value> {
    scanner::inventory(&InventoryOptions {
        installed_roots: vec![path.into()],
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn selected_bundle_metadata_keeps_identity_and_missing_version_unknown() {
    let tmp = tempfile::tempdir().unwrap();
    let app = tmp.path().join("Example.app");
    fs::create_dir_all(app.join("Contents")).unwrap();
    let metadata = app.join("Contents/Info.plist");
    fs::write(&metadata, r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>org.example.app</string><key>CFBundleShortVersionString</key><string>2.3.4</string></dict></plist>"#).unwrap();
    let result = inventory(&app);
    assert_eq!(result["packages"][0]["name"], "org.example.app");
    assert_eq!(result["packages"][0]["version"], "2.3.4");
    assert_eq!(result["packages"][0]["presence"], "selected-bundle");
    assert_eq!(result["packages"][0]["advisory_mapping"], "unsupported");
    assert_eq!(result["source_outcomes"][0]["outcome"], "complete");
    fs::write(&metadata, r#"<plist version="1.0"><dict><key>CFBundleName</key><string>Example</string></dict></plist>"#).unwrap();
    let result = inventory(&app);
    assert_eq!(result["packages"][0]["version"], "unknown");
    assert_eq!(result["packages"][0]["version_evidence"], "unknown");
}

#[test]
fn selected_metadata_is_bounded_and_does_not_search_directories() {
    let tmp = tempfile::tempdir().unwrap();
    fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"selected-package","version":"1.2.3"}"#,
    )
    .unwrap();
    let result = inventory(tmp.path());
    assert_eq!(result["source_outcomes"][0]["outcome"], "unsupported");
    assert_eq!(result["packages"], json!([]));
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["completed_paths"], json!([]));
    let path = tmp.path().join("package.json");
    let result = inventory(&path);
    assert_eq!(result["packages"][0]["name"], "selected-package");
    assert_eq!(result["packages"][0]["presence"], "selected-metadata");
    assert_eq!(result["packages"][0]["ecosystem"], "npm");
    fs::write(&path, "not json").unwrap();
    let result = inventory(&path);
    assert_eq!(result["source_outcomes"][0]["outcome"], "malformed");
    assert_eq!(result["completed_paths"], json!([]));
    fs::write(&path, vec![b' '; 4_000_001]).unwrap();
    let result = inventory(&path);
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["completed_paths"], json!([]));
    fs::remove_file(&path).unwrap();
    let result = inventory(&path);
    assert_eq!(result["source_outcomes"][0]["outcome"], "missing");
    assert_eq!(
        result["input_evidence"]["observations"][0]["kind"],
        "observed-absence"
    );
}

#[test]
fn selected_non_distro_and_environment_metadata_preserves_source_limits() {
    let tmp = tempfile::tempdir().unwrap();
    for (filename, text, expected) in [
        (
            "metadata",
            "[Application]\nname=org.example.App\nruntime=org.example.Platform/x86_64/24.08\n",
            vec![
                ("org.example.App", "unknown", "Flatpak"),
                (
                    "org.example.Platform/x86_64/24.08",
                    "unknown",
                    "Flatpak runtime",
                ),
            ],
        ),
        (
            "snap.yaml",
            "name: example-snap\nversion: '3.1'\n",
            vec![("example-snap", "3.1", "Snap")],
        ),
        (
            "manifest.json",
            r#"{"version":2,"elements":{"example":{"active":true,"storePaths":["/nix/store/hash-example-7.0"]}}}"#,
            vec![("example", "unknown", "Nix")],
        ),
        (
            "METADATA",
            "Metadata-Version: 2.1\nName: example-python\nVersion: 4.5.6\n\nDescription",
            vec![("example-python", "4.5.6", "PyPI")],
        ),
        (
            "pom.properties",
            "groupId=org.example\nartifactId=component\nversion=2.0.1\n",
            vec![("org.example:component", "2.0.1", "Maven")],
        ),
        (
            "packages.lock.json",
            r#"{"version":1,"dependencies":{"net8.0":{"Example.Dependency":{"type":"Direct","resolved":"8.1.2"},"Example.Project":{"type":"Project"}}}}"#,
            vec![("Example.Dependency", "8.1.2", "NuGet")],
        ),
    ] {
        let path = tmp.path().join(filename);
        fs::write(&path, text).unwrap();
        let result = inventory(&path);
        assert_eq!(result["status"], "complete", "{filename}: {result:?}");
        let packages = result["packages"].as_array().unwrap();
        assert_eq!(packages.len(), expected.len(), "{filename}");
        for (name, version, ecosystem) in expected {
            assert!(
                packages.iter().any(|p| p["name"] == name
                    && p["version"] == version
                    && p["ecosystem"] == ecosystem),
                "{filename}: {packages:?}"
            );
        }
        assert_eq!(
            result["source_outcomes"][0]["advisory_coverage"],
            "not-assessed"
        );
    }
}

#[cfg(unix)]
#[test]
fn selected_metadata_refuses_symlinks_without_clearing_source() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("actual.json");
    fs::write(&source, r#"{"name":"outside","version":"1.0"}"#).unwrap();
    let link = tmp.path().join("package.json");
    std::os::unix::fs::symlink(source, &link).unwrap();
    let result = inventory(&link);
    assert_eq!(result["packages"], json!([]));
    assert_eq!(result["completed_paths"], json!([]));
    assert_eq!(result["status"], "unknown");
}

#[cfg(not(windows))]
#[test]
fn windows_source_on_other_platform_is_explicitly_unsupported() {
    let result = scanner::inventory(&InventoryOptions {
        installed_apps: true,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(result["source_outcomes"][0]["outcome"], "unsupported");
    assert_eq!(result["packages"], json!([]));
    assert_eq!(result["status"], "unknown");
}

#[test]
fn project_nuget_lock_uses_resolved_versions_and_keeps_unresolved_input_unknown() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("packages.lock.json");
    fs::write(&path,r#"{"version":1,"dependencies":{"net8.0":{"Example.Package":{"type":"Direct","requested":"[1.0, )","resolved":"2.1.0"}}}}"#).unwrap();
    let options = InventoryOptions {
        roots: vec![tmp.path().into()],
        ..Default::default()
    };
    let result = scanner::inventory(&options).unwrap();
    assert_eq!(result["packages"][0]["version"], "2.1.0");
    assert_eq!(result["packages"][0]["origin"], "project");
    assert_eq!(result["packages"][0]["presence"], "referenced");
    fs::write(&path,r#"{"version":1,"dependencies":{"net8.0":{"Example.Package":{"type":"Direct","requested":"[1.0, )"}}}}"#).unwrap();
    let result = scanner::inventory(&options).unwrap();
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["packages"], json!([]));
    assert_eq!(result["completed_paths"], json!([]));
}

#[cfg(unix)]
#[test]
fn denied_metadata_and_missing_bundle_metadata_cannot_claim_removal() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("package.json");
    fs::write(&path, r#"{"name":"private","version":"1.2.3"}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let result = inventory(&path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(result["source_outcomes"][0]["outcome"], "denied");
    assert_eq!(result["completed_paths"], json!([]));
    let app = tmp.path().join("MissingMetadata.app");
    fs::create_dir(&app).unwrap();
    let result = inventory(&app);
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["completed_paths"], json!([]));
    fs::remove_dir(&app).unwrap();
    let result = inventory(&app);
    assert_eq!(result["source_outcomes"][0]["outcome"], "missing");
}

#[cfg(windows)]
#[test]
fn native_windows_inventory_attempts_both_views_without_elevation() {
    let result = scanner::inventory(&InventoryOptions {
        installed_apps: true,
        ..Default::default()
    })
    .unwrap();
    let outcomes = result["source_outcomes"].as_array().unwrap();
    assert_eq!(outcomes.len(), 5);
    for path in [
        "windows-uninstall:HKCU:32",
        "windows-uninstall:HKCU:64",
        "windows-uninstall:HKLM:32",
        "windows-uninstall:HKLM:64",
        "windows-msix:HKCU:activatable-packages",
    ] {
        assert!(outcomes.iter().any(|o| o["path"] == path));
    }
    println!("native source outcomes: {}", result["source_outcomes"]);
    for p in result["packages"].as_array().unwrap() {
        assert!(["windows-uninstall", "windows-msix"]
            .contains(&p["collector_source"].as_str().unwrap()));
        assert_eq!(p["advisory_mapping"], "unsupported");
        assert_eq!(p["running"], "unknown");
    }
}

#[test]
fn selected_image_sbom_retains_rpm_as_unmapped_and_language_coordinates() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("syft.json");
    fs::write(&path,r#"{"artifacts":[{"name":"example-rpm","version":"2.1-1","type":"rpm"},{"name":"example-python","version":"1.2.3","type":"python"}]}"#).unwrap();
    let result = inventory(&path);
    let packages = result["packages"].as_array().unwrap();
    let rpm = packages
        .iter()
        .find(|p| p["name"] == "example-rpm")
        .unwrap();
    assert_eq!(rpm["ecosystem"], "Unmapped:rpm");
    assert_eq!(rpm["advisory_mapping"], "unsupported");
    assert_eq!(rpm["origin"], "image");
    assert_eq!(rpm["presence"], "imported-metadata");
    let python = packages
        .iter()
        .find(|p| p["name"] == "example-python")
        .unwrap();
    assert_eq!(python["ecosystem"], "PyPI");
    assert_eq!(python["version"], "1.2.3");
    assert_eq!(
        result["source_outcomes"][0]["advisory_coverage"],
        "not-assessed"
    );
}

#[test]
fn selected_msix_manifest_reports_identity_without_claiming_registration() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("AppxManifest.xml");
    fs::write(&path,r#"<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Example.App" Version="1.2.3.4" Publisher="CN=Example"/></Package>"#).unwrap();
    let result = vorda::scanner::inventory::installed::selected(&path);
    assert_eq!(result.outcomes[0]["outcome"], "complete");
    assert_eq!(result.packages[0].name, "Example.App");
    assert_eq!(result.packages[0].version, "1.2.3.4");
    assert_eq!(result.packages[0].extra["presence"], "selected-manifest");
    assert_eq!(result.packages[0].extra["advisory_mapping"], "unsupported");
    fs::write(&path, "<Package/>").unwrap();
    let result = vorda::scanner::inventory::installed::selected(&path);
    assert!(result.packages.is_empty());
    assert_eq!(result.outcomes[0]["outcome"], "malformed");
}

#[test]
fn msix_registration_preserves_source_identity_unknown_versions_and_partial_results() {
    use vorda::scanner::inventory::installed::msix_inventory;
    let snapshot = |outcome: &str, keys: &[&str], errors: Vec<String>| RegistrySnapshot {
        hive: "HKCU".into(),
        view: 0,
        outcome: outcome.into(),
        entries: keys
            .iter()
            .map(|key| RegistryEntry {
                key: (*key).into(),
                ..Default::default()
            })
            .collect(),
        errors,
    };
    let result = msix_inventory(&snapshot(
        "complete",
        &[
            "Example.App_1.2.3.4_x64__abcdefghijklm",
            "Example.App_beta_x86__abcdefghijklm",
            "Example.Other_65536.0.0.0_neutral__abcdefghijklm",
        ],
        vec![],
    ));
    assert_eq!(result.packages.len(), 3);
    assert_eq!(result.packages[0].name, "Example.App");
    assert_eq!(result.packages[0].version, "1.2.3.4");
    assert_ne!(result.packages[0].path, result.packages[1].path);
    assert_eq!(result.packages[1].version, "unknown");
    assert_eq!(result.packages[1].extra["raw_version"], "beta");
    assert_eq!(result.packages[2].version, "unknown");
    for p in &result.packages {
        assert_eq!(p.ecosystem, "MSIX");
        assert_eq!(p.extra["origin"], "installed");
        assert_eq!(p.extra["advisory_mapping"], "unsupported");
        assert_eq!(p.extra["running"], "unknown");
        assert_eq!(p.extra["presence"], "registered");
    }
    assert_eq!(result.outcomes[0]["outcome"], "complete");
    for outcome in ["missing", "denied", "partial", "complete"] {
        let result = msix_inventory(&snapshot(outcome, &[], vec![]));
        assert!(result.packages.is_empty());
        assert_eq!(result.outcomes[0]["outcome"], outcome);
        assert_eq!(result.outcomes[0]["advisory_coverage"], "not-assessed");
    }
    let partial = msix_inventory(&snapshot(
        "partial",
        &["Example.App_1.2.3.4_x64__abcdefghijklm"],
        vec!["enumeration stopped".into()],
    ));
    assert_eq!(partial.packages.len(), 1);
    assert_eq!(partial.outcomes[0]["outcome"], "partial");
    let malformed = msix_inventory(&snapshot("complete", &["unparseable"], vec![]));
    assert_eq!(malformed.packages[0].name, "unparseable");
    assert_eq!(malformed.packages[0].version, "unknown");
    assert_eq!(malformed.outcomes[0]["outcome"], "partial");
}

#[test]
fn msix_removal_requires_completed_source_and_keeps_other_inventory() {
    use std::collections::BTreeSet;
    use vorda::{assets, scanner::inventory::installed::msix_inventory, store::Store};
    let snapshot = |outcome: &str, present: bool| RegistrySnapshot {
        hive: "HKCU".into(),
        view: 0,
        outcome: outcome.into(),
        errors: vec![],
        entries: if present {
            vec![RegistryEntry {
                key: "Example.App_1.2.3.4_x64__abcdefghijklm".into(),
                ..Default::default()
            }]
        } else {
            vec![]
        },
    };
    for outcome in ["partial", "denied", "unsupported", "complete", "missing"] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let mut packages = msix_inventory(&snapshot("complete", true)).packages;
        let mut other = packages[0].clone();
        other.path = "windows-uninstall:HKCU:64/other".into();
        packages.push(other);
        let rows = assets::observations(&packages, &[], None).unwrap();
        assert!(rows.iter().all(|r| r["category"] == "Applications"));
        assets::save(&mut store, "selected", &rows, &BTreeSet::new(), false, None).unwrap();
        let removed = msix_inventory(&snapshot(outcome, false));
        assets::retire_absent_sources(
            &mut store,
            "selected",
            &removed.packages,
            &removed
                .outcomes
                .into_iter()
                .filter(|s| ["complete", "missing"].contains(&s["outcome"].as_str().unwrap_or("")))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let summary =
            assets::summary(&store.db, None, Some(&BTreeSet::from(["selected".into()]))).unwrap();
        assert_eq!(
            summary["total"],
            if ["complete", "missing"].contains(&outcome) {
                1
            } else {
                2
            },
            "{outcome}"
        );
    }
}

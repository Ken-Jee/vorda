//! Packaging checks for the canonical `vorda` skill. They show the files are well formed and name
//! real tools; they do not show that the skill improves a client's security decisions.
use regex::Regex;
use serde_json::json;
use std::{collections::BTreeSet, fs, path::PathBuf};
use vorda::{fleet::http::ROUTES, surfaces::mcp};

fn skill_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../plugin/skills/vorda")
}

fn skill() -> String {
    fs::read_to_string(skill_dir().join("SKILL.md")).unwrap()
}

/// The backticked names on the first line that starts with `prefix`.
fn listed(text: &str, prefix: &str) -> BTreeSet<String> {
    let line = text
        .lines()
        .find(|l| l.trim_start_matches("- ").starts_with(prefix))
        .unwrap_or_else(|| panic!("no `{prefix}` line"));
    Regex::new(r"`([a-z_]+)`")
        .unwrap()
        .captures_iter(line)
        .map(|c| c[1].to_string())
        .collect()
}

#[test]
fn the_skill_has_frontmatter_and_a_compact_body() {
    let text = skill();
    let rest = text.strip_prefix("---\n").expect("frontmatter");
    let (front, _) = rest.split_once("\n---\n").expect("closed frontmatter");
    let meta: serde_norway::Value = serde_norway::from_str(front).unwrap();
    assert_eq!(meta["name"], "vorda");
    assert!(meta["description"].as_str().is_some_and(|d| d.len() > 40));
    let lines = text.lines().count();
    assert!((100..=200).contains(&lines), "SKILL.md has {lines} lines");
}

#[test]
fn every_linked_reference_exists_and_every_reference_is_linked() {
    let text = skill();
    let link = Regex::new(r"references/[A-Za-z0-9_.-]+\.md").unwrap();
    let linked: BTreeSet<String> = link.find_iter(&text).map(|m| m.as_str().into()).collect();
    assert!(!linked.is_empty());
    for path in &linked {
        assert!(skill_dir().join(path).is_file(), "{path} is missing");
    }
    let present: BTreeSet<String> = fs::read_dir(skill_dir().join("references"))
        .unwrap()
        .map(|e| format!("references/{}", e.unwrap().file_name().to_string_lossy()))
        .collect();
    assert_eq!(linked, present);
}

#[test]
fn the_tool_names_the_skill_lists_are_the_real_ones() {
    let text = skill();
    let fleet: BTreeSet<String> = ROUTES.iter().map(|r| r.to_string()).collect();
    assert_eq!(listed(&text, "Fleet tools:"), fleet);
    let state = tempfile::tempdir().unwrap();
    let tools = mcp::call(state.path(), &json!({"method":"tools/list"}), None, None).unwrap();
    let local: BTreeSet<String> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(listed(&text, "Local tools:"), local);
}

#[test]
fn no_skill_file_carries_a_client_or_mailbox_identity() {
    let identity = Regex::new(r"(?i)claude|codex|gemini|copilot|--reader\s+\S").unwrap();
    let mut files = vec![skill_dir().join("SKILL.md")];
    for entry in fs::read_dir(skill_dir().join("references")).unwrap() {
        files.push(entry.unwrap().path());
    }
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        assert!(
            !identity.is_match(&text),
            "{} names a client or reader identity",
            file.display()
        );
    }
}

#[test]
fn the_embedded_skill_copy_is_the_canonical_directory_byte_for_byte() {
    use vorda::surfaces::skill_copy::FILES;
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, fs::read(&path).unwrap()));
            }
        }
    }
    let mut on_disk = Vec::new();
    walk(&skill_dir(), &skill_dir(), &mut on_disk);
    on_disk.sort();
    let mut embedded: Vec<(String, Vec<u8>)> = FILES
        .iter()
        .map(|(p, t)| (p.to_string(), t.as_bytes().to_vec()))
        .collect();
    embedded.sort();
    // Every file under the directory (scripts/, assets/ too) is embedded, and the reverse.
    let names = |v: &[(String, Vec<u8>)]| v.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>();
    assert_eq!(names(&embedded), names(&on_disk), "embedded list drifted");
    assert!(embedded == on_disk, "an embedded file's bytes drifted");
}

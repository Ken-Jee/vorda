//! `vorda connect` hub mode and skill copy, driven through the binary. They show the config and
//! receipts are written, left alone and undone exactly; they do not show a real client accepts them.
use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const SENTINEL: &str = "sentinel-reader-credential-4f2a";
const HUB: &str = "https://hub.example:8443";

struct Setup {
    _dir: tempfile::TempDir,
    home: std::path::PathBuf,
    state: std::path::PathBuf,
    ca: std::path::PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("with space");
    let (home, state, ca) = (
        root.join("my home"),
        root.join("my state"),
        root.join("ca bundle.pem"),
    );
    fs::create_dir_all(&home).unwrap();
    fs::write(&ca, "pem").unwrap();
    Setup {
        _dir: dir,
        home,
        state,
        ca,
    }
}

fn vorda(s: &Setup, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_vorda"))
        .args(["--state", s.state.to_str().unwrap(), "connect"])
        .args(args)
        .args(["--home", s.home.to_str().unwrap()])
        .env("VORDA_READER_TOKEN", SENTINEL)
        .output()
        .unwrap()
}

fn holds_sentinel(dir: &Path) -> bool {
    fs::read_dir(dir).unwrap().any(|e| {
        let path = e.unwrap().path();
        if path.is_dir() {
            holds_sentinel(&path)
        } else {
            fs::read_to_string(path).is_ok_and(|t| t.contains(SENTINEL))
        }
    })
}

fn ok(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn receipt(stdout: &str) -> String {
    let v: Value = serde_json::from_str(stdout).unwrap();
    v["receipt"].as_str().unwrap().to_string()
}

fn refused(s: &Setup, args: &[&str], why: &str) {
    let output = vorda(s, args);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && err.contains(why),
        "{args:?}: {err}"
    );
    assert!(!err.contains(SENTINEL));
    assert!(
        fs::read_dir(&s.home).unwrap().next().is_none(),
        "{args:?} wrote under home"
    );
}

/// The args of the named entry in the client's own config format.
fn entry_args(client: &str, config: &Path, name: &str) -> Vec<String> {
    let text = fs::read_to_string(config).unwrap();
    let args = if client == "codex" {
        let t: toml::Value = toml::from_str(&text).unwrap();
        serde_json::to_value(&t["mcp_servers"][name]["args"]).unwrap()
    } else {
        serde_json::from_str::<Value>(&text).unwrap()["mcpServers"][name]["args"].clone()
    };
    args.as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect()
}

/// The `env_vars` Codex is told to pass to the server (Claude Code inherits the launching environment).
fn entry_env_vars(config: &Path, name: &str) -> Option<Vec<String>> {
    let t: toml::Value = toml::from_str(&fs::read_to_string(config).unwrap()).unwrap();
    let list = t["mcp_servers"][name].get("env_vars")?.as_array()?;
    Some(
        list.iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect(),
    )
}

#[test]
fn hub_entry_previews_applies_coexists_and_undoes_exactly() {
    for (client, rel, original) in [
        (
            "claude-code",
            ".claude.json",
            "{\"z\":1,\"mcpServers\":{\"other\":{\"command\":\"x\"}}}\n",
        ),
        ("codex", ".codex/config.toml", "# mine\nmodel = \"m\"\n"),
    ] {
        let s = setup();
        let config = s.home.join(rel);
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(&config, original).unwrap();
        let (ca, hub) = (
            s.ca.to_str().unwrap(),
            ["--hub", HUB, "--reader-env", "VORDA_READER_TOKEN"],
        );
        let mut hub_args = vec![client];
        hub_args.extend(hub);
        hub_args.extend(["--ca-file", ca]);

        let preview = ok(vorda(&s, &hub_args));
        assert!(preview.contains("vorda-fleet") && preview.contains("VORDA_READER_TOKEN"));
        assert!(!preview.contains(SENTINEL));
        assert_eq!(
            fs::read_to_string(&config).unwrap(),
            original,
            "preview wrote"
        );

        hub_args.push("--apply");
        let applied = ok(vorda(&s, &hub_args));
        assert!(!applied.contains(SENTINEL));
        let hub_receipt = receipt(&applied);
        let want = [
            "hub-mcp",
            "--hub",
            HUB,
            "--reader-env",
            "VORDA_READER_TOKEN",
            "--ca-file",
            ca,
        ];
        assert_eq!(entry_args(client, &config, "vorda-fleet"), want);
        if client == "codex" {
            let listed = Some(vec!["VORDA_READER_TOKEN".to_string()]);
            assert_eq!(entry_env_vars(&config, "vorda-fleet"), listed);
        }

        let local_receipt = receipt(&ok(vorda(&s, &[client, "--apply"])));
        assert_eq!(entry_args(client, &config, "vorda").last().unwrap(), "mcp");
        assert_eq!(entry_args(client, &config, "vorda-fleet"), want);

        // Nothing connect wrote (config, receipts, backups) holds the credential: it never reads it.
        assert!(!holds_sentinel(s.state.parent().unwrap()));

        // Last applied, first undone: each undo then finds its own installed bytes and restores them.
        ok(vorda(&s, &["--undo", &local_receipt]));
        assert_eq!(entry_args(client, &config, "vorda-fleet"), want);
        assert!(!fs::read_to_string(&config)
            .unwrap()
            .contains("[mcp_servers.vorda]"));
        ok(vorda(&s, &["--undo", &hub_receipt]));
        assert_eq!(
            fs::read_to_string(&config).unwrap(),
            original,
            "{client} not restored exactly"
        );
    }
}

#[test]
fn hub_mode_refuses_what_hub_mcp_would_refuse_and_writes_nothing() {
    let s = setup();
    let ca = s.ca.to_str().unwrap();
    let env = ["--reader-env", "VORDA_READER_TOKEN"];
    let with = |hub: &'static str| {
        ["claude-code", "--hub", hub]
            .into_iter()
            .chain(env)
            .collect::<Vec<_>>()
    };
    refused(&s, &with("http://hub.example:8443"), "https origin");
    refused(&s, &with("https://hub.example/v2"), "https origin");
    refused(&s, &with("https://user:pw@hub.example"), "https origin");
    refused(
        &s,
        &["claude-code", "--hub", HUB, "--reader-env", SENTINEL],
        "environment variable",
    );
    for bad in ["1BAD", "lower_case", "WITH-DASH"] {
        refused(
            &s,
            &["claude-code", "--hub", HUB, "--reader-env", bad],
            "environment variable",
        );
    }
    refused(&s, &["claude-code", "--hub", HUB], "--reader-env");
    refused(
        &s,
        &[
            "claude-code",
            "--hub",
            HUB,
            "--reader-env",
            "A",
            "--name",
            "bad name",
        ],
        "--name",
    );
    refused(
        &s,
        &[
            "claude-code",
            "--hub",
            HUB,
            "--reader-env",
            "A",
            "--ca-file",
            "missing.pem",
        ],
        "--ca-file",
    );
    let home = s.home.to_str().unwrap();
    let directory = [
        "claude-code",
        "--hub",
        HUB,
        "--reader-env",
        "A",
        "--ca-file",
        home,
    ];
    refused(&s, &directory, "--ca-file");
    // A path the TOML writer would emit as invalid TOML is refused, not written.
    let odd = s.ca.with_file_name("ca\u{7f}.pem");
    fs::write(&odd, "pem").unwrap();
    let odd = odd.to_str().unwrap();
    refused(
        &s,
        &["codex", "--hub", HUB, "--reader-env", "A", "--ca-file", odd],
        "not valid TOML",
    );
    refused(&s, &["claude-code", "--reader-env", "A"], "need --hub");
    refused(
        &s,
        &["claude-code", "--hub", HUB, "--reader-env", "A", "--skill"],
        "cannot be combined",
    );
    for client in ["cursor", "claude-desktop", "nonesuch"] {
        refused(
            &s,
            &[client, "--hub", HUB, "--reader-env", "A"],
            "claude-code and codex only",
        );
    }
    // Loopback http is the one allowed exception, as for hub-mcp.
    ok(vorda(
        &s,
        &[
            "codex",
            "--hub",
            "http://127.0.0.1:7788",
            "--reader-env",
            "A",
            "--ca-file",
            ca,
        ],
    ));
}

#[test]
fn a_credential_given_as_the_reader_env_is_refused_and_never_echoed() {
    // 64 hex characters starting with a letter, and a mixed-case value of 32 characters.
    let hex = "a3f1c9d27b4e5068a3f1c9d27b4e5068a3f1c9d27b4e5068a3f1c9d27b4e5068";
    for secret in [hex, "AbCdEfGhIjKlMnOpQrStUvWxYz012345"] {
        for client in ["claude-code", "codex"] {
            let s = setup();
            let output = vorda(
                &s,
                &[client, "--hub", HUB, "--reader-env", secret, "--apply"],
            );
            let (out, err) = (
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            assert!(!output.status.success());
            assert!(err.contains("--reader-env must name an environment variable"));
            assert!(!out.contains(secret) && !err.contains(secret));
            assert!(
                !s.state.join("connect-receipts").exists(),
                "wrote a receipt"
            );
            assert!(fs::read_dir(&s.home).unwrap().next().is_none());
        }
    }
}

#[test]
fn undo_takes_no_other_connect_options() {
    let s = setup();
    for extra in [
        &["--skill"][..],
        &["--hub", HUB],
        &["--reader-env", "A"],
        &["--name", "x"],
        &["--skill-dir", "d"],
        &["--ca-file", "c"],
    ] {
        let mut args = vec!["--undo", "missing.json"];
        args.extend(extra);
        let output = vorda(&s, &args);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(err.contains("other connect options"), "{extra:?}: {err}");
    }
}

#[test]
fn undoing_the_earlier_entry_first_keeps_the_later_one() {
    for (client, rel) in [
        ("claude-code", ".claude.json"),
        ("codex", ".codex/config.toml"),
    ] {
        let s = setup();
        let config = s.home.join(rel);
        let hub = [
            "--hub",
            HUB,
            "--reader-env",
            "VORDA_READER_TOKEN",
            "--apply",
        ];
        let hub_receipt = receipt(&ok(vorda(&s, &[&[client][..], &hub].concat())));
        let local_receipt = receipt(&ok(vorda(&s, &[client, "--apply"])));
        ok(vorda(&s, &["--undo", &hub_receipt]));
        assert_eq!(entry_args(client, &config, "vorda").last().unwrap(), "mcp");
        assert!(!fs::read_to_string(&config).unwrap().contains("vorda-fleet"));
        ok(vorda(&s, &["--undo", &local_receipt]));
        let text = fs::read_to_string(&config).unwrap();
        assert!(
            !text.contains("hub-mcp") && !text.contains("\"mcp\""),
            "{text}"
        );
    }
}

#[test]
fn skill_copy_previews_writes_the_canonical_files_and_undoes_exactly() {
    let s = setup();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugin/skills/vorda");
    let target = s.home.join(".claude/skills/vorda");

    assert!(ok(vorda(&s, &["claude-code", "--skill"])).contains("SKILL.md"));
    assert!(!target.exists(), "preview wrote");

    let r = receipt(&ok(vorda(&s, &["claude-code", "--skill", "--apply"])));
    for (rel, _) in vorda::surfaces::skill_copy::FILES {
        assert_eq!(
            fs::read(target.join(rel)).unwrap(),
            fs::read(source.join(rel)).unwrap(),
            "{rel}"
        );
    }
    refused_existing(&s);

    fs::write(target.join("SKILL.md"), "edited").unwrap();
    let blocked = vorda(&s, &["--undo", &r]);
    assert!(
        !blocked.status.success() && target.join("SKILL.md").exists(),
        "undo ran over an edit"
    );
    fs::write(
        target.join("SKILL.md"),
        fs::read(source.join("SKILL.md")).unwrap(),
    )
    .unwrap();

    ok(vorda(&s, &["--undo", &r]));
    assert!(
        fs::read_dir(&s.home).unwrap().next().is_none(),
        "undo left what apply made"
    );
}

fn refused_existing(s: &Setup) {
    let output = vorda(s, &["claude-code", "--skill"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
}

#[test]
fn skill_undo_keeps_directories_that_hold_other_files() {
    let s = setup();
    let r = receipt(&ok(vorda(&s, &["claude-code", "--skill", "--apply"])));
    let skills = s.home.join(".claude/skills");
    let target = skills.join("vorda");
    fs::write(skills.join("mine.md"), "other").unwrap();
    fs::write(target.join("references/note.md"), "user note").unwrap();
    ok(vorda(&s, &["--undo", &r]));
    assert!(!target.join("SKILL.md").exists() && !target.join("references/triage.md").exists());
    assert_eq!(fs::read_to_string(skills.join("mine.md")).unwrap(), "other");
    assert_eq!(
        fs::read_to_string(target.join("references/note.md")).unwrap(),
        "user note"
    );
    assert!(!Path::new(&r).exists(), "receipt left behind");
}

#[test]
fn skill_copy_refuses_other_clients_and_parent_components() {
    let s = setup();
    let dir = s.home.join("skills/vorda");
    let dir = dir.to_str().unwrap();
    refused(
        &s,
        &["cursor", "--skill", "--skill-dir", dir],
        "claude-code and codex only",
    );
    let up = s.home.join("a/../b/vorda");
    refused(
        &s,
        &["codex", "--skill", "--skill-dir", up.to_str().unwrap()],
        "..",
    );
}

#[test]
fn codex_skill_copy_needs_an_explicit_directory() {
    let s = setup();
    let err = vorda(&s, &["codex", "--skill"]);
    assert!(!err.status.success() && String::from_utf8_lossy(&err.stderr).contains("--skill-dir"));
    let dir = s.home.join("skills dir/vorda");
    let r = receipt(&ok(vorda(
        &s,
        &[
            "codex",
            "--skill",
            "--skill-dir",
            dir.to_str().unwrap(),
            "--apply",
        ],
    )));
    assert!(dir.join("references/triage.md").is_file());
    ok(vorda(&s, &["--undo", &r]));
    assert!(fs::read_dir(&s.home).unwrap().next().is_none());
}

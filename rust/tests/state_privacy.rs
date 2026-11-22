#![cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Runs a command that opens the state folder: an inventory of an empty project.
fn open_state(state: &Path) {
    let project = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_vorda"))
        .arg("--state")
        .arg(state)
        .args(["inventory", "--root"])
        .arg(project.path())
        .output()
        .unwrap();
    assert!(
        output.status.code().is_some(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_new_state_folder_and_its_database_are_owner_only() {
    let parent = tempfile::tempdir().unwrap();
    let state = parent.path().join("state");
    open_state(&state);
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&state.join("mail.db")), 0o600);
}

#[test]
fn an_existing_shared_state_folder_and_database_become_owner_only() {
    let parent = tempfile::tempdir().unwrap();
    let state = parent.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
    open_state(&state);
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&state.join("mail.db")), 0o600);

    fs::set_permissions(&state, fs::Permissions::from_mode(0o775)).unwrap();
    fs::set_permissions(state.join("mail.db"), fs::Permissions::from_mode(0o644)).unwrap();
    open_state(&state);
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&state.join("mail.db")), 0o600);
}

//! `vorda connect CLIENT --skill`: for a host that needs the skill as a file, a copy generated from
//! the canonical `plugin/skills/vorda` embedded at build time. A test keeps the two identical.
use super::connect::refuse_link;
use crate::{store::atomic, Error, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub const FILES: [(&str, &str); 4] = [
    (
        "SKILL.md",
        include_str!("../../../plugin/skills/vorda/SKILL.md"),
    ),
    (
        "references/scope-and-coverage.md",
        include_str!("../../../plugin/skills/vorda/references/scope-and-coverage.md"),
    ),
    (
        "references/triage.md",
        include_str!("../../../plugin/skills/vorda/references/triage.md"),
    ),
    (
        "references/verification.md",
        include_str!("../../../plugin/skills/vorda/references/verification.md"),
    ),
];

fn hash(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

/// Claude Code's user skills directory is documented; Codex's is not verified here, so it is asked for.
pub fn plan(client: &str, home: &Path, dir: Option<&Path>) -> Result<Value> {
    if !["claude-code", "codex"].contains(&client) {
        return Err(Error::usage(
            "skill copy supports claude-code and codex only",
        ));
    }
    let dir = match (client, dir) {
        (_, Some(dir)) => std::path::absolute(dir)?,
        ("claude-code", None) => home.join(".claude/skills/vorda"),
        _ => {
            return Err(Error::new(
                "codex needs --skill-dir: its skills directory is not assumed",
            ))
        }
    };
    if dir.components().any(|c| c == Component::ParentDir) {
        return Err(Error::new("skill directory must not contain .. components"));
    }
    let parent = dir
        .parent()
        .ok_or_else(|| Error::new("skill directory needs a parent"))?;
    if refuse_link(parent).is_err() || refuse_link(&dir).is_err() {
        return Err(Error::new(
            "skills directory is a symlink; give --skill-dir the resolved path",
        ));
    }
    if dir.exists() {
        return Err(Error::new(
            "skill directory already exists; remove or undo before installing",
        ));
    }
    let files: Vec<Value> = FILES
        .iter()
        .map(|(p, t)| json!({"path":p,"sha256":hash(t)}))
        .collect();
    let lines: String = FILES
        .iter()
        .map(|(p, _)| format!("+ {}\n", dir.join(p).display()))
        .collect();
    Ok(
        json!({"kind":"skill","client":client,"dir":dir,"files":files,"diff":format!("Copy the vorda skill:\n{lines}")}),
    )
}

pub fn apply(plan: &Value) -> Result<Value> {
    let dir = Path::new(super::text(plan, "dir")?);
    let created = install(dir, &FILES)?;
    Ok(json!({"kind":"skill","dir":dir,"files":plan["files"],"created":created}))
}

/// Writes the files into a temporary sibling directory and renames it to `dir`, so a failure
/// leaves neither a partial skill nor the parent directories this call made. Returns what it made.
fn install(dir: &Path, files: &[(&str, &str)]) -> Result<Vec<PathBuf>> {
    if dir.exists() {
        return Err(Error::new("skill directory appeared since preview"));
    }
    let parent = dir
        .parent()
        .ok_or_else(|| Error::new("skill directory needs a parent"))?;
    let missing: Vec<&Path> = parent.ancestors().take_while(|p| !p.exists()).collect();
    let temp = parent.join(format!(".vorda-skill-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        fs::create_dir_all(parent)?;
        for (path, text) in files {
            atomic(&temp.join(path), text)?;
        }
        fs::rename(&temp, dir)?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_dir_all(&temp);
        for path in missing {
            if fs::remove_dir(path).is_err() {
                break;
            }
        }
        return Err(e);
    }
    let mut created: Vec<PathBuf> = missing.into_iter().map(Path::to_path_buf).collect();
    for (path, _) in files {
        if let Some(sub) = Path::new(path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            let sub = dir.join(sub);
            if !created.contains(&sub) {
                created.push(sub);
            }
        }
    }
    created.push(dir.to_path_buf());
    Ok(created)
}

/// Removes the files `apply` wrote if all are untouched, then the directories it created that are
/// now empty; a directory that holds anything else (the user's own files) is kept.
pub fn undo(receipt: &Value) -> Result<()> {
    let dir = Path::new(super::text(receipt, "dir")?);
    let files = receipt["files"]
        .as_array()
        .ok_or_else(|| Error::new("receipt lists no files"))?;
    let mut present = Vec::new();
    for file in files {
        let path = dir.join(super::text(file, "path")?);
        refuse_link(&path)?;
        match fs::read_to_string(&path) {
            Ok(text) if hash(&text) == super::text(file, "sha256")? => present.push(path),
            Ok(_) => return Err(Error::new("installed skill file changed; refusing undo")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    for path in present {
        fs::remove_file(path)?;
    }
    let mut created: Vec<&str> = receipt["created"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    created.sort();
    for path in created.into_iter().rev() {
        match fs::remove_dir(path) {
            Err(e)
                if !matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                return Err(e.into())
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::install;

    #[test]
    fn a_failed_install_leaves_nothing_behind() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a/b/vorda");
        // The second file's parent is the first file, so its write fails after the first succeeded.
        let bad = [("SKILL.md", "x"), ("SKILL.md/more.md", "y")];
        assert!(install(&dir, &bad).is_err());
        assert!(
            std::fs::read_dir(root.path()).unwrap().next().is_none(),
            "install left files or directories behind"
        );
    }
}

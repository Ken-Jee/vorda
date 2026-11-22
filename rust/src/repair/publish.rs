use super::{commands::*, digest, Repairs};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn transport(args: &[String], root: &Path) -> Result<String> {
    let mut command = Command::new("git");
    command
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "http.followRedirects=false",
            "-c",
            "credential.helper=",
            "-c",
            "credential.helper=!gh auth git-credential",
        ])
        .args(args)
        .current_dir(root)
        .env_clear()
        .env("PATH", search_path())
        .env("HOME", home())
        .env("LANG", "C.UTF-8")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GH_HOST", "github.com")
        .env("GH_PROMPT_DISABLED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    bounded(command)
}
fn bounded(command: Command) -> Result<String> {
    super::commands::bounded(command, 120)
}
pub fn publish(
    repairs: &Repairs,
    item: &str,
    reviewed: &str,
    repository: &str,
    base: &str,
    branch: &str,
) -> Result<Value> {
    let result = (|| -> Result<Value> {
        if !regex::Regex::new(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$")
            .unwrap()
            .is_match(repository)
        {
            return Err(Error::new("choose a GitHub owner/repository"));
        }
        let ref_re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_./\-]*$").unwrap();
        for name in [base, branch] {
            if !ref_re.is_match(name)
                || name.contains("..")
                || name.ends_with('/')
                || name.ends_with(".lock")
            {
                return Err(Error::new("invalid branch name"));
            }
        }
        repairs.db.execute_batch("BEGIN IMMEDIATE")?;
        let row = repairs.row(item)?;
        let draft: Value = serde_json::from_str(&repairs.db.query_row(
            "SELECT payload FROM drafts WHERE item=? AND dismissed=0",
            [item],
            |r| r.get::<_, String>(0),
        )?)?;
        let plan = &row["plan"];
        if row["status"] != "planned"
            || plan["kind"] != "repo"
            || plan.get("locked").is_some()
            || draft["changes"] != *plan
            || draft["digest"] != reviewed
            || digest(plan)? != reviewed
        {
            return Err(Error::rejected(
                403,
                "an active reviewed npm manifest draft is required",
            ));
        }
        let modes = repairs.fleet()?;
        if !modes.enough(repairs.approval_count(item)?) {
            return Err(Error::rejected(403, "approval quorum is required"));
        }
        let humans: Vec<_> = repairs
            .db
            .prepare("SELECT actor,channel FROM approvals WHERE item=? AND kind='human'")?
            .query_map([item], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        if !humans
            .iter()
            .any(|(a, c)| modes.approval_allowed(a, "human", c))
            || repairs.can(field(&row, "agent")?, "lockfiles")?["answer"] == "no"
            || repairs.policy()?.decision(
                field(plan, "package")?,
                "patch",
                &json!(repairs.changes + 1),
                None,
            ) == "deny"
        {
            return Err(Error::rejected(
                403,
                "human approval and current policy are required",
            ));
        }
        repairs.validate(item, plan)?;
        let root = fs::canonicalize(field(&draft, "repository")?)?;
        if run(
            &strings(&["git", "rev-parse", "--show-toplevel"]),
            Some(&root),
        )?
        .trim()
            != root.to_string_lossy()
        {
            return Err(Error::rejected(
                403,
                "a standalone draft repository is required",
            ));
        }
        let config = run(
            &strings(&["git", "config", "--local", "--null", "--list", "--includes"]),
            Some(&root),
        )?;
        if config.split('\0').any(|e| {
            ["url.", "credential.", "http.", "https.", "core.gitproxy"]
                .iter()
                .any(|p| {
                    e.split('\n')
                        .next()
                        .unwrap_or("")
                        .to_lowercase()
                        .starts_with(p)
                })
        }) {
            return Err(Error::rejected(
                403,
                "draft has custom transport configuration",
            ));
        }
        let commit = field(&draft, "commit")?;
        if !regex::Regex::new(r"^[0-9a-f]{40,64}$")
            .unwrap()
            .is_match(commit)
            || draft["test_result"] != "passed"
            || run(&strings(&["git", "rev-parse", "HEAD"]), Some(&root))?.trim() != commit
            || !run(&strings(&["git", "status", "--porcelain"]), Some(&root))?.is_empty()
            || run(
                &strings(&["git", "rev-parse", &format!("{commit}^")]),
                Some(&root),
            )?
            .trim()
                != field(plan, "head")?
        {
            return Err(Error::rejected(403, "tested draft changed"));
        }
        let names = run(
            &strings(&["git", "diff", "--name-only", field(plan, "head")?, commit]),
            Some(&root),
        )?;
        let mut before: Value = serde_json::from_str(&run(
            &strings(&[
                "git",
                "show",
                &format!("{}:package.json", field(plan, "head")?),
            ]),
            Some(&root),
        )?)?;
        let after: Value = serde_json::from_str(&run(
            &strings(&["git", "show", &format!("{commit}:package.json")]),
            Some(&root),
        )?)?;
        let (section, package) = (field(plan, "section")?, field(plan, "package")?);
        if before[section][package] != plan["old"] {
            return Err(Error::rejected(403, "reviewed old version differs"));
        }
        before[section][package] = plan["new"].clone();
        if names.trim() != "package.json" || before != after {
            return Err(Error::rejected(
                403,
                "commit contains changes outside the reviewed repair",
            ));
        }
        let destination = format!("https://github.com/{repository}.git");
        let remote_ref = format!("refs/heads/{branch}");
        if !transport(
            &strings(&["ls-remote", "--heads", &destination, &remote_ref]),
            &root,
        )?
        .trim()
        .is_empty()
        {
            return Err(Error::rejected(
                403,
                "destination branch already exists; choose a new branch",
            ));
        }
        transport(
            &strings(&[
                "push",
                &format!("--force-with-lease={remote_ref}:"),
                &destination,
                &format!("{commit}:{remote_ref}"),
            ]),
            &root,
        )?;
        repairs
            .db
            .execute("UPDATE claims SET status='pr-pushed' WHERE item=?", [item])?;
        repairs.audit(
            item,
            "pr-branch-pushed",
            &json!({"repository":repository,"branch":branch,"commit":commit}),
        )?;
        repairs.db.execute_batch("COMMIT")?;
        let body=format!("## Summary\n\nUpdate {package} from {} to {}.\n\n## Evidence\n\nConfigured checks passed on commit {commit}. Approved plan digest: {reviewed}. Policy checked again before publishing.\n\n## Merge Danger\n\n**Door:** two-way\n\n**Blast Radius:** dependency\n\nReview the diff and run CI before merging. Deployment remediation requires a re-scan. Revert this dependency change to undo. No automatic merge is configured.",field(plan,"old")?,field(plan,"new")?);
        let mut body_file = tempfile::NamedTempFile::new()?;
        body_file.write_all(body.as_bytes())?;
        let mut command = Command::new("gh");
        command
            .args([
                "pr",
                "create",
                "--repo",
                repository,
                "--base",
                base,
                "--head",
                branch,
                "--draft",
                "--title",
                "Apply reviewed dependency repair",
                "--body-file",
            ])
            .arg(body_file.path())
            .env_clear()
            .env("PATH", search_path())
            .env("HOME", home())
            .env("LANG", "C.UTF-8")
            .env("GH_HOST", "github.com")
            .env("GH_PROMPT_DISABLED", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let url = bounded(command)?.trim().to_string();
        repairs
            .db
            .execute("UPDATE claims SET status='published' WHERE item=?", [item])?;
        repairs.audit(
            item,
            "pr-opened",
            &json!({"url":url,"digest":reviewed,"commit":commit}),
        )?;
        Ok(json!({"url":url,"commit":commit,"branch":branch}))
    })();
    if let Err(e) = &result {
        let _ = repairs.db.execute_batch("ROLLBACK");
        repairs.audit(
            item,
            "refused",
            &json!({"stage":"publish","error":e.to_string()}),
        )?;
    }
    result
}

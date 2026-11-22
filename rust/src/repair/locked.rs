use super::commands::*;
use crate::{policy::Policy, Error, Result};
use serde_json::{json, Value};
use std::{fs, path::Path};

fn dependency_map(value: &Value) -> Result<()> {
    let names = regex::Regex::new(r"^(?:@[a-z0-9][a-z0-9._\-]*/)?[a-z0-9][a-z0-9._\-]*$").unwrap();
    // Restrict resolution to numeric semver ranges. Tags, aliases, URLs, local and Git
    // specs require a separately reviewed workflow; npm must not interpret them here.
    let ranges = regex::Regex::new(r"^[0-9xX*~^<>=|. +\-]+$").unwrap();
    for (name, spec) in value
        .as_object()
        .ok_or_else(|| Error::new("a dependency map is required"))?
    {
        if !names.is_match(name)
            || !spec
                .as_str()
                .is_some_and(|s| !s.is_empty() && ranges.is_match(s))
        {
            return Err(Error::new(
                "only numeric registry dependency ranges are supported; use manual repair",
            ));
        }
    }
    Ok(())
}

fn preflight(manifest: &Value, lock: &Value) -> Result<()> {
    let root = &lock["packages"][""];
    if !root.is_object() {
        return Err(Error::new("a lock root package is required"));
    }
    for input in [manifest, root] {
        if [
            "workspaces",
            "overrides",
            "resolutions",
            "bundledDependencies",
            "bundleDependencies",
        ]
        .iter()
        .any(|key| input.get(key).is_some())
        {
            return Err(Error::new(
                "workspace, override and bundled resolution require manual repair",
            ));
        }
    }
    let exact = regex::Regex::new(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$").unwrap();
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if manifest.get(section) != root.get(section) {
            return Err(Error::new(
                "manifest and lock root dependency maps disagree",
            ));
        }
        if let Some(map) = manifest.get(section) {
            dependency_map(map)?;
            for (name, spec) in map.as_object().unwrap() {
                let version = &lock["packages"][format!("node_modules/{name}")]["version"];
                if !version.as_str().is_some_and(|s| exact.is_match(s))
                    || (spec.as_str().is_some_and(|s| exact.is_match(s)) && version != spec)
                {
                    return Err(Error::new(
                        "direct registry dependency is missing or disagrees with the lock",
                    ));
                }
            }
        }
    }
    registry_only(lock)?;
    if let Some(legacy) = lock.get("dependencies") {
        legacy_dependencies(legacy)?;
    }
    Ok(())
}

fn legacy_dependencies(dependencies: &Value) -> Result<()> {
    let map = dependencies
        .as_object()
        .ok_or_else(|| Error::new("a legacy dependency map is required"))?;
    for (name, package) in map {
        let mut entry = package.clone();
        entry
            .as_object_mut()
            .ok_or_else(|| Error::new("a legacy dependency object is required"))?
            .remove("dependencies");
        registry_only(&json!({"packages":{name:entry}}))?;
        if let Some(requires) = package.get("requires") {
            dependency_map(requires)?;
        }
        if let Some(nested) = package.get("dependencies") {
            legacy_dependencies(nested)?;
        }
    }
    Ok(())
}

fn registry_only(lock: &Value) -> Result<()> {
    let packages = lock["packages"]
        .as_object()
        .ok_or_else(|| Error::new("lock packages are required"))?;
    let numeric = regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").unwrap();
    for (name, package) in packages {
        if name.is_empty() {
            continue;
        }
        if !package["version"]
            .as_str()
            .is_some_and(|v| numeric.is_match(v))
        {
            return Err(Error::new("a numeric locked registry version is required"));
        }
        if [
            "workspaces",
            "overrides",
            "resolutions",
            "bundledDependencies",
            "bundleDependencies",
        ]
        .iter()
        .any(|key| package.get(key).is_some())
        {
            return Err(Error::new("unsupported locked resolution input"));
        }
        for section in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            if let Some(map) = package.get(section) {
                dependency_map(map)?;
            }
        }
        let url=package["resolved"].as_str().and_then(|s|url::Url::parse(s).ok())
            .ok_or_else(||Error::new("a registry tarball URL is required; use manual repair for local, Git or linked dependencies"))?;
        if url.scheme() != "https"
            || url.host_str() != Some("registry.npmjs.org")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().ends_with(".tgz")
            || package["link"] == true
        {
            return Err(Error::new(
                "only public npm registry tarballs are supported; use manual repair",
            ));
        }
    }
    Ok(())
}

pub fn resolve(
    root: &Path,
    package: &str,
    version: &str,
    policy: &Policy,
    runtime: Option<&Value>,
    scan: impl FnOnce(&Path) -> Result<Value>,
) -> Result<Value> {
    let mut result = json!({"status":"failed","coverage":"unknown","findings":[],"errors":[]});
    let outcome = (|| -> Result<()> {
        if !regex::Regex::new(r"^(?:@[a-z0-9][a-z0-9._\-]*/)?[a-z0-9][a-z0-9._\-]*$")
            .unwrap()
            .is_match(package)
        {
            return Err(Error::new("a registry package name is required"));
        }
        if policy.decision(package, "patch", &json!(1), None) != "allow" {
            result["status"] = json!("denied");
            return Ok(());
        }
        let runtime = runtime
            .and_then(Value::as_object)
            .filter(|r| r.len() == 2 && r.contains_key("node") && r.contains_key("npm"))
            .ok_or_else(|| Error::new("explicit absolute paths for node and npm are required"))?;
        let mut executables = Vec::new();
        for key in ["node", "npm"] {
            let path = Path::new(
                runtime[key]
                    .as_str()
                    .ok_or_else(|| Error::new("runtime path must be text"))?,
            );
            if !path.is_absolute() {
                return Err(Error::new("absolute runtime paths are required"));
            }
            let path = fs::canonicalize(path)?;
            regular(&path, u64::MAX)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let m = fs::metadata(&path)?;
                let uid = run(&strings(&["id", "-u"]), None)?
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| Error::new("cannot identify runtime owner"))?;
                if m.mode() & 0o022 != 0 || m.uid() != 0 && m.uid() != uid {
                    return Err(Error::new("runtime must be owner-writable only"));
                }
            }
            executables.push(path.to_string_lossy().into_owned());
        }
        let root = fs::canonicalize(root)?;
        if root.join(".npmrc").exists()
            || home().join(".npmrc").exists()
            || root.join("npm-shrinkwrap.json").exists()
        {
            return Err(Error::new(
                "npm configuration requires separate owner review",
            ));
        }
        if !run(&strings(&["git", "status", "--porcelain"]), Some(&root))?
            .trim()
            .is_empty()
        {
            return Err(Error::new("a clean repository is required"));
        }
        for name in ["package.json", "package-lock.json"] {
            regular(&root.join(name), 4_000_000)?;
        }
        let manifest = read_json(&root.join("package.json"))?;
        let lock = read_json(&root.join("package-lock.json"))?;
        if !manifest.is_object()
            || !lock["packages"].is_object()
            || ![json!(2), json!(3)].contains(&lock["lockfileVersion"])
        {
            return Err(Error::new(
                "manifest and npm lockfile v2/v3 objects are required",
            ));
        }
        preflight(&manifest, &lock)?;
        let sections: Vec<_> = ["dependencies", "devDependencies"]
            .into_iter()
            .filter(|s| manifest[s].get(package).is_some())
            .collect();
        if sections.len() != 1 {
            return Err(Error::new("exactly one direct dependency is required"));
        }
        patch_versions(field(&manifest[sections[0]], package)?, version)?;
        let temp = tempfile::tempdir()?;
        let clone = temp.path().join("repo");
        run(
            &strings(&[
                "git",
                "clone",
                "--no-local",
                "--no-hardlinks",
                "--",
                &root.to_string_lossy(),
                &clone.to_string_lossy(),
            ]),
            None,
        )?;
        if policy.decision(package, "patch", &json!(1), None) != "allow" {
            return Err(Error::new("policy changed"));
        }
        // Resolve only the snapshot that was inspected, including the files npm reads.
        if read_json(&clone.join("package.json"))? != manifest
            || read_json(&clone.join("package-lock.json"))? != lock
            || clone.join(".npmrc").exists()
            || clone.join("npm-shrinkwrap.json").exists()
        {
            return Err(Error::new("repository changed since preflight"));
        }
        let mut argv = executables.clone();
        argv.push("--version".into());
        result["runtime_version"] = json!(run(&argv, None)?.trim());
        let user_config = temp.path().join("npm-user-config");
        let global_config = temp.path().join("npm-global-config");
        fs::write(&user_config, "")?;
        fs::write(&global_config, "")?;
        let mut command = executables;
        command.push(format!("--userconfig={}", user_config.display()));
        command.push(format!("--globalconfig={}", global_config.display()));
        command.extend(strings(&[
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--save-exact",
            "--registry=https://registry.npmjs.org",
            "--",
            &format!("{package}@{version}"),
        ]));
        run(&command, Some(&clone))?;
        let updated = read_json(&clone.join("package.json"))?;
        let resolved = read_json(&clone.join("package-lock.json"))?;
        registry_only(&resolved)?;
        let mut expected = manifest;
        expected[sections[0]][package] = json!(version);
        if updated != expected
            || resolved["packages"][format!("node_modules/{package}")]["version"] != version
        {
            return Err(Error::new("unexpected manifest delta or resolved version"));
        }
        let mut names: Vec<_> = run(
            &strings(&[
                "git",
                "diff",
                "--no-textconv",
                "--no-ext-diff",
                "--name-only",
            ]),
            Some(&clone),
        )?
        .lines()
        .map(String::from)
        .collect();
        names.sort();
        if names != ["package-lock.json", "package.json"] {
            return Err(Error::new("unexpected repository delta"));
        }
        let previous = lock["packages"].as_object().unwrap();
        let current = resolved["packages"]
            .as_object()
            .ok_or_else(|| Error::new("resolved packages are required"))?;
        let keys: std::collections::BTreeSet<_> = previous.keys().chain(current.keys()).collect();
        let delta: Vec<_> = keys
            .into_iter()
            .filter(|k| previous.get(*k) != current.get(*k))
            .map(|k| json!({"path":k,"before":previous.get(k),"after":current.get(k)}))
            .collect();
        let assessment = scan(&clone)?;
        if assessment["coverage"] != "complete" || !assessment["findings"].is_array() {
            return Err(Error::new("re-scan is incomplete"));
        }
        result["status"] = json!("resolved");
        result["coverage"] = json!("complete");
        result["findings"] = assessment["findings"].clone();
        result["manifest"] = updated;
        result["lockfile"] = resolved;
        result["command"] = json!(command);
        result["package_delta"] = json!(delta);
        Ok(())
    })();
    if let Err(e) = outcome {
        result["errors"]
            .as_array_mut()
            .unwrap()
            .push(json!(e.to_string()));
    }
    Ok(result)
}

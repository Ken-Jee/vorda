use crate::{Error, Result};
use std::{collections::BTreeMap, fs, path::Path};

pub fn render(dist: &Path, repository: &str, version: &str, output: &Path) -> Result<()> {
    let url = url::Url::parse(repository).map_err(|e| Error::usage(e.to_string()))?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || !url
            .path()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
    {
        return Err(Error::usage(
            "repository must be an HTTPS GitHub repository URL",
        ));
    }
    if version.is_empty()
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return Err(Error::usage("invalid release version"));
    }
    let mut hashes = BTreeMap::new();
    for line in fs::read_to_string(dist.join("SHA256SUMS"))?.lines() {
        let (hash, name) = line
            .split_once("  ")
            .ok_or_else(|| Error::new("invalid SHA256SUMS line"))?;
        if hash.len() != 64
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
            || hashes.insert(name.to_owned(), hash.to_owned()).is_some()
        {
            return Err(Error::new("invalid or duplicate artifact checksum"));
        }
    }
    let mut values = vec![
        ("@VERSION@", version.to_owned()),
        ("@REPO_URL@", repository.trim_end_matches('/').to_owned()),
    ];
    for (token, target) in [
        ("@SHA256_MAC_ARM64@", "aarch64-apple-darwin"),
        ("@SHA256_MAC_X64@", "x86_64-apple-darwin"),
        ("@SHA256_LINUX_ARM64@", "aarch64-unknown-linux-gnu"),
        ("@SHA256_LINUX_X64@", "x86_64-unknown-linux-gnu"),
        ("@SHA256_EXE_UPPER@", "x86_64-pc-windows-msvc.exe"),
    ] {
        let name = format!("vorda-{version}-{target}");
        let hash = hashes
            .get(&name)
            .ok_or_else(|| Error::new(format!("missing artifact checksum: {name}")))?;
        values.push((
            token,
            if token == "@SHA256_EXE_UPPER@" {
                hash.to_uppercase()
            } else {
                hash.to_lowercase()
            },
        ));
    }
    let templates = [
        (
            "homebrew/vorda.rb",
            include_str!("../../release/templates/homebrew/vorda.rb.in"),
        ),
        (
            "winget/Ken-Jee.vorda.installer.yaml",
            include_str!("../../release/templates/winget/Ken-Jee.vorda.installer.yaml.in"),
        ),
        (
            "winget/Ken-Jee.vorda.locale.en-US.yaml",
            include_str!("../../release/templates/winget/Ken-Jee.vorda.locale.en-US.yaml.in"),
        ),
        (
            "winget/Ken-Jee.vorda.yaml",
            include_str!("../../release/templates/winget/Ken-Jee.vorda.yaml.in"),
        ),
        (
            "mcp/server.json",
            include_str!("../../release/templates/mcp/server.json.in"),
        ),
    ];
    if output.exists() {
        return Err(Error::new("manifest output already exists"));
    }
    for (name, template) in templates {
        let mut text = template.to_owned();
        for (token, value) in &values {
            text = text.replace(token, value);
        }
        let path = output.join(name);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, text)?;
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<i32> {
    let mut dist = None;
    let mut repository = None;
    let mut version = None;
    let mut output = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--help" || arg == "-h" {
            println!("Usage: vorda render-manifests --dist DIR --repo-url URL --version VERSION --out DIR");
            return Ok(0);
        }
        let slot = match arg.as_str() {
            "--dist" => &mut dist,
            "--repo-url" => &mut repository,
            "--version" => &mut version,
            "--out" => &mut output,
            _ => {
                return Err(Error::usage(format!(
                    "unrecognized manifest argument: {arg}"
                )))
            }
        };
        if slot.is_some() {
            return Err(Error::usage(format!("duplicate argument: {arg}")));
        }
        *slot = Some(
            iter.next()
                .filter(|value| !value.starts_with("--") && !matches!(value.as_str(), "-h" | "-V"))
                .ok_or_else(|| Error::usage(format!("{arg} requires a value")))?
                .clone(),
        );
    }
    render(
        Path::new(&dist.ok_or_else(|| Error::usage("--dist is required"))?),
        &repository.ok_or_else(|| Error::usage("--repo-url is required"))?,
        &version.ok_or_else(|| Error::usage("--version is required"))?,
        Path::new(&output.ok_or_else(|| Error::usage("--out is required"))?),
    )?;
    Ok(0)
}

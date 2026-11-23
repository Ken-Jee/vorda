use super::{error, input, package, record};
use crate::{
    domain::{InventoryOptions, Package, Record},
    Result,
};
use regex::Regex;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    rc::Rc,
    time::{Duration, Instant},
};

pub mod installed;
mod lock_validation;

pub const LOCKS: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "go.mod",
    "Gemfile.lock",
    "composer.lock",
    "packages.lock.json",
];
/// Folders never read: version-control internals, and installed copies of what a lockfile
/// lists. Every other folder is walked unless `generated` names it.
pub const SKIP: &[&str] = &[".git", "node_modules"];
/// Folders under the home folder a machine scan never walks: package caches, toolchains,
/// downloads, app data and the trash. The lockfiles in them are not the person's projects.
pub const HOME_SKIP: &[&str] = &[
    ".cache",
    ".cargo",
    ".rustup",
    ".npm",
    ".pnpm-store",
    ".yarn",
    ".bun",
    ".deno",
    ".nvm",
    ".pyenv",
    ".rbenv",
    ".gem",
    ".bundle",
    ".m2",
    ".gradle",
    ".nuget",
    ".dotnet",
    ".conda",
    ".local",
    ".config",
    ".var",
    ".vscode",
    ".vscode-server",
    ".cursor",
    ".mozilla",
    ".docker",
    ".steam",
    ".wine",
    ".Trash",
    "go/pkg",
    "snap",
    "Downloads",
    "Library",
    "AppData",
    "scoop",
];
/// Entries a machine scan may visit under the home folder; a project scan stops at 100,000.
const MACHINE_WORK: usize = 1_000_000;
/// Evidence reason for a `HOME_SKIP` folder.
const COPY_HOME_SKIPPED: &str =
    "home cache, toolchain, download, app-data, or trash folder skipped in a machine scan";
/// Warning and evidence reason for a symlinked folder under the home folder.
const COPY_HOME_LINK: &str =
    "symlinked folder not followed in a machine scan (run vorda scan PATH to check it)";
/// Ends the warning for a symlinked folder skipped because its target is read in the scan.
pub const READ_THERE: &str = "is inside the scanned folder and is read there";
/// Folders of test and example data. Their packages are likely dev-only, and a file in one that
/// Vorda cannot check is listed as not covered instead of making the whole scan unknown.
const TEST_DATA: &[&str] = &[
    "test",
    "tests",
    "testdata",
    "__tests__",
    "__fixtures__",
    "fixtures",
    "example",
    "examples",
];
/// Ends the warning for a test or example file Vorda could not check.
pub const NOT_COVERED_TEST_DATA: &str = "this file is in a test or example folder, so it is listed as not covered instead of making the scan unknown";

/// The file sits in a test or example folder below the scan root (never the root itself).
fn test_data(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root)
        .ok()
        .and_then(Path::parent)
        .is_some_and(|dir| {
            dir.components().any(|c| {
                c.as_os_str()
                    .to_str()
                    .is_some_and(|n| TEST_DATA.iter().any(|t| t.eq_ignore_ascii_case(n)))
            })
        })
}

fn skip_test_data(
    path: &Path,
    reason: &str,
    warnings: &mut Vec<String>,
    evidence: &mut Vec<Value>,
) {
    warnings.push(format!(
        "{}: {reason}; {NOT_COVERED_TEST_DATA}",
        path.display()
    ));
    evidence.push(json!({"kind":"not-covered-test-data","path":path,"reason":reason}));
}

/// What a folder is when a tool made it: an installed Python environment, or a build output or
/// cache that marks itself with CACHEDIR.TAG (cargo's `target` does). Such a folder is not
/// walked, only searched for lockfiles by `lockfile_within`.
fn generated(dir: &Path) -> Option<&'static str> {
    // Only a marker a tool wrote counts: a venv's config names its `home`, and a cache tag
    // starts with the standard signature.
    let starts = |name: &str, prefix: &str| {
        input::read_regular(&dir.join(name), None, 4096, true).is_ok_and(|bytes| {
            String::from_utf8_lossy(&bytes)
                .lines()
                .any(|line| line.starts_with(prefix))
        })
    };
    // Tools that download or build into these never write a marker.
    let named = dir.file_name().and_then(|n| n.to_str());
    if named == Some(".vscode-test") {
        Some("VS Code test download")
    } else if named == Some(".next") {
        Some("Next.js build output")
    } else if starts("pyvenv.cfg", "home") {
        Some("Python virtual environment")
    } else if starts(
        "CACHEDIR.TAG",
        "Signature: 8a477f597d28d172789f06886806bc55",
    ) {
        Some("build or cache folder (CACHEDIR.TAG)")
    } else {
        None
    }
}

/// Entries a generated folder may hold before it is too large to search.
const SEARCH_ENTRIES: usize = 200_000;

/// Why a generated folder cannot be skipped as clean: it holds a supported lockfile, or it
/// could not be searched whole. `None` when it holds no lockfile.
fn lockfile_within(dir: &Path) -> Option<String> {
    let mut stack = vec![dir.to_path_buf()];
    let mut seen = 0;
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => return Some(format!("could not be searched ({}: {e})", dir.display())),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => return Some(format!("could not be searched ({}: {e})", dir.display())),
            };
            seen += 1;
            if seen > SEARCH_ENTRIES {
                return Some(format!(
                    "holds over {SEARCH_ENTRIES} entries, too many to search for lockfiles"
                ));
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if supported(&name) {
                return Some(format!(
                    "holds {}, which was not read",
                    entry.path().display()
                ));
            }
            if entry.file_type().is_ok_and(|t| t.is_dir()) && !SKIP.contains(&name.as_str()) {
                stack.push(entry.path());
            }
        }
    }
    None
}
pub fn supported(name: &str) -> bool {
    LOCKS.contains(&name)
        || pylock(name)
        || name.starts_with("requirements") && name.ends_with(".txt")
}
/// A PEP 751 lockfile: `pylock.toml` or `pylock.<name>.toml`, with no dot in the name.
fn pylock(name: &str) -> bool {
    name == "pylock.toml"
        || name
            .strip_prefix("pylock.")
            .and_then(|rest| rest.strip_suffix(".toml"))
            .is_some_and(|middle| !middle.is_empty() && !middle.contains('.'))
}
/// A compiled file beside a requirements input lists its exact versions, so that file is read
/// instead of the input: a `<stem>.txt` Vorda reads, or a pylock in the same folder that lists
/// every package the input names.
fn compiled(input: &Path, root: &Path) -> bool {
    let present = |path: &Path| path.symlink_metadata().is_ok_and(|m| !m.is_dir());
    let txt = input.with_extension("txt");
    if present(&txt)
        && (txt
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(supported)
            || requirements_input(&txt, root))
    {
        return true;
    }
    let normal = |name: &str| {
        rx(r"[-_.]+")
            .replace_all(&name.to_ascii_lowercase(), "-")
            .into_owned()
    };
    // Only plain requirement lines can be matched to a pylock: an option, include or direct
    // reference keeps the input read.
    let Some(wanted) = read_text(input, root).and_then(|text| {
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let name = rx(r"^([A-Za-z0-9][A-Za-z0-9._-]*)");
        text.lines()
            .map(|line| line.split(" #").next().unwrap_or(line).trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                name.captures(line)
                    .filter(|_| !line.contains(['@', '/', '\\']))
                    .map(|c| normal(&c[1]))
            })
            .collect::<Option<Vec<_>>>()
    }) else {
        return false;
    };
    let Some(entries) = input.parent().and_then(|dir| fs::read_dir(dir).ok()) else {
        return false;
    };
    entries.filter_map(|e| e.ok()).any(|e| {
        let Some(name) = e
            .file_name()
            .to_str()
            .filter(|n| pylock(n))
            .map(str::to_owned)
        else {
            return false;
        };
        let listed: Option<std::collections::HashSet<String>> = present(&e.path())
            .then(|| read_text(&e.path(), root))
            .flatten()
            .and_then(|text| lock_validation::toml_lock(&name, &text).ok())
            .and_then(|data| {
                data.get("packages")?.as_array().map(|packages| {
                    packages
                        .iter()
                        .filter_map(|p| p.get("name")?.as_str())
                        .map(normal)
                        .collect()
                })
            });
        listed.is_some_and(|listed| wanted.iter().all(|w| listed.contains(w)))
    })
}
/// A requirements file whose name alone does not mark it as read: `requirements*.in` with no
/// compiled file beside it, or a `.txt` or `.in` of requirement lines under a `requirements`
/// folder. Its exact pins are read like requirements.txt.
fn requirements_input(path: &Path, root: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let input = name.ends_with(".in");
    if name.starts_with("constraints") || !input && !name.ends_with(".txt") {
        return false;
    }
    if input && compiled(path, root) {
        return false;
    }
    let parent = path.parent().unwrap_or(root);
    let in_directory = parent
        .ancestors()
        .take_while(|p| p.starts_with(root))
        .any(|p| p.file_name().is_some_and(|n| n == "requirements"));
    // An unreadable file is taken in, so reading it reports the error.
    input && name.starts_with("requirements")
        || in_directory && requirement_content(path, root).unwrap_or(true)
}
fn python_dependencies(value: &toml::Value) -> bool {
    if value
        .get("project")
        .is_some_and(|project| project.as_table().is_none())
    {
        return true;
    }
    fn populated(value: &toml::Value) -> bool {
        match value {
            toml::Value::Array(a) => a.iter().any(populated),
            toml::Value::Table(t) => t.values().any(populated),
            _ => true,
        }
    }
    fn dependency_tables(value: &toml::Value) -> bool {
        ["dependencies", "optional-dependencies", "dev-dependencies"]
            .iter()
            .any(|key| value.get(*key).is_some_and(populated))
    }
    value.get("project").is_some_and(dependency_tables)
        || value
            .get("project")
            .and_then(|project| project.get("dynamic"))
            .and_then(toml::Value::as_array)
            .is_some_and(|fields| {
                fields.iter().any(|field| {
                    matches!(
                        field.as_str(),
                        Some("dependencies" | "optional-dependencies")
                    )
                })
            })
        || value.get("dependency-groups").is_some_and(populated)
        || value.get("tool").is_some_and(|tools| {
            ["poetry", "pdm"].iter().any(|name| {
                tools.get(*name).is_some_and(|settings| {
                    dependency_tables(settings)
                        || settings
                            .get("group")
                            .and_then(toml::Value::as_table)
                            .is_some_and(|groups| groups.values().any(dependency_tables))
                })
            }) || tools
                .get("uv")
                .and_then(|uv| uv.get("dev-dependencies"))
                .is_some_and(populated)
                || tools
                    .get("hatch")
                    .and_then(|hatch| hatch.get("envs"))
                    .and_then(toml::Value::as_table)
                    .is_some_and(|envs| envs.values().any(dependency_tables))
                || tools.get("pixi").is_some_and(dependency_tables)
                || tools
                    .get("flit")
                    .and_then(|flit| flit.get("metadata"))
                    .is_some_and(|metadata| {
                        ["requires", "requires-extra"]
                            .iter()
                            .any(|key| metadata.get(*key).is_some_and(populated))
                    })
        })
}

fn requirement_content(path: &Path, root: &Path) -> Result<bool> {
    let text = String::from_utf8(input::read_regular(
        path,
        Some(root),
        input::MAX_FILE,
        false,
    )?)
    .map_err(error)?;
    let requirement = rx(
        r"^[A-Za-z0-9][A-Za-z0-9_.-]*(?:\s*\[[^\]]+\])?(?:\s*(?:(?:===|==|~=|!=|<=|>=|<|>|@|;).*|\(\s*(?:===|==|~=|!=|<=|>=|<|>)[^)]*\)(?:\s*;.*)?))?$",
    );
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let line = line
            .split_once(" #")
            .map_or(line, |(requirement, _)| requirement)
            .trim();
        if requirement.is_match(line)
            || line.starts_with('-')
            || [
                "\\", "http://", "https://", "git+", "hg+", "svn+", "bzr+", "./", "../", "/",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unsupported(path: &Path, root: &Path) -> Result<Option<String>> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = path.parent().unwrap_or(root);
    let present = |path: &Path| path.symlink_metadata().is_ok_and(|m| !m.is_dir());
    // A lock higher up that does not list this folder, named when nothing else covers it.
    let unlisted = std::cell::Cell::new(None::<PathBuf>);
    // A package.json with nothing to lock needs no lock of its own under one higher up.
    let free = name == "package.json" && !js_dependencies(path, root);
    let under_lock = |names: &[&str]| {
        parent
            .ancestors()
            .take_while(|p| p.starts_with(root))
            .any(|p| {
                names.iter().any(|name| {
                    let lock = p.join(name);
                    present(&lock)
                        && (p == parent || free || listed(&lock, parent, root) || {
                            unlisted.set(Some(lock));
                            false
                        })
                })
            })
    };
    let python_locks = ["poetry.lock", "uv.lock", "Pipfile.lock", "pylock.toml"];
    let missing = match name {
        "package.json"
            if !under_lock(&[
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "bun.lock",
                "bun.lockb",
            ]) =>
        {
            Some((
                "package-lock.json (or your package manager's supported lockfile)",
                "npm install --package-lock-only",
            ))
        }
        "Cargo.toml" if !under_lock(&["Cargo.lock"]) => {
            Some(("Cargo.lock", "cargo generate-lockfile"))
        }
        "Gemfile" if !under_lock(&["Gemfile.lock"]) => {
            Some(("Gemfile.lock", "bundle lock"))
        }
        "gems.rb" if !under_lock(&["Gemfile.lock"]) => return Ok(Some("Vorda does not read gems.locked (the lockfile for gems.rb); this dependency format is not supported. Scan a supported Gemfile.lock instead.".into())),
        _ if name.ends_with(".gemspec") && !under_lock(&["Gemfile.lock"]) => {
            Some(("Gemfile.lock", "bundle lock"))
        }
        "composer.json" if !under_lock(&["composer.lock"]) => {
            Some(("composer.lock", "composer update --no-install"))
        }
        "Pipfile" if !present(&parent.join("Pipfile.lock")) => Some(("Pipfile.lock", "pipenv lock")),
        "pyproject.toml" | "setup.py" | "setup.cfg" => {
            let requirements = fs::read_dir(parent).is_ok_and(|entries| {
                entries.filter_map(|e| e.ok()).any(|e| {
                    e.file_type().is_ok_and(|t| !t.is_dir())
                        && e.file_name().to_str().is_some_and(|name| {
                            name.starts_with("requirements") && name.ends_with(".txt")
                        })
                })
            });
            if under_lock(&python_locks) || requirements {
                return Ok(None);
            }
            if name == "pyproject.toml" {
                let text = String::from_utf8(input::read_regular(
                    path,
                    Some(root),
                    input::MAX_FILE,
                    false,
                )?)
                .map_err(|_| error("cannot determine pyproject.toml dependencies: invalid UTF-8; coverage is unknown"))?;
                lock_validation::toml_bounded(&text).map_err(|_| error("cannot determine pyproject.toml dependencies: too large or too deeply nested to read safely; coverage is unknown"))?;
                let value: toml::Value = toml::from_str(&text).map_err(|_| error("cannot determine pyproject.toml dependencies: invalid TOML; coverage is unknown"))?;
                if !python_dependencies(&value) {
                    return Ok(None);
                }
            }
            Some((
                "uv.lock, poetry.lock, Pipfile.lock or pinned requirements.txt",
                "uv lock",
            ))
        }
        "packages.config" | "Directory.Packages.props" if !under_lock(&["packages.lock.json"]) => {
            Some(("packages.lock.json", "dotnet restore --use-lock-file"))
        }
        _ if [".csproj", ".fsproj", ".vbproj"]
            .iter()
            .any(|extension| name.ends_with(extension))
            && !under_lock(&["packages.lock.json"]) =>
        {
            Some(("packages.lock.json", "dotnet restore --use-lock-file"))
        }
        _ => None,
    };
    if let Some((lock, command)) = missing {
        if let Some(above) = unlisted.take() {
            let above = above.strip_prefix(root).unwrap_or(&above).display();
            return Ok(Some(format!("{above} does not list this folder as a workspace member or path dependency, so it does not cover {name}. Generate and commit {lock} here (usual command: `{command}`), or add this folder to that workspace.")));
        }
        return Ok(Some(format!("No supported lockfile found for {name}. Generate and commit {lock} (usual command: `{command}`), or scan where the lockfile is inside the selected root.")));
    }
    if [
        "package.json",
        "Cargo.toml",
        "Gemfile",
        "gems.rb",
        "composer.json",
        "Pipfile",
        "packages.config",
        "Directory.Packages.props",
    ]
    .contains(&name)
        || [".csproj", ".fsproj", ".vbproj", ".gemspec"]
            .iter()
            .any(|extension| name.ends_with(extension))
    {
        return Ok(None);
    }
    if [
        "pom.xml",
        "POM.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "gradle.lockfile",
        "libs.versions.toml",
        "npm-shrinkwrap.json",
        "pdm.lock",
        "mix.lock",
        "mix.exs",
        "pubspec.lock",
        "pubspec.yaml",
        "deno.lock",
        "deno.json",
        "deno.jsonc",
        // Read when spelled exactly; another letter case is named, not silently ignored.
        "pylock.toml",
        "Package.resolved",
        "Podfile",
        "Podfile.lock",
        "renv.lock",
        "environment.yml",
        "environment.yaml",
        "conanfile.txt",
        "build.sbt",
        "pixi.lock",
        "requirements.pip",
        "Requirements.txt",
        "gems.locked",
        "go.work",
        "Gopkg.lock",
        "Gopkg.toml",
        "paket.lock",
        "paket.dependencies",
        "Package.swift",
        "conan.lock",
        "conanfile.py",
        "vcpkg.json",
        "ivy.xml",
        "Chart.lock",
    ]
    .iter()
    // File names are matched in any case: Windows and macOS tools accept `Pom.xml`.
    .any(|known| known.eq_ignore_ascii_case(name))
        || name.starts_with("requirements") && name.ends_with(".lock")
    {
        return Ok(Some(format!(
            "Vorda does not read this dependency format ({name}); it is not supported."
        )));
    }
    if !name.starts_with("constraints") && (name.ends_with(".txt") || name.ends_with(".in")) {
        let named = name.starts_with("requirements")
            || [
                "-requirements.txt",
                "-requirements.in",
                "_requirements.txt",
                "_requirements.in",
            ]
            .iter()
            .any(|suffix| name.ends_with(suffix));
        let in_directory = parent
            .ancestors()
            .take_while(|p| p.starts_with(root))
            .any(|p| p.file_name().is_some_and(|n| n == "requirements"));
        if named || in_directory && requirement_content(path, root)? {
            if name.ends_with(".in") && compiled(path, root) {
                return Ok(None);
            }
            return Ok(Some(format!("Vorda does not read this requirements input ({name}); it is not supported. Scan exact pins in requirements.txt.")));
        }
    }
    Ok(None)
}
/// Whether a lockfile in an ancestor folder covers the manifest folder `dir`: it lists the
/// folder as a workspace member, importer or path source (Cargo: the crate as a local package),
/// or the folder is an installed copy under `vendor`.
fn listed(lock: &Path, dir: &Path, root: &Path) -> bool {
    let Some(relative) = lock.parent().and_then(|base| dir.strip_prefix(base).ok()) else {
        return false;
    };
    if relative.components().any(|c| c.as_os_str() == "vendor") {
        return true;
    }
    let listing = LISTINGS.with(|cache| {
        Rc::clone(
            cache
                .borrow_mut()
                .entry(lock.to_path_buf())
                .or_insert_with(|| Rc::new(read_listing(lock, root))),
        )
    });
    if lock.ends_with("Cargo.lock") {
        let package = read_text(&dir.join("Cargo.toml"), root)
            .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
            .and_then(|v| v.get("package").cloned());
        let Some(name) = package.as_ref().and_then(|p| p.get("name")?.as_str()) else {
            return false;
        };
        // A version inherited from the workspace is not in the manifest: match the name alone.
        return match package.as_ref().and_then(|p| p.get("version")?.as_str()) {
            Some(version) => listing.names.contains(&format!("{name}@{version}")),
            None => listing
                .names
                .iter()
                .any(|n| n.starts_with(&format!("{name}@"))),
        };
    }
    if lock.ends_with("packages.lock.json") {
        return fs::read_dir(dir).into_iter().flatten().flatten().any(|e| {
            let file = PathBuf::from(e.file_name());
            file.extension()
                .is_some_and(|x| ["csproj", "fsproj", "vbproj"].iter().any(|k| x == *k))
                && file
                    .file_stem()
                    .is_some_and(|s| listing.names.contains(&s.to_string_lossy().to_lowercase()))
        });
    }
    let relative = relative.to_string_lossy().replace('\\', "/");
    listing.names.contains(&relative)
        || listing
            .package
            .as_ref()
            .is_some_and(|members| members.member(&relative))
            // yarn 1 skips a workspace folder whose package.json has no name.
            && read_text(&dir.join("package.json"), root)
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .is_some_and(|p| p["name"].is_string())
}

/// What an ancestor lockfile lists as its own local parts, read once per scan.
#[derive(Default)]
struct Listing {
    /// Folders it names, relative and without `./`; Cargo: `name@version` of its local
    /// packages; NuGet: lowercased names of referenced projects.
    names: std::collections::HashSet<String>,
    /// The package.json beside a yarn classic lock, whose `workspaces` name the members
    /// (yarn classic records no member paths in yarn.lock).
    package: Option<lock_validation::Workspaces>,
}

thread_local! {
    static LISTINGS: std::cell::RefCell<BTreeMap<PathBuf, Rc<Listing>>> = Default::default();
}

fn read_text(path: &Path, root: &Path) -> Option<String> {
    input::read_regular(path, Some(root), input::MAX_FILE, false)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

fn read_listing(lock: &Path, root: &Path) -> Listing {
    let mut listing = Listing::default();
    let Some(text) = read_text(lock, root) else {
        return listing;
    };
    // Bounded so that many hostile locks cannot pile up in the cache. Over the bound the lock
    // lists nothing, and the manifests below it stay unknown.
    let (mut count, mut bytes, mut over) = (0usize, 0usize, false);
    let mut capture = |pattern: &str| {
        for c in rx(pattern).captures_iter(&text) {
            if over {
                return;
            }
            let found = c
                .iter()
                .skip(1)
                .flatten()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join("@");
            let found = found.trim_start_matches("./");
            // Installed copies and download URLs are never member folders.
            if found.contains("://") || found.split('/').any(|s| s == "node_modules") {
                continue;
            }
            count += 1;
            bytes += found.len();
            if count > 4 * MAX_INPUT_PACKAGES || bytes > 8 << 20 {
                over = true;
                listing.names = Default::default();
                return;
            }
            listing.names.insert(found.to_owned());
        }
    };
    match lock.file_name().and_then(|n| n.to_str()).unwrap_or("") {
        // Local packages carry no `source`; registry ones do.
        "Cargo.lock" => capture(
            r#"\[\[package\]\]\r?\nname = "([^"]+)"\r?\nversion = "([^"]+)"(?:\r?\n(?:dependencies|\r?\n|$)|$)"#,
        ),
        "packages.lock.json" => {
            let value: Value = serde_json::from_str(&text).unwrap_or_default();
            for (key, p) in value["dependencies"]
                .as_object()
                .into_iter()
                .flat_map(|targets| targets.values())
                .filter_map(Value::as_object)
                .flatten()
            {
                if p["type"]
                    .as_str()
                    .is_some_and(|t| t.eq_ignore_ascii_case("project"))
                {
                    listing.names.insert(key.to_lowercase());
                }
            }
        }
        name => {
            for pattern in [
                r#""([^"\n]+)":\s*\{"#,                  // npm packages, bun workspaces
                r"(?m)^  '?([^'\s:]+)'?:(?: \{\})?\r?$", // pnpm importers
                r#"@workspace:([^"\n]+)""#,              // yarn berry
                r#"(?:editable|virtual|directory|url) = "([^"\n]+)""#, // uv, poetry
                r#""(?:path|url)": "([^"\n]+)""#,        // Pipfile, composer
                r"(?m)^  remote: (\S+)\r?$",             // Gemfile PATH
            ] {
                capture(pattern);
            }
            // Only yarn classic leaves members out of its lock; npm, bun and yarn Berry write
            // every member in, and pnpm ignores `workspaces`.
            if name == "yarn.lock" && text.contains("# yarn lockfile v1") {
                listing.package = read_text(&lock.with_file_name("package.json"), root)
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                    // yarn 1 ignores `workspaces` unless the root is private.
                    .filter(|package| package["private"] == Value::Bool(true))
                    // Over the pattern bounds no folder is a member: each stays unknown.
                    .and_then(|package| lock_validation::Workspaces::new(Some(&package)).ok());
            }
        }
    }
    listing
}

/// Whether a package.json declares dependencies a lockfile would pin. One that declares none
/// (a build output's module-type marker, an editor SDK) has nothing to lock.
fn js_dependencies(path: &Path, root: &Path) -> bool {
    let Some(value) = read_text(path, root).and_then(|t| serde_json::from_str::<Value>(&t).ok())
    else {
        return true;
    };
    js_dependencies_in(&value)
}

fn js_dependencies_in(value: &Value) -> bool {
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "bundleDependencies",
        "bundledDependencies",
    ]
    .iter()
    .any(|key| match &value[key] {
        Value::Object(m) => !m.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Null | Value::Bool(false) => false,
        _ => true,
    })
}

/// Why a lockfile that read cleanly and lists no packages does not show a project with no
/// dependencies: it is empty, or the manifest beside it is missing, unreadable or declares
/// some. `None` when the project really declares nothing.
fn empty_lock_doubt(lock: &Path, root: &Path) -> Option<String> {
    let name = lock.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let text = read_text(lock, root).unwrap_or_default();
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    if text.trim().is_empty() {
        return Some(format!(
            "{name} is empty, so it does not show what the project depends on; coverage is unknown"
        ));
    }
    // Whether the manifest declares anything a lockfile would pin; `None` when unreadable.
    let (manifest, declares): (&str, fn(&str) -> Option<bool>) = match name {
        "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" | "bun.lock" => {
            ("package.json", |t| {
                let v = serde_json::from_str::<Value>(t)
                    .ok()
                    .filter(Value::is_object)?;
                let workspaces = !matches!(&v["workspaces"], Value::Null | Value::Bool(false))
                    && v["workspaces"] != json!([])
                    && v["workspaces"] != json!({});
                Some(workspaces || js_dependencies_in(&v))
            })
        }
        "Cargo.lock" => ("Cargo.toml", |t| {
            let v = toml::from_str::<toml::Table>(t).ok()?;
            let tables = [
                "dependencies",
                "dev-dependencies",
                "dev_dependencies",
                "build-dependencies",
                "build_dependencies",
            ];
            Some(
                v.contains_key("target")
                    || v.contains_key("workspace")
                    || tables.iter().any(|key| {
                        v.get(*key)
                            .is_some_and(|d| d.as_table().is_none_or(|d| !d.is_empty()))
                    }),
            )
        }),
        "poetry.lock" | "uv.lock" => ("pyproject.toml", |t| {
            let v = toml::from_str::<toml::Table>(t).ok()?;
            let at = |path: &[&str]| path.iter().try_fold(&v, |t, k| t.get(*k)?.as_table());
            let listed = |t: Option<&toml::Table>, key: &str| {
                t.and_then(|t| t.get(key)).is_some_and(|d| match d {
                    toml::Value::Table(d) => d.keys().any(|k| k != "python"),
                    toml::Value::Array(d) => !d.is_empty(),
                    _ => true,
                })
            };
            let project = at(&["project"]);
            let poetry = at(&["tool", "poetry"]);
            let uv = at(&["tool", "uv"]);
            // `dynamic = ["dependencies"]`: the build backend fills them in.
            let dynamic = project
                .and_then(|p| p.get("dynamic")?.as_array())
                .is_some_and(|d| d.iter().any(|f| f.as_str() != Some("version")));
            Some(
                listed(project, "dependencies")
                    || listed(project, "optional-dependencies")
                    || dynamic
                    || v.contains_key("dependency-groups")
                    || listed(poetry, "dependencies")
                    || listed(poetry, "dev-dependencies")
                    || listed(poetry, "group")
                    || listed(uv, "dev-dependencies")
                    || listed(uv, "workspace"),
            )
        }),
        "Pipfile.lock" => ("Pipfile", |t| {
            let v = toml::from_str::<toml::Table>(t).ok()?;
            Some(v.iter().any(|(k, d)| {
                !["source", "requires", "scripts", "pipenv"].contains(&k.as_str())
                    && d.as_table().is_none_or(|d| !d.is_empty())
            }))
        }),
        "composer.lock" => ("composer.json", |t| {
            let v = serde_json::from_str::<Value>(t)
                .ok()
                .filter(Value::is_object)?;
            Some(["require", "require-dev"].iter().any(|key| match &v[key] {
                Value::Object(m) => m.keys().any(|k| k != "php" && !k.starts_with("ext-")),
                Value::Null => false,
                _ => true,
            }))
        }),
        // Only `source` and `ruby` lines: every other line can add gems.
        "Gemfile.lock" => ("Gemfile", |t| {
            Some(t.lines().map(str::trim).any(|l| {
                !(l.is_empty()
                    || l.starts_with('#')
                    || l.starts_with("source ")
                    || l.starts_with("ruby "))
            }))
        }),
        "go.sum" => ("go.mod", |t| Some(!go_mod(t).selected.is_empty())),
        // go.mod and requirements files are their own manifests.
        "go.mod" if go_mod(text).selected.is_empty() => return None,
        "go.mod" => {
            return Some(
                "go.mod requires modules but go.sum lists none; coverage is unknown".into(),
            )
        }
        _ if name.starts_with("requirements")
            && text
                .lines()
                .all(|l| l.trim().is_empty() || l.trim().starts_with('#')) =>
        {
            return None
        }
        _ => return Some(format!("{name} lists no packages; coverage is unknown")),
    };
    let beside = lock.with_file_name(manifest);
    if name == "pnpm-lock.yaml" && beside.with_file_name("pnpm-workspace.yaml").exists() {
        return Some(format!("pnpm-workspace.yaml may name workspace packages but {name} lists none; coverage is unknown"));
    }
    match read_text(&beside, root).as_deref().and_then(declares) {
        Some(false) => None,
        Some(true) => Some(format!(
            "{manifest} declares dependencies but {name} lists none; coverage is unknown"
        )),
        None => Some(format!("{name} lists no packages and there is no readable {manifest} beside it to show the project declares none; coverage is unknown")),
    }
}

fn rx(s: &str) -> Regex {
    Regex::new(s).expect("static parser expression")
}

/// The package a Yarn Berry block installs, from its `resolution`.
fn yarn_resolved_name(block: &str) -> Option<String> {
    let resolution = rx(r#"\n[ \t]+resolution:[ \t]+"?([^"\r\n]+)"?"#).captures(block)?;
    lock_validation::locator(&resolution[1])
        .map(|(name, _)| name.to_string())
        .filter(|name| !name.is_empty())
}

const GO_BEFORE_117: &str = "Coverage: this go.mod declares a Go version before 1.17 (or none), so its require list can omit indirect dependencies; commit go.sum beside it, or run `go mod tidy -go=1.17` and scan again";

/// The modules a go.mod selects, after `replace`, plus its Go version.
struct GoMod {
    /// (module, version, replacement source): a local replacement has no version.
    selected: Vec<(String, String, Option<String>)>,
    /// Go 1.17+ lists every module the build needs, indirect ones included.
    complete_graph: bool,
    /// Lines Vorda cannot read as go.mod syntax: their modules may be missing.
    unreadable: Vec<String>,
    /// More entries than the per-input cap; reading stopped there.
    over_cap: bool,
}

fn go_mod(text: &str) -> GoMod {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut go = None;
    let mut require = Vec::new();
    let mut replace = Vec::new();
    let mut unreadable = Vec::new();
    let mut block: Option<String> = None;
    // Requires and unreadable lines are entries; replace lines are bounded on their own.
    let over = |require: &Vec<_>, replace: &Vec<_>, unreadable: &Vec<_>| {
        require.len() + unreadable.len() > MAX_INPUT_PACKAGES || replace.len() > MAX_INPUT_PACKAGES
    };
    let mut over_cap = false;
    for (number, raw) in text.lines().enumerate() {
        if over(&require, &replace, &unreadable) {
            over_cap = true;
            break;
        }
        let line = raw.split("//").next().unwrap_or("");
        // Go's lexer reads `(` and `)` as tokens of their own: `require(` opens a block.
        let tokens: Vec<String> = line
            .replace('(', " ( ")
            .replace(')', " ) ")
            .split_whitespace()
            .map(|f| f.trim_matches('"').to_string())
            .collect();
        let mut bad = || {
            unreadable.push(format!("Coverage: go.mod line {} is not go.mod syntax Vorda can read ({}), so modules may be missing; coverage is unknown", number + 1, lock_validation::display(raw.trim())));
        };
        let (verb, fields) = match (&block, tokens.as_slice()) {
            (_, []) => continue,
            (Some(_), [close]) if close == ")" => {
                block = None;
                continue;
            }
            (Some(verb), fields) => (verb.clone(), fields),
            (None, [verb, open]) if open == "(" => {
                block = Some(verb.clone());
                continue;
            }
            (None, [verb, fields @ ..]) => (verb.clone(), fields),
        };
        if fields.iter().any(|f| f == "(" || f == ")") {
            bad();
            continue;
        }
        match (verb.as_str(), fields) {
            ("module" | "tool" | "toolchain", [_]) => {}
            ("go", [v]) => go = Some(v.clone()),
            ("require", [n, v]) => require.push((n.clone(), v.clone())),
            ("exclude", [_, _]) => {}
            ("retract" | "godebug" | "ignore", [_, ..]) => {}
            ("replace", fields) => {
                let arrow = fields.iter().position(|f| f == "=>");
                match arrow.map(|a| fields.split_at(a)) {
                    Some((from @ [_] | from @ [_, _], [_, to @ ..]))
                        if (1..=2).contains(&to.len()) =>
                    {
                        replace.push((
                            from[0].clone(),
                            from.get(1).cloned(),
                            to[0].clone(),
                            to.get(1).cloned(),
                        ));
                    }
                    _ => bad(),
                }
            }
            _ => bad(),
        }
    }
    if block.is_some() {
        unreadable.push("Coverage: go.mod ends inside an unclosed block, so modules may be missing; coverage is unknown".into());
    }
    over_cap |= over(&require, &replace, &unreadable);
    if over_cap {
        require.clear();
    }
    // The first replace of each (module, version) wins, as the first match did.
    let mut index = std::collections::HashMap::new();
    for (from, at, target, to) in &replace {
        index
            .entry((from.as_str(), at.as_deref()))
            .or_insert((target, to));
    }
    let selected = require
        .into_iter()
        .map(|(name, version)| {
            // A version-specific replace wins over a path-only one, as in cmd/go.
            let hit = index
                .get(&(name.as_str(), Some(version.as_str())))
                .or_else(|| index.get(&(name.as_str(), None)))
                .copied();
            match hit {
                Some((target, Some(to))) => (target.clone(), to.clone(), None),
                Some((target, None)) => (name, version, Some(target.clone())),
                None => (name, version, None),
            }
        })
        .collect();
    let minor = |v: &str| {
        let mut parts = v.split('.');
        let major = parts.next().and_then(|p| p.parse::<u32>().ok());
        let minor = parts.next().and_then(|p| {
            p.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|p| p.parse::<u32>().ok())
        });
        major.zip(minor)
    };
    let complete_graph = go
        .as_deref()
        .and_then(minor)
        .is_some_and(|(major, minor)| major > 1 || minor >= 17);
    GoMod {
        selected,
        complete_graph,
        unreadable,
        over_cap,
    }
}

/// Most packages one lockfile may list. Over it the file is unknown, never truncated. Each
/// package costs about 15 KB through a scan, so a hostile file cannot exhaust memory.
pub const MAX_INPUT_PACKAGES: usize = 20_000;
/// Most lockfile packages one inventory checks; a lockfile that would pass it is unknown and
/// none of its packages are checked. Installed, OS, tool and browser sources come from this
/// machine and are bounded by their own enumeration limits.
pub const MAX_SCAN_PACKAGES: usize = 50_000;

fn over_input_cap() -> crate::Error {
    error(format!("File-level: holds more than {MAX_INPUT_PACKAGES} package entries, readable or not, over the per-input cap of {MAX_INPUT_PACKAGES}; none of its packages were checked; coverage is unknown"))
}

/// Uncheckable entries met while parsing one lockfile. Past the per-input cap only the count
/// grows, so a file of unreadable lines costs no more memory than one at the cap.
#[derive(Default)]
struct Unreadable {
    kept: std::cell::RefCell<Vec<String>>,
    seen: std::cell::Cell<usize>,
}
impl Unreadable {
    fn push(&self, issue: String) {
        self.seen.set(self.seen.get() + 1);
        if self.seen.get() <= MAX_INPUT_PACKAGES {
            self.kept.borrow_mut().push(issue);
        }
    }
}

/// `read` counts the packages and error lines this scan already holds; `unread` the
/// uncheckable entries of this input, which are carried as error lines.
fn within_scan_cap(read: usize, items: Vec<Package>, unread: usize) -> Result<Vec<Package>> {
    if read + items.len() + unread > MAX_SCAN_PACKAGES {
        return Err(error(format!("its {} packages were not checked: they would take this scan over the per-scan cap of {MAX_SCAN_PACKAGES} packages; coverage is unknown", items.len())));
    }
    Ok(items)
}

pub fn lockfile(path: &Path, root: Option<&Path>) -> Result<Vec<Package>> {
    let (packages, issues) = lockfile_report(path, root)?;
    if !issues.is_empty() {
        return Err(error(issues.join("; ")));
    }
    Ok(packages)
}

pub(super) fn lockfile_report(
    path: &Path,
    root: Option<&Path>,
) -> Result<(Vec<Package>, Vec<String>)> {
    let path = input::absolute(path)?;
    let root = root.map(input::absolute).transpose()?;
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name == "bun.lockb" {
        return Err(error("File-level: unsupported binary lockfile; export bun.lock with `bun install --save-text-lockfile` and scan again"));
    }
    let parent = path.parent().unwrap_or(Path::new("/"));
    if !supported(name) && !requirements_input(&path, root.as_deref().unwrap_or(parent)) {
        let root = root.as_deref().unwrap_or(parent);
        LISTINGS.with(|cache| cache.borrow_mut().clear());
        return Err(error(unsupported(&path, root)?.unwrap_or_else(|| {
            format!("Vorda does not read {name} directly; scan its supported lockfile or containing folder")
        })));
    }
    // Requirements inputs found by folder or by `.in` are read as requirements.txt.
    let name = if supported(name) {
        name
    } else {
        "requirements.txt"
    };
    let text = String::from_utf8(input::read_regular(
        &path,
        root.as_deref(),
        input::MAX_FILE,
        false,
    )?)
    .map_err(error)
    .map_err(lock_validation::file)?;
    let dev = root.as_deref().is_some_and(|root| test_data(&path, root));
    let sum = path.with_file_name("go.sum");
    // Before Go 1.17 go.mod can omit indirect modules; go.sum then lists the build.
    let (mut packages, mut issues) = if name == "go.mod"
        && !go_mod(&text).complete_graph
        && sum.symlink_metadata().is_ok_and(|m| m.is_file())
    {
        let sum_text = String::from_utf8(input::read_regular(
            &sum,
            root.as_deref(),
            input::MAX_FILE,
            false,
        )?)
        .map_err(error)
        .map_err(lock_validation::file)?;
        let (packages, mut issues) =
            parse_lockfile_report("go.sum", &sum_text, &sum.to_string_lossy())?;
        if packages.is_empty() && issues.is_empty() && !go_mod(&text).selected.is_empty() {
            return Err(error(
                "go.mod requires modules but go.sum lists none; coverage is unknown",
            ));
        }
        let (_, module_issues) = parse_lockfile_report(name, &text, &path.to_string_lossy())?;
        issues.extend(module_issues.into_iter().filter(|i| i != GO_BEFORE_117));
        (packages, issues)
    } else {
        parse_lockfile_report(name, &text, &path.to_string_lossy())?
    };
    // A go.work at or above a module can change its versions (`use`, `replace`). Vorda never
    // opens it: any entry named go.work (file, folder, broken link) makes coverage unknown.
    if let (true, Some(module)) = (name == "go.mod", path.parent()) {
        let work = module.ancestors().map(|dir| dir.join("go.work")).find(|work| {
            !matches!(work.symlink_metadata(), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        });
        if let Some(work) = work {
            issues.push(format!("Coverage: this module is inside a Go workspace ({}); workspace membership is not checked, so coverage is unknown", work.display()));
        }
    }
    if packages.len() + issues.len() > MAX_INPUT_PACKAGES {
        return Err(over_input_cap());
    }
    if dev {
        for p in &mut packages {
            p.scope = "likely-dev-only".into();
        }
    }
    Ok((packages, issues))
}

pub fn parse_lockfile(name: &str, text: &str, path: &str) -> Result<Vec<Package>> {
    let (packages, issues) = parse_lockfile_report(name, text, path)?;
    if !issues.is_empty() {
        return Err(error(issues.join("; ")));
    }
    Ok(packages)
}

fn parse_lockfile_report(
    name: &str,
    text: &str,
    path: &str,
) -> Result<(Vec<Package>, Vec<String>)> {
    parse_lockfile_entries(name, text, path).map_err(lock_validation::file)
}

fn parse_lockfile_entries(
    name: &str,
    text: &str,
    path: &str,
) -> Result<(Vec<Package>, Vec<String>)> {
    lock_validation::format(name, text)?;
    let mut out = Vec::new();
    let mut issues = Vec::new();
    let unresolved_paths = Unreadable::default();
    // Workspace members are skipped, not listed, but still count toward the per-input cap.
    let members = std::cell::Cell::new(0);
    let empty;
    let mut add = |n: &str, v: &str, e: &str, dev: bool| -> Result<()> {
        if out.len() + issues.len() + unresolved_paths.seen.get() + members.get()
            >= MAX_INPUT_PACKAGES
        {
            return Err(over_input_cap());
        }
        if let Some(issue) = lock_validation::entry_issue(n, v, e) {
            issues.push(issue);
            return Ok(());
        }
        out.push(package(n, v, e, path, dev, "project"));
        Ok(())
    };
    match name {
        "packages.lock.json" => {
            let (mut packages, issues) = installed::nuget_lock_report(text, path)?;
            for p in &mut packages {
                p.extra.insert("origin".into(), json!("project"));
            }
            return Ok((packages, issues));
        }
        "package-lock.json" => {
            let data: Value = serde_json::from_str(text)?;
            if !data.is_object() {
                return Err(error("invalid package-lock schema"));
            }
            if let Some(packages) = data.get("packages") {
                empty = packages.as_object().is_some_and(|m| {
                    m.keys().all(String::is_empty)
                        && m.get("").is_none_or(|p| {
                            ["dependencies", "devDependencies", "optionalDependencies"]
                                .iter()
                                .all(|key| {
                                    p.get(key)
                                        .is_none_or(|d| d.as_object().is_some_and(|d| d.is_empty()))
                                })
                        })
                });
                let packages = packages
                    .as_object()
                    .ok_or_else(|| error("invalid packages map"))?;
                let workspaces =
                    lock_validation::Workspaces::new(packages.get("")).map_err(error)?;
                for (key, p) in packages {
                    if !key.is_empty() {
                        // A link to a member listed in this map is reported with that member.
                        if p.get("link") == Some(&Value::Bool(true))
                            && packages.contains_key(super::string(p, "resolved"))
                        {
                            continue;
                        }
                        if p.get("name").is_some_and(|name| !name.is_string()) {
                            unresolved_paths
                                .push(lock_validation::uncheckable(key, &p["name"].to_string()));
                            continue;
                        }
                        // Workspace members inside the project are first-party code, skipped
                        // like the root; other local folders (vendored copies) stay uncheckable.
                        if !key.contains("node_modules/")
                            && lock_validation::inside_project(key)
                            && workspaces.member(key)
                        {
                            members.set(members.get() + 1);
                            continue;
                        }
                        if (p.get("link") == Some(&Value::Bool(true)) && p.get("version").is_none())
                            || !key.contains("node_modules/")
                        {
                            unresolved_paths.push(lock_validation::uncheckable(
                                p.get("name").and_then(Value::as_str).unwrap_or(key),
                                &format!(
                                    "file:{}",
                                    Some(super::string(p, "resolved"))
                                        .filter(|r| !r.is_empty())
                                        .unwrap_or(key)
                                ),
                            ));
                            continue;
                        }
                        add(
                            p.get("name").and_then(Value::as_str).unwrap_or_else(|| {
                                key.rsplit("node_modules/").next().unwrap_or(key)
                            }),
                            p.get("version").and_then(Value::as_str).unwrap_or(""),
                            "npm",
                            p.get("dev") == Some(&Value::Bool(true)),
                        )?;
                    }
                }
            } else {
                empty = data
                    .get("dependencies")
                    .and_then(Value::as_object)
                    .is_some_and(|m| m.is_empty());
                fn deps(
                    data: &Value,
                    out: &mut dyn FnMut(&str, &str, &str, bool) -> Result<()>,
                    depth: usize,
                ) -> Result<()> {
                    if depth > 128 {
                        return Err(error("dependency nesting limit exceeded"));
                    }
                    if !data.is_null() {
                        let items = data
                            .as_object()
                            .ok_or_else(|| error("invalid dependency collection"))?;
                        for (name, p) in items {
                            out(
                                name,
                                super::string(p, "version"),
                                "npm",
                                p.get("dev") == Some(&json!(true)),
                            )?;
                            deps(&p["dependencies"], out, depth + 1)?;
                        }
                    }
                    Ok(())
                }
                deps(&data["dependencies"], &mut add, 0)?;
            }
        }
        "Pipfile.lock" => {
            let data: Value = serde_json::from_str(text)?;
            empty = ["default", "develop"].iter().all(|g| {
                data.get(g)
                    .is_none_or(|m| m.as_object().is_some_and(|m| m.is_empty()))
            }) && data.get("default").is_some();
            for group in ["default", "develop"] {
                if let Some(value) = data.get(group) {
                    let items = value.as_object().ok_or_else(|| {
                        error(format!(
                            "invalid package group {}",
                            lock_validation::display(group)
                        ))
                    })?;
                    for (n, p) in items {
                        let v = super::string(p, "version");
                        if v.is_empty() {
                            if let Some(source) = ["git", "path", "file"].iter().find_map(|key| {
                                p.get(key)
                                    .and_then(Value::as_str)
                                    .map(|value| format!("{key}:{value}"))
                            }) {
                                add(n, &source, "PyPI", group == "develop")?;
                                continue;
                            }
                        }
                        let Some(version) = v.strip_prefix("===").or_else(|| v.strip_prefix("=="))
                        else {
                            unresolved_paths.push(lock_validation::uncheckable(n, v));
                            continue;
                        };
                        add(n, version, "PyPI", group == "develop")?;
                    }
                }
            }
        }
        "composer.lock" => {
            let data: Value = serde_json::from_str(text)?;
            empty = data
                .get("packages")
                .and_then(Value::as_array)
                .is_some_and(|a| a.is_empty())
                && data
                    .get("packages-dev")
                    .is_none_or(|a| a.as_array().is_some_and(|a| a.is_empty()));
            for group in ["packages", "packages-dev"] {
                let Some(items) = data.get(group) else {
                    continue;
                };
                let items = items.as_array().ok_or_else(|| {
                    error(format!(
                        "invalid package collection {}",
                        lock_validation::display(group)
                    ))
                })?;
                for p in items {
                    add(
                        super::string(p, "name"),
                        super::string(p, "version").trim_start_matches('v'),
                        "Packagist",
                        group == "packages-dev",
                    )?;
                }
            }
        }
        "Cargo.lock" | "poetry.lock" | "uv.lock" => {
            let data = lock_validation::toml_lock(name, text)?;
            let packages = match data.get("package") {
                None => &[][..],
                Some(toml::Value::Array(packages)) => packages.as_slice(),
                Some(_) => return Err(error("invalid package collection")),
            };
            // Declared empty: Cargo's bare version header, or uv/Poetry's `package = []`.
            empty = packages.is_empty()
                && if name == "Cargo.lock" {
                    data.keys().all(|k| k == "version")
                } else {
                    data.contains_key("package")
                };
            let members: Vec<_> = data
                .get("manifest")
                .and_then(|m| m.get("members"))
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .collect();
            for block in packages {
                let field = |key: &str| block.get(key).and_then(toml::Value::as_str);
                let package = field("name").unwrap_or("");
                let local = block
                    .get("source")
                    .and_then(|s| s.get("editable").or_else(|| s.get("virtual")))
                    .and_then(toml::Value::as_str)
                    .filter(|_| name == "uv.lock");
                if let Some(local) = local {
                    // An editable source outside the project cannot be checked.
                    if !lock_validation::inside_project(local) {
                        unresolved_paths.push(lock_validation::uncheckable(
                            package,
                            &format!("file:{local}"),
                        ));
                        continue;
                    }
                    // The root and workspace members are first-party code, skipped; other
                    // local packages (vendored copies) are queried by name and version.
                    if local == "." || members.contains(&package) {
                        continue;
                    }
                }
                add(
                    package,
                    field("version").unwrap_or(""),
                    if name == "Cargo.lock" {
                        "crates.io"
                    } else {
                        "PyPI"
                    },
                    false,
                )?;
            }
        }
        name if pylock(name) => {
            let data = lock_validation::toml_lock(name, text)?;
            let packages = match data.get("packages") {
                Some(toml::Value::Array(packages)) => packages.as_slice(),
                _ => return Err(error("invalid package collection")),
            };
            empty = packages.is_empty();
            for block in packages {
                let field = |key: &str| block.get(key).and_then(toml::Value::as_str);
                let package = field("name").unwrap_or("");
                let directory = block
                    .get("directory")
                    .and_then(|d| d.get("path"))
                    .and_then(toml::Value::as_str);
                if let Some(local) = directory {
                    // A folder inside the project with no version is first-party code, skipped;
                    // a versioned copy is queried by name and version.
                    if !lock_validation::inside_project(local) {
                        unresolved_paths.push(lock_validation::uncheckable(
                            package,
                            &format!("file:{local}"),
                        ));
                        continue;
                    }
                    if field("version").is_none() {
                        members.set(members.get() + 1);
                        continue;
                    }
                } else if let Some(source) = ["vcs", "archive", "directory"]
                    .into_iter()
                    .find(|key| block.get(key).is_some())
                {
                    // A VCS checkout or an archive is not a registry release.
                    unresolved_paths.push(lock_validation::uncheckable(package, source));
                    continue;
                }
                add(package, field("version").unwrap_or(""), "PyPI", false)?;
            }
        }
        "go.sum" => {
            empty = text.trim().is_empty();
            for (number, line) in text.lines().enumerate() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if fields.is_empty() {
                    continue;
                }
                if fields.len() != 3 {
                    unresolved_paths.push(lock_validation::uncheckable(
                        &format!("line {}", number + 1),
                        line,
                    ));
                    continue;
                }
                if !fields[1].ends_with("/go.mod") {
                    add(fields[0], fields[1], "Go", false)?;
                }
            }
        }
        "go.mod" => {
            let module = go_mod(text);
            if module.over_cap {
                return Err(over_input_cap());
            }
            empty = module.selected.is_empty();
            for (n, v, local) in &module.selected {
                match local {
                    Some(target) => unresolved_paths.push(lock_validation::uncheckable(
                        n,
                        &format!("replace => {target}"),
                    )),
                    None => add(n, v, "Go", false)?,
                }
            }
            for issue in module.unreadable {
                unresolved_paths.push(issue);
            }
            if !module.complete_graph {
                unresolved_paths.push(GO_BEFORE_117.into());
            }
        }
        "Gemfile.lock" => {
            empty = lock_validation::empty_text(name, text);
            let spec = rx(r"^    ([^\s].*|) \(([^)]*)\)$");
            let mut specs = false;
            let mut seen = std::collections::HashSet::new();
            for line in text.lines() {
                if !line.starts_with(' ') && !line.is_empty() {
                    specs = false;
                }
                if line == "  specs:" {
                    specs = true;
                    continue;
                }
                if specs && !line.starts_with("      ") && !line.trim().is_empty() {
                    if let Some(c) = spec.captures(line) {
                        // RubyGems versions never hold `-`; Bundler appends `-<platform>` to
                        // each platform build, and every build shares one version.
                        let version = c[2].split('-').next().unwrap_or_default();
                        if seen.insert((c[1].to_owned(), version.to_owned())) {
                            add(&c[1], version, "RubyGems", false)?;
                        }
                    } else {
                        add(line.trim(), "", "RubyGems", false)?;
                    }
                }
            }
        }
        "yarn.lock" => {
            empty = lock_validation::empty_text(name, text);
            let header = rx(r#"^"?((?:@[^/\s]+/)?[^@\s:"]+)@"#);
            let version = rx(r#"\n[ \t]+version[ :]+("[^"]*"|[^\r\n]+)"#);
            let metadata = rx(r#"^['"]?__metadata['"]?:"#);
            let mut block = String::new();
            for line in text.lines().chain(std::iter::once("END")) {
                if !line.starts_with(char::is_whitespace) && !block.is_empty() {
                    if !block.trim().is_empty()
                        && !block.trim_start_matches('\u{feff}').starts_with('#')
                        && !metadata.is_match(&block)
                    {
                        let n = header.captures(&block);
                        let v = version.captures(&block);
                        let v = v
                            .as_ref()
                            .map(|v| v[1].trim().trim_matches('"'))
                            .unwrap_or("");
                        if let Some(n) = n {
                            let spec = block[n.get(0).map_or(0, |m| m.end())..]
                                .split([',', '"', '\n'])
                                .next()
                                .unwrap_or("")
                                .trim_end_matches(':');
                            // An alias `name@npm:real[@range]` installs `real`: named in the
                            // header (Berry's resolution names it for a tag). After `npm:`, a
                            // range is not an alias; anything else is the name.
                            let real = match spec.strip_prefix("npm:") {
                                Some(rest)
                                    if !rest.starts_with(|c: char| {
                                        c.is_ascii_digit() || "^~<>=*".contains(c)
                                    }) =>
                                {
                                    lock_validation::locator(rest)
                                        .map(|(real, _)| real.to_string())
                                        .filter(|real| !real.is_empty())
                                        .or_else(|| yarn_resolved_name(&block))
                                        .unwrap_or_else(|| rest.to_string())
                                }
                                _ => n[1].to_string(),
                            };
                            add(&real, v, "npm", false)?;
                        } else {
                            add(block.lines().next().unwrap_or(""), v, "npm", false)?;
                        }
                    }
                    block.clear();
                }
                block.push_str(line);
                block.push('\n');
            }
        }
        "pnpm-lock.yaml" => {
            // A declared-empty lock is empty in every document; a package listed in two
            // documents is read once.
            let documents = lock_validation::pnpm_lock(text)?;
            let (mut all_empty, mut seen) = (true, std::collections::BTreeSet::new());
            for data in &documents {
                let mapping = |key: &str| match data.get(key) {
                    None | Some(serde_norway::Value::Null) => Ok(None),
                    Some(serde_norway::Value::Mapping(m)) => Ok(Some(m)),
                    Some(_) => Err(error(format!("invalid {key} map"))),
                };
                let packages = mapping("packages")?;
                let importers = mapping("importers")?.filter(|m| !m.is_empty());
                // Declared empty: `packages: {}`, or importers that all declare nothing.
                let doc_empty = packages.is_none_or(|p| p.is_empty())
                    && match importers {
                        Some(importers) => importers
                            .values()
                            .all(|i| i.as_mapping().is_some_and(|m| m.is_empty())),
                        None => packages.is_some(),
                    };
                all_empty &= doc_empty;
                for (key, body) in packages.into_iter().flatten() {
                    let Some(key) = key.as_str() else {
                        add("", "", "npm", false)?;
                        continue;
                    };
                    let key = key.strip_prefix('/').unwrap_or(key);
                    if !seen.insert(key) {
                        continue;
                    }
                    let source_resolution = body
                        .get("resolution")
                        .and_then(serde_norway::Value::as_mapping)
                        .is_some_and(|r| {
                            ["tarball", "directory", "repo"]
                                .iter()
                                .any(|k| r.contains_key(*k))
                        });
                    if lock_validation::source(key)
                        || (lock_validation::locator(key).is_none() && source_resolution)
                    {
                        unresolved_paths.push(lock_validation::uncheckable(
                            key,
                            "non-registry pnpm source reference",
                        ));
                        continue;
                    }
                    let key = if let Some((base, _)) = key.split_once('(') {
                        if !key.ends_with(')') {
                            unresolved_paths.push(lock_validation::uncheckable(
                                key,
                                "malformed peer version suffix",
                            ));
                            continue;
                        }
                        base
                    } else {
                        key
                    };
                    if let Some((n, v)) = lock_validation::locator(key) {
                        add(n, v, "npm", false)?;
                    } else {
                        add(key, "", "npm", false)?;
                    }
                }
            }
            empty = all_empty;
        }
        "bun.lock" => {
            empty = lock_validation::empty_text(name, text);
            let data = crate::scanner::agentbom::discover::jsonc(text)?;
            let packages = data
                .get("packages")
                .and_then(Value::as_object)
                .ok_or_else(|| error("invalid packages map"))?;
            let workspaces = data.get("workspaces").and_then(Value::as_object);
            for (key, tuple) in packages {
                let locator = tuple
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if let Some((n, v)) = lock_validation::locator(locator) {
                    // Workspace members are first-party code, skipped like the root.
                    if v.strip_prefix("workspace:").is_some_and(|path| {
                        workspaces.is_some_and(|w| w.contains_key(path))
                            && lock_validation::inside_project(path)
                    }) {
                        continue;
                    }
                    add(n, v, "npm", false)?;
                } else {
                    unresolved_paths.push(lock_validation::uncheckable(key, locator));
                }
            }
        }
        name if name.starts_with("requirements") => {
            // The hint names the real file: a requirements folder's `base.txt`, or `requirements.in`.
            let name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(name);
            // Windows editors start a file with a byte-order mark.
            let text = text.strip_prefix('\u{feff}').unwrap_or(text);
            empty = text
                .lines()
                .all(|l| l.trim().is_empty() || l.trim().starts_with('#'));
            // `===` (arbitrary equality) is an exact pin too.
            let exact = rx(r"^[\w.-]+(?:\[[^\]]+\])?===?[^\s;*\\=]+(?:\s|;|$)");
            let pin = rx(r"^([\w.-]+)(?:\[[^\]]+\])?===?([^\s;\\=]+)");
            let unpinned = rx(r"^([A-Za-z0-9][\w.-]*)");
            for (number, line) in text.lines().enumerate() {
                let line = line.trim();
                if ["-r", "--requirement"].iter().any(|p| line.starts_with(p)) {
                    return Err(error(format!(
                        "File-level: unsupported dependency directive at line {}; scan exact pins directly",
                        number + 1
                    )));
                }
                // An editable install is one local or VCS source entry.
                if ["-e", "--editable"].iter().any(|p| line.starts_with(p)) {
                    unresolved_paths.push(lock_validation::uncheckable(
                        &format!("line {}", number + 1),
                        line,
                    ));
                    continue;
                }
                if line.is_empty() || line.starts_with(['#', '-', '\\']) {
                    continue;
                }
                if !exact.is_match(line) {
                    // A bare name or a range (`fastapi>=0.115  # api`), not a URL or path.
                    let spec = line.split(" #").next().unwrap_or(line).trim_end();
                    let issue = match unpinned.captures(spec) {
                        Some(c) if !spec.contains(['@', '/', '\\']) && !spec.contains("==") => {
                            lock_validation::unpinned(&c[1], number + 1, name)
                        }
                        _ => lock_validation::uncheckable(&format!("line {}", number + 1), line),
                    };
                    unresolved_paths.push(issue);
                    continue;
                }
                if let Some(c) = pin.captures(line) {
                    add(&c[1], &c[2], "PyPI", false)?;
                }
            }
        }
        _ => {
            return Err(error(
                "Vorda does not read this dependency format; it is not supported",
            ))
        }
    }
    if out.len() + issues.len() + unresolved_paths.seen.get() + members.get() > MAX_INPUT_PACKAGES {
        return Err(over_input_cap());
    }
    issues.extend(unresolved_paths.kept.into_inner());
    if out.is_empty() && issues.is_empty() && !empty {
        return Err(error(format!(
            "no readable package entries; file content {}",
            lock_validation::display(text)
        )));
    }
    Ok((out, issues))
}

/// True for a Microsoft Store app alias under `%LOCALAPPDATA%\Microsoft\WindowsApps`. Stock Windows
/// ships `python3.exe` there as a stub that only prints "Python was not found" and exits 9009.
pub fn store_alias(binary: &Path, local_app_data: Option<&std::ffi::OsStr>) -> bool {
    let Some(local) = local_app_data.filter(|l| !l.is_empty()) else {
        return false;
    };
    let folder = Path::new(local).join("Microsoft").join("WindowsApps");
    binary.parent().is_some_and(|p| {
        p.to_string_lossy()
            .eq_ignore_ascii_case(&folder.to_string_lossy())
    })
}

pub fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .flat_map(|p| {
                #[cfg(windows)]
                {
                    vec![
                        p.join(name),
                        p.join(format!("{name}.exe")),
                        p.join(format!("{name}.cmd")),
                    ]
                }
                #[cfg(not(windows))]
                {
                    vec![p.join(name)]
                }
            })
            .find(|p| p.is_file())
    })
}
pub fn run(argv: &[&str], timeout: u64) -> Result<String> {
    let mut command = Command::new(argv[0]);
    command
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(error)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| error("command stdout is missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| error("command stderr is missing"))?;
    let (out_send, out_recv) = std::sync::mpsc::channel();
    let (err_send, err_recv) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(64_000_001)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = out_send.send(result);
    });
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stderr.take(1000).read_to_end(&mut bytes).map(|_| bytes);
        let _ = err_send.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let timed_out = |child: &mut std::process::Child| {
        #[cfg(unix)]
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
        error(format!("{}: timed out", argv[0]))
    };
    let status = loop {
        if let Some(status) = child.try_wait().map_err(error)? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(timed_out(&mut child));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let bytes = out_recv
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| timed_out(&mut child))?
        .map_err(error)?;
    let err = err_recv
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| timed_out(&mut child))?
        .map_err(error)?;
    if !status.success() {
        return Err(error(format!(
            "{}: {}",
            argv[0],
            String::from_utf8_lossy(&err)
        )));
    }
    if bytes.len() > 64_000_000 {
        return Err(error("command output exceeds limit"));
    }
    Ok(String::from_utf8_lossy(&bytes).trim().into())
}

/// The target of a linked folder when the walk reads that folder anyway: inside the root and
/// not under a skipped or generated folder, so skipping the link drops nothing.
fn walked_elsewhere(link: &Path, root: &Path) -> Option<PathBuf> {
    let real = fs::canonicalize(link).ok()?;
    let mut dir = root.to_path_buf();
    for part in real.strip_prefix(root).ok()?.components() {
        dir.push(part);
        if SKIP.iter().any(|s| part.as_os_str() == *s) || generated(&dir).is_some() {
            return None;
        }
    }
    real.is_dir().then_some(real)
}

pub fn collect(options: &InventoryOptions) -> Result<Record> {
    if let Some(path) = &options.oci {
        let path = input::absolute(path)?;
        let result = super::container::inventory(&path, super::container::Limits::default());
        return Ok(super::record(serde_json::to_value(result)?));
    }
    // Lockfile listings are read once per scan, never carried into the next one.
    LISTINGS.with(|cache| cache.borrow_mut().clear());
    // Errors Vorda names as not covered (an unsupported format, an unlocked manifest, an
    // unpinned entry) rather than a read or lookup that failed. Each is also in `errors`.
    let mut gaps = Vec::<String>::new();
    let (mut packages, mut errors, mut warnings, mut completed, mut evidence) = (
        Vec::<Package>::new(),
        Vec::<String>::new(),
        Vec::<String>::new(),
        Vec::<String>::new(),
        Vec::<Value>::new(),
    );
    for root in &options.roots {
        let root = match input::absolute(root) {
            Ok(root) => root,
            Err(e) => {
                (if root.is_dir() {
                    &mut warnings
                } else {
                    &mut errors
                })
                .push(format!("{}: skipped symlink root: {e}", root.display()));
                continue;
            }
        };
        let explicit = !root.is_dir();
        if let Err(e) = input::refuse_links(&root) {
            (if explicit { &mut errors } else { &mut warnings })
                .push(format!("{}: skipped symlink root: {e}", root.display()));
            continue;
        }
        if !root.exists() {
            errors.push(format!("{}: missing root", root.display()));
            continue;
        }
        let mut files = if explicit {
            vec![root.clone()]
        } else {
            Vec::new()
        };
        let mut stack = if explicit {
            vec![]
        } else {
            vec![(root.clone(), 0)]
        };
        let mut work = 0;
        let mut unread = Vec::new();
        while let Some((dir, depth)) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) => {
                    errors.push(format!("{}: {e}", dir.display()));
                    continue;
                }
            };
            work += 1;
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        errors.push(e.to_string());
                        continue;
                    }
                };
                work += 1;
                if work
                    > if options.machine {
                        MACHINE_WORK
                    } else {
                        100_000
                    }
                {
                    errors.push(format!("{}: traversal work limit exceeded", root.display()));
                    stack.clear();
                    break;
                }
                let path = entry.path();
                // Recorded as the user spelled it: path equality ignores what a string compare
                // would not (a Windows drive letter's case), and the scan scope uses the spelling.
                if let Some(excluded) = options.exclude.iter().find(|e| **e == path) {
                    evidence.push(json!({"kind":"excluded","path":excluded}));
                    continue;
                }
                if options.machine && depth <= 1 && HOME_SKIP.iter().any(|s| path == root.join(s)) {
                    evidence.push(
                        json!({"kind":"skipped-folder","path":path,"reason":COPY_HOME_SKIPPED}),
                    );
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let metadata = match fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(e) => {
                        errors.push(e.to_string());
                        continue;
                    }
                };
                if metadata.is_dir() || input::linked(&path) && !supported(&name) && path.is_dir() {
                    // A linked folder is never taken as generated: it stays unknown below.
                    let generated = (!input::linked(&path)).then(|| generated(&path)).flatten();
                    if SKIP.contains(&name.as_str()) {
                        if input::linked(&path) {
                            warnings.push(format!(
                                "{}: skipped ignored symlink directory",
                                path.display()
                            ));
                        }
                        continue;
                    }
                    if let Some(kind) = generated {
                        let reason = match lockfile_within(&path) {
                            Some(problem) => {
                                format!("skipped {kind}; it {problem}; coverage is unknown")
                            }
                            None => {
                                evidence.push(json!({"kind":"skipped-folder","path":path,"reason":format!("skipped {kind}; it holds no supported lockfile")}));
                                continue;
                            }
                        };
                        errors.push(format!("{}: {reason}", path.display()));
                        evidence
                            .push(json!({"kind":"incomplete-input","path":path,"reason":reason}));
                        continue;
                    }
                    if input::linked(&path) {
                        if let Some(real) = walked_elsewhere(&path, &root) {
                            warnings.push(format!(
                                "{}: skipped symlink directory; its target {} {READ_THERE}",
                                path.display(),
                                real.display()
                            ));
                            continue;
                        }
                        // The home folder links out to disks and synced folders a machine
                        // scan does not own; `vorda scan PATH` reads one strictly.
                        if options.machine {
                            warnings.push(format!("{}: {COPY_HOME_LINK}", path.display()));
                            evidence.push(json!({"kind":"skipped-folder","path":path,"reason":COPY_HOME_LINK}));
                            continue;
                        }
                        let reason = "skipped symlink directory; its package coverage is unknown";
                        errors.push(format!("{}: {reason}", path.display()));
                        evidence
                            .push(json!({"kind":"incomplete-input","path":path,"reason":reason}));
                    } else if depth >= 32 {
                        errors.push(format!("{}: directory depth limit exceeded", dir.display()));
                    } else {
                        stack.push((path, depth + 1));
                    }
                } else if supported(&name) || requirements_input(&path, &root) {
                    files.push(path);
                } else {
                    unread.push(path);
                }
            }
        }
        for path in unread {
            if path
                .file_name()
                .is_some_and(|name| name == "Directory.Packages.props")
                && files.iter().any(|lock| {
                    lock.file_name()
                        .is_some_and(|name| name == "packages.lock.json")
                        && lock.starts_with(path.parent().unwrap_or(&root))
                })
            {
                continue;
            }
            let (reason, gap) = match unsupported(&path, &root) {
                Ok(Some(reason)) => (reason, true),
                Ok(None) => continue,
                Err(e) => (e.to_string(), false),
            };
            if test_data(&path, &root) {
                skip_test_data(&path, &reason, &mut warnings, &mut evidence);
                continue;
            }
            if gap {
                gaps.push(format!("{}: {reason}", path.display()));
            }
            errors.push(format!("{}: {reason}", path.display()));
            evidence.push(json!({"kind":"incomplete-input","path":path,"reason":reason}));
        }
        files.sort();
        // go.mod selects the module versions; its go.sum also holds versions the build drops.
        let modules: std::collections::HashSet<_> = files
            .iter()
            .filter(|f| f.file_name().is_some_and(|n| n == "go.mod"))
            .map(|f| f.with_file_name("go.sum"))
            .collect();
        files.retain(|f| !modules.contains(f));
        let base = if explicit {
            root.parent().unwrap_or(Path::new("/"))
        } else {
            &root
        };
        for path in files {
            match lockfile_report(&path, Some(base))
                .and_then(|(items, issues)| {
                    let read = packages.len() + errors.len();
                    Ok((within_scan_cap(read, items, issues.len())?, issues))
                })
                .and_then(|(items, issues)| {
                    let doubt = (items.is_empty() && issues.is_empty())
                        .then(|| empty_lock_doubt(&path, base))
                        .flatten();
                    doubt.map_or(Ok((items, issues)), |reason| Err(error(reason)))
                }) {
                Ok((items, issues)) => {
                    packages.extend(items);
                    if issues.is_empty() {
                        completed.push(path.to_string_lossy().into_owned());
                        evidence.push(json!({"kind":"supported-input","path":path}));
                    } else {
                        let reason = format!(
                            "{} uncheckable package entries were not queried",
                            issues.len()
                        );
                        if test_data(&path, &root) {
                            skip_test_data(&path, &reason, &mut warnings, &mut evidence);
                            continue;
                        }
                        for issue in issues {
                            let error = format!("{}: {issue}", path.display());
                            // A `Coverage:` issue means entries may be missing, not one named skip.
                            if !issue.starts_with("Coverage:") {
                                gaps.push(error.clone());
                            }
                            errors.push(error);
                        }
                        evidence
                            .push(json!({"kind":"incomplete-input","path":path,"reason":reason}));
                    }
                }
                Err(e) if test_data(&path, &root) => {
                    skip_test_data(&path, &e.to_string(), &mut warnings, &mut evidence)
                }
                Err(e) => {
                    errors.push(format!("{}: {e}", path.display()));
                    evidence.push(
                        json!({"kind":"incomplete-input","path":path,"reason":e.to_string()}),
                    );
                }
            }
        }
    }
    let mut source_outcomes = Vec::new();
    let mut installed_sources = options
        .installed_roots
        .iter()
        .map(|path| installed::selected(path))
        .collect::<Vec<_>>();
    if options.installed_apps {
        installed_sources.push(installed::windows_inventory());
        installed_sources.push(installed::current_user_msix_inventory());
    }
    for source in installed_sources {
        packages.extend(source.packages);
        for observation in source.outcomes {
            let outcome = observation["outcome"].as_str().unwrap_or("unknown");
            let path = observation["path"].as_str().unwrap_or("");
            if ["complete", "missing"].contains(&outcome) {
                completed.push(path.into());
                evidence.push(json!({"kind":if outcome=="missing" {"observed-absence"}else{"supported-input"},"path":path,"source_outcome":observation}));
            } else {
                errors.push(format!(
                    "{path}: installed source {outcome}: {}",
                    observation["errors"]
                ));
                evidence.push(
                    json!({"kind":"incomplete-source","path":path,"source_outcome":observation}),
                );
            }
            source_outcomes.push(observation);
        }
    }
    if options.os_packages {
        collect_os(&mut packages, &mut errors, &mut completed, &mut evidence);
    }
    if options.tools {
        for (binary, name, ecosystem) in [
            ("node", "node", "Bitnami"),
            ("python3", "python", "Bitnami"),
            ("bun", "bun", "Unsupported runtime"),
            ("deno", "deno", "crates.io"),
            ("claude", "@anthropic-ai/claude-code", "npm"),
            ("codex", "@openai/codex", "npm"),
            ("gemini", "@google/gemini-cli", "npm"),
            ("opencode", "opencode-ai", "npm"),
        ] {
            let path = format!("tool:{binary}");
            if which(binary).is_none() {
                // A scheduled run may not see the PATH a person's shell has. A machine scan
                // lists the tool as unseen without counting it checked, so a saved finding
                // on it stays open; a project scan that asked for tools stays unknown.
                if options.scheduled && options.machine {
                    evidence.push(json!({"kind":"unseen-scheduled","path":path}));
                } else if options.scheduled {
                    errors.push(format!(
                        "{path}: scheduled lookup unavailable; installation status unknown"
                    ));
                } else {
                    completed.push(path.clone());
                    evidence.push(json!({"kind":"observed-absence","path":path}));
                }
                continue;
            }
            match run(&[binary, "--version"], 15).and_then(|text| {
                rx(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?")
                    .find(&text)
                    .map(|v| v.as_str().to_owned())
                    .ok_or_else(|| error(format!("{binary}: no version")))
            }) {
                Ok(v) => {
                    let mut tool = package(name, &v, ecosystem, &path, false, "tool");
                    if let Some(owner) = which(binary).and_then(|b| super::distro::owner(&b)) {
                        tool.extra.insert("distro_package".into(), json!(owner));
                    }
                    packages.push(tool);
                    completed.push(path.clone());
                    evidence.push(json!({"kind":"supported-input","path":path}));
                }
                // Only the stub's own refusal: a timeout or launch failure stays an error.
                Err(e)
                    if cfg!(windows)
                        && e.to_string().contains("Python was not found")
                        && which(binary).is_some_and(|b| {
                            store_alias(&b, std::env::var_os("LOCALAPPDATA").as_deref())
                        }) =>
                {
                    completed.push(path.clone());
                    evidence.push(json!({"kind":"observed-absence","path":path}));
                }
                Err(e) => errors.push(e.to_string()),
            }
        }
    }
    if options.browsers {
        // A machine scan reads the browser caches only: walking all of home for unpacked
        // Chrome for Testing builds would hit the browser walk's limit.
        let roots = if options.machine {
            &[][..]
        } else {
            &options.roots[..]
        };
        let (builds, err) = super::browsers::collect(roots, options.cache_dir.as_deref());
        for b in builds {
            let path = super::string(&b, "path");
            packages.push(package(
                "chromium",
                b.get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                "Chromium",
                path,
                false,
                "browser",
            ));
            completed.push(path.into());
        }
        if err.is_empty() {
            evidence.push(json!({"kind":"completed-browser-inventory","path":"selected-browsers"}));
        }
        errors.extend(err);
    }
    // A requested source beyond the folder walk that found nothing (no package manager, no
    // browser) proves nothing; an empty folder alone is nothing to scan. OCI returned above.
    let other_sources = options.os_packages
        || options.tools
        || options.browsers
        || options.installed_apps
        || !options.installed_roots.is_empty();
    if other_sources && packages.is_empty() && errors.is_empty() {
        let reason = "No package versions found; nothing was checked; package coverage is unknown";
        errors.push(reason.into());
        evidence.push(json!({"kind":"incomplete-input","reason":reason}));
    }
    let unique: BTreeMap<_, _> = packages
        .into_iter()
        .map(|p| {
            (
                (
                    p.path.clone(),
                    p.ecosystem.clone(),
                    p.name.clone(),
                    p.version.clone(),
                ),
                p,
            )
        })
        .collect();
    Ok(record(
        json!({"source_outcomes":source_outcomes,"packages":unique.into_values().collect::<Vec<_>>(),"errors":errors,"coverage_gaps":gaps,"warnings":warnings,"completed_paths":completed,"status":if errors.is_empty(){"complete"}else{"unknown"},"observed":super::now(),"input_evidence":{"status":if !evidence.is_empty()&&errors.is_empty()&&evidence.iter().all(|e|e["kind"]!="not-covered-test-data"){"complete"}else{"partial"},"observations":evidence}}),
    ))
}

/// Why a dpkg row that has files on disk cannot be checked at its recorded version, from its
/// status abbreviation (wanted state, current state, error flag; see dpkg-query(1)). The
/// wanted state (install, hold, remove, purge) does not change what is on disk. Installed,
/// unpacked, half-configured and trigger-waiting packages have that version's files
/// unpacked; a half-installed or reinstall-required one may hold a mix of old and new files.
fn dpkg_unsure(status: &str) -> Option<&'static str> {
    let status = status.as_bytes();
    if status.get(2) == Some(&b'R') {
        return Some("marked reinstall-required by dpkg");
    }
    match status.get(1) {
        Some(b'i' | b'U' | b'F' | b'W' | b't') => None,
        Some(b'H') => Some("half-installed"),
        _ => Some("in a dpkg state Vorda does not recognise"),
    }
}

fn collect_os(
    packages: &mut Vec<Package>,
    errors: &mut Vec<String>,
    completed: &mut Vec<String>,
    evidence: &mut Vec<Value>,
) {
    let distro = || {
        super::distro::ecosystem(
            &fs::read_to_string("/etc/os-release").unwrap_or_default(),
            &fs::read_to_string("/etc/alpine-release").unwrap_or_default(),
        )
    };
    for(binary,args,ecosystem)in [("dpkg-query",vec!["-W","-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"],"Debian"),("rpm",vec!["-qa","--qf","%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"],"RPM"),("pacman",vec!["-Q"],"Arch Linux"),("apk",vec!["info","-v"],"Alpine"),("brew",vec!["list","--versions"],"Homebrew"),("choco",vec!["list","--limit-output"],"Chocolatey")] {
        if which(binary).is_none(){continue;}let mut argv=vec![binary];argv.extend(args);match run(&argv,20){Ok(text)=>{let eco=if ["Debian","RPM","Alpine"].contains(&ecosystem){distro()}else{ecosystem.into()};for line in text.lines(){let line=line.replace('|'," ");
            // dpkg-query fields are tab-separated and may be empty (an unpack cut short leaves
            // no version), so they are read by position.
            let fields:Vec<_>=if binary=="dpkg-query"{line.split('\t').map(str::trim).collect()}else{line.split_whitespace().collect()};
            if binary=="dpkg-query"{
                if line.trim().is_empty()||fields.len()>=5&&matches!(fields[4].as_bytes().get(1),Some(b'n'|b'c')){continue;}
                if fields.len()<5||fields[0].is_empty()||fields[1].is_empty(){errors.push(format!("dpkg-query: the row {} has no package name or version, so that package was not checked; coverage is unknown",lock_validation::display(line.trim())));continue;}
                if let Some(why)=dpkg_unsure(fields[4]){
                    // Only a reinstall repairs a half-installed or reinstall-required package.
                    let repair=if matches!(fields[4].as_bytes().get(1),Some(b'H'))||fields[4].as_bytes().get(2)==Some(&b'R'){format!("sudo apt-get install --reinstall {}",fields[0])}else{"sudo dpkg --configure -a".into()};
                    errors.push(format!("dpkg-query: {} {} is {why}, so its files may not match that version and it was not checked; repair it ({repair}) and scan again",fields[0],fields[1]));continue;}}
            let origin=if ["brew","choco"].contains(&binary){"installed"}else{"os"};if fields.len()>=2{let mut p=package(fields[0],fields[1],&eco,binary,false,origin);if binary=="dpkg-query"{p.extra.insert("source_name".into(),json!(fields[2]));p.extra.insert("source_version".into(),json!(fields[3]));}packages.push(p);}else if eco.starts_with("Alpine:"){if let Some(c)=rx(r"(.+)-(\d.+)").captures(&line){packages.push(package(&c[1],&c[2],&eco,binary,false,origin));}}}completed.push(binary.into());evidence.push(json!({"kind":"supported-input","path":binary}));},Err(e)=>errors.push(e.to_string())}
    }
    if which("winget").is_some() {
        let output = std::env::temp_dir().join(format!(
            "vorda-winget-{}-{}.json",
            std::process::id(),
            super::now()
        ));
        let filename = output.to_string_lossy();
        let result = run(
            &[
                "winget",
                "export",
                "--output",
                &filename,
                "--include-versions",
                "--disable-interactivity",
            ],
            20,
        )
        .and_then(|_| input::text(&output))
        .and_then(|text| {
            serde_json::from_str::<Value>(text.trim_start_matches('\u{feff}')).map_err(Into::into)
        });
        let _ = fs::remove_file(&output);
        match result {
            Ok(data) => {
                for source in super::array(&data["Sources"]) {
                    for item in super::array(&source["Packages"]) {
                        let name = super::string(item, "PackageIdentifier");
                        let v = super::string(item, "Version");
                        if v.is_empty() {
                            errors.push(format!("winget: unresolved version for {name}"));
                        } else {
                            packages.push(package(name, v, "Winget", "winget", false, "installed"));
                        }
                    }
                }
                completed.push("winget".into());
                evidence.push(json!({"kind":"supported-input","path":"winget"}));
            }
            Err(e) => errors.push(format!("winget: {e}")),
        }
    }
}

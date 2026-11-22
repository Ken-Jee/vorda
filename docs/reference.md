# Technical reference

[Quick start](../README.md) · [Agent setup](agents.md)

## Modes and permissions

Fleet permissions are a local owner policy, not a security boundary against anyone with shell or config-file access.

`watch` collects findings without proposing changes. `advise` prepares advice for review. `fix` lets approved changes run only when policy also allows them. Protected-package rules always win, and narrower machine or agent scopes can tighten your policy.

A minimal `vorda.yaml` can use JSON with no extra dependencies:

```json
{"mode":"advise","never":["kernel","sshd","bootloader","package-manager"]}
```

Check or change modes with `vorda mode`, and test permissions with `vorda can`. From a clean folder with no policy file, they print:

```text
$ vorda mode
advise: advise mode does not apply changes
$ vorda can assistant lockfiles
no: advise mode does not apply changes
```

To preview a permitted action, set `fix` and an `allow` rule in your owner policy. Running a repair still needs a reviewed draft and approval checks; changing the mode never applies a change on its own.

The dashboard is read-only by default. With `dashboard --allow-writes` and a host-approved fix config, approved drafts show Apply when machine and agent policy allows it. Failed checks or an incomplete rescan roll the change back. Open PR works on unlocked npm drafts and needs an authenticated `gh`, an explicit repository, a base branch, and a new branch. It pushes the reviewed commit and opens a draft PR, never merging it. You can dismiss unapproved drafts.

## Dashboard

```sh
vorda dashboard
```

Open the local URL printed in your terminal (usually http://127.0.0.1:7780/). This read-only view needs no token or config. Keep it running and press Ctrl+C to stop. If the port is busy, run `vorda dashboard --port 0` for a free port. Run a scan first so the dashboard has saved results to show.

## Data sources

Package advisories come from [OSV.dev](https://osv.dev) (including GitHub Security Advisories), or from OSV's per-ecosystem exports in [offline mode](#offline-advisory-database). Priority uses [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [FIRST EPSS](https://www.first.org/epss/). OS packages use the Debian, Ubuntu (including Ubuntu OVAL and Canonical's CVE tracker online), Arch, and Alpine security trackers, plus the [NVD](https://nvd.nist.gov/) API and [CVEList V5](https://github.com/CVEProject/cvelistV5) for upstream matches. Browsers use NVD, Chrome Releases, and Chrome for Testing metadata. Release signatures use [minisign](https://jedisct1.github.io/minisign/), checked with `minisign-verify`. Libraries and licenses: [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Run

```sh
# Install vorda first; see install.md if you have not installed it yet.
vorda check --root ./project --os-packages --tools --browsers
vorda mail list --reader codex
vorda mail read --reader codex --id 1
vorda mail ack --reader codex --id 1
vorda mail snooze --reader claude --id 2 --seconds 3600
vorda check --offline
vorda fix --dry-run
```

Put `--state DIR` before the subcommand; `VORDA_HOME` sets its default. On Unix, the state folder is set to 0700 and `mail.db` to 0600 on every open, even if wider permissions existed. Default scan root is the current folder; pass `--root` (repeatable) to name the roots to scan instead. Inventory is read-only; only cache, mailbox, and requested schedules are written. No notifications, webhooks, telemetry, accounts, or fixes are on by default. Online checks send package names and versions to the configured authoritative sources. `--offline` makes no requests and returns unknown (exit 2); `--offline-db` (the default for `scan` and `check`) answers from your local database and can be complete (see [offline advisory database](#offline-advisory-database)). Exit 3 means findings; exit 0 means no new known findings in the scan (not a guarantee of complete coverage or safety); exit 2 means an unknown or incomplete result, or an operational error; exit 64 means a usage error. Inspect `coverage_evidence.status` before assuming resolution. `inventory` prints exact package records without fetching feeds; `check --inventory-file FILE` scans that saved list.

`vorda scan` (and `check`) prints a short human summary; `--json` prints the full result with the same exit code. The summary shows the status, package count, up to eight package-version lines with findings (`name version (path and N others): K advisories`, known-exploited count, and up to three fixed versions in finding order), and the first three errors. Names, versions, paths, errors, and `inventory` `Warning:` lines replace control and invisible characters with `?`, and names or versions longer than 120 characters are cut with `…`. `check --scheduled` prints the same summary unless you pass `--json`.

## Offline advisory database

`scan --offline-db` (and `check --offline-db`) checks OSV advisories and the CISA known-exploited (KEV) list against a local copy of OSV's exports with no network requests. It exits 0, 3, or 2 like an online scan, and reports unknown whenever the local copy could be wrong.

### Fetch and update the database

```sh
vorda db update                          # npm, PyPI, crates.io and Go, then the KEV list
vorda db update --ecosystem PyPI         # one ecosystem; repeat --ecosystem for more
vorda db update --from /srv/osv-mirror   # copy from a mirror folder instead of downloading
vorda db status                          # what scan --offline-db would use now
```

- **Where:** `VORDA_ADVISORY_DB_DIR`, defaulting to `vorda/advisory-db` under `$XDG_CACHE_HOME` or `~/.cache` (`%LOCALAPPDATA%` on Windows), outside the state folder. All four ecosystems take a few hundred MB on disk (npm alone is about 130 MB).
- **Download:** `update` fetches `<Ecosystem>/all.zip` from OSV's export bucket and the KEV list from CISA. Each new index is built and renamed over the old one, so a failed or killed refresh keeps the previous index.
- **Mirror:** `--from DIR` reads `DIR/<Ecosystem>/all.zip` (the bucket's own layout) and `DIR/kev.json`. A mirrored file's age comes from its modification time, not copy time, so keep timestamps when syncing (`rsync -t`, `cp -p`); resetting them makes an old mirror look fresh.
- **Schedule:** run `vorda db update` daily before scans and log its output. It exits 2 whenever something needs attention (see below).
- **Status:** `vorda db status` prints `ready` or `unknown: <why>` per ecosystem and for KEV. It exits 0 only when every line is `ready`.
- `--json` on either command prints an indented JSON array with one object per ecosystem and one for KEV (`ecosystem`, `outcome` or `state`, `fetched_at`, `source_url`, `records`, and `error` when present), with the same exit code.

### Offline advisory database and defaults

`vorda scan` and `vorda check` use your local offline advisory database (`--offline-db`) by default, with no automatic network fallback. Pass `--online` for one online OSV.dev scan, or set `VORDA_ADVISORIES=online` or `"advisories": "online"` in `config.json` to stay online. Precedence is CLI flags, then `VORDA_ADVISORIES`, then `config.json`, then `--offline-db`. `--offline` is separate: it runs an inventory-only scan that always reports unknown (exit 2).

### First-use setup

Setup runs only when no local advisory indexes exist. In an interactive terminal, you can (1) download the offline database now (about 80 seconds; package names stay local), (2) scan online this once (sends package names and versions to OSV.dev), or press Enter to cancel. If a database is stale or missing an ecosystem index, setup does not run and affected targets report unknown.

### Offline coverage

Offline mode checks npm, PyPI, crates.io, and Go packages from any inventory source. Packages in other ecosystems or feeds needing the network report `unknown`.

### Noninteractive, CI, and GitHub Action

Vorda never prompts in noninteractive shells, CI, or the GitHub Action. Without a local database, it exits 2 (unknown) and tells you to run `vorda db update` then rerun, or `vorda scan --online` once. The GitHub Action defaults to the local offline database, and with none installed it reports `status=unknown` and fails the step (exit 2) even with `fail-on-findings=false`. Set the `advisories` input to `online` (or `VORDA_ADVISORIES=online`) to scan online.

### Run offline

Pick the advisory source in order of priority:

- flag: `--offline-db` or `--online` on `scan`/`check`;
- environment: `VORDA_ADVISORIES=offline-db` (or `online`);
- state `config.json`: `"advisories": "offline-db"`;
- default: `offline-db` for `vorda scan`, `vorda check`, MCP `check`, and the GitHub Action; `online` for `agentbom` and MCP `agent_check`.

On the CLI, `--offline` skips advisory lookups and leaves results `unknown` regardless of configuration (even when `offline-db` is configured); combining `--offline` with `--offline-db` is invalid (exit 64). The MCP `check` tool accepts optional `online`, `offline_db`, and `offline` booleans (`offline: true` runs an inventory-only scan that always returns `unknown`); setting more than one to `true` is rejected. When omitted, MCP `check` follows `VORDA_ADVISORIES` > `advisories` in `config.json` > `offline-db` by default, matching CLI `scan`/`check`, and when the local advisory database is absent or stale it saves health findings and returns `unknown` with no automatic network fallback. `vorda agentbom` and MCP `agent_check` follow `VORDA_ADVISORIES` and `config.json` `advisories`, defaulting to `online`.

Offline-db scans print `Advisories: local offline database (no network); EPSS not checked.` JSON output includes `"advisory_source": "offline-db"` and a `not_checked` list.

Not covered offline (each reports unknown, exit 2, never clean):

- ecosystems outside npm, PyPI, crates.io, and Go (RubyGems, Maven, NuGet, Packagist, OS ecosystems, and others);
- `--os-packages`, `--tools`, and `--browsers`: feeds need the network and are refused with "offline-db: not looked up, this source needs the network: URL";
- EPSS scores: always `null`, so priority uses KEV and CVSS only.

`vorda agentbom` has no `--offline-db` flag; it follows `VORDA_ADVISORIES` and `advisories`. When offline-db is configured, it queries your local database and refuses `agentbom --offline` with "--offline and the offline advisory database cannot be combined" (exit 64). Otherwise, `agentbom --offline` skips lookups and returns unknown.

One exception: `vorda repair` verification always rescans online, regardless of your advisory setting.

### Exit codes

`vorda scan` and `vorda check` exit 0 with no known findings, 3 with findings, and 2 for an unknown or incomplete result or an operational error. Usage errors exit 64 (EX_USAGE) and report JSON status `usage_error`. In the GitHub Action, usage errors always fail the run regardless of `fail-on-findings`.

`vorda db update` prints one line per ecosystem plus KEV, exiting 0 only when every line is `updated` (otherwise 2).

| Outcome | Meaning | Scans of that ecosystem |
|---|---|---|
| `updated` | new index or KEV list replaced the old one | use it |
| `updated-stale` | loaded, but already past the age limit (stale mirror) | unknown until a fresher copy loads |
| `updated-with-unreadable-records` | loaded, but some records were unreadable | unknown until a clean export loads |
| `kept-previous` | download failed or export was too small; old index stays | use old index if it exists and is fresh |
| `unreadable` | export is malformed or over a size bound | unknown until a good refresh |

`vorda db status` exits 0 when every line is `ready`, else 2. Scans exit 0 (no known findings), 3 (findings), 2 (unknown), or 64 (usage error). Offline unknowns emit `offline-db:<Ecosystem>` coverage errors ("REASON: N packages not checked (NAME VERSION, …); the result is unknown, not clean") when:

- no index exists for the ecosystem, or it cannot be matched offline;
- the index or KEV list is too old, or has a future fetch time;
- the latest refresh was unreadable, or the export had unreadable records;
- a record exceeds a per-record bound, a version or range cannot be ordered, or a range type or event is unknown, even if the entry also lists affected versions (listed or in-range versions are affected, so the list alone never clears it);
- a per-package or per-scan lookup bound or time budget ran out.

Entries with only Git ranges, or with no ranges or versions, match no version (just like OSV version queries). They are not findings and do not make scans unknown; they appear in `warnings` (and in `vorda agentbom`) with the packages they concern.

Some records use non-version range events like `last_affected: "2.6.0-NA"`, `"2.6.0-cu124"` (torch, apache-airflow, gdal, monai), `fixed: "0.7.11p3"` (buildbot), or `introduced: "9.6.0b1"` (Go's go-redis). When an event starts with three or more numbers followed by a letter, `-`, `_`, or `+`, it always sorts between earlier and later releases. The offline database places it there to decide other releases, while OSV sorts it below every version (matching no airflow version checked, even below the event, and every buildbot release from the first affected one up). Vorda clears a version only if both readings clear it, so offline can report a finding online does not. These stay unknown (exit 2):

- a version in the event's own release (torch 2.6.0 for `2.6.0-cu124`);
- a version where the two readings disagree, like go-redis v9.5.0 below `introduced: "9.6.0b1"`, or buildbot releases after `fixed: "0.7.11p3"`;
- events of different kinds within that release, whose order is unclear;
- an entry whose version list includes a version the range would clear, showing the event means something else.

Any other non-version event, such as `next`, leaves every version of that package unknown.

### Staleness

An index or KEV list older than `VORDA_ADVISORY_DB_MAX_AGE_HOURS` (default 72, tolerating two missed daily refreshes) is ignored, making scans of that ecosystem unknown ("local advisory database for ECOSYSTEM is N hours old, over the limit of 72 hours; run `vorda db update`"). Downloads age from fetch time; mirror files age from modification time. `db update` marks an already-stale copy `updated-stale` and exits 2 so scheduled jobs catch stopped mirrors early. Indexes built with an older package-name format are also rejected ("stores package names in an older form"); run `vorda db update` once after upgrading.

### Partial mirrors

OSV exports lack a completeness marker, so `db update` cannot prove an export is whole. It refuses clearly undersized exports with `kept-previous` and exit 2:

- **Below the ecosystem floor:** about half a complete export in late 2026 (complete exports only grow because OSV keeps withdrawn records).

  | Ecosystem | Fewest entries accepted |
  |---|---|
  | npm | 115,000 |
  | PyPI | 13,000 |
  | crates.io | 1,500 |
  | Go | 4,800 |

  The error reads "export has N entries, fewer than the FLOOR a complete ECOSYSTEM export holds". Set a custom floor for all ecosystems on a small private mirror with `VORDA_ADVISORY_DB_MIN_ENTRIES`.
- **Under 90% of the index's largest export:** entry count includes valid, withdrawn, and unreadable records. The index tracks the highest clean export count; exports with unreadable records must meet it without raising it, catching mirrors that lose a few percent per sync once they fall 10% below that high-water mark. The error reads "export has N entries, fewer than 90% of the M this index has held". After a real shrink, delete `<Ecosystem>.sqlite` from the database folder so the next update resets the mark.

After a refusal, the previous index stays active. These are size checks only: an export missing a few advisories still passes if it beats the floor and stays within 10% of the high-water mark.

## Inventory and matching

### Agent inventory preview: known coverage limits

`vorda agentbom` is a preview with incomplete coverage handling. Never treat a clean result as a security clearance:

- A malformed or truncated Claude plugin or Gemini extension manifest can close findings for a server that is still present. Restore the manifest, rescan, and check closed messages before treating them as resolved.
- Unreadable command folders, some model folders (including Hugging Face), and projects under unreadable parent folders can report no known findings without a coverage error. Confirm those paths are readable first; existing findings stay open, but the clean status is unreliable.
- IDE extension inventory can skip unreadable folders without a coverage error and does not yet produce vulnerability findings.

These are known defects, not supported clean scans. Other completed checks do not establish coverage of omitted paths.

### Project lockfiles

Vorda does not resolve dependencies; it checks only what a file lists. A requirements.txt of direct pins misses transitive dependencies pip would install, yet can still report coverage `complete`. Scan a full lock (uv.lock, poetry.lock, or a requirements.txt from `pip freeze`) to cover them.

Reads exact versions from these lockfile formats:

| File | Accepted format versions | Missing version marker |
| --- | --- | --- |
| package-lock.json | `lockfileVersion` 1, 2, 3 | Unknown |
| pnpm-lock.yaml | `lockfileVersion` 6.0, 9.0 | Unknown |
| yarn.lock | Classic v1; Berry `__metadata.version` 8 | Classic v1 works without its comment header; Berry metadata requires a version |
| bun.lock | Text `lockfileVersion` 0, 1, 2; optional `configVersion` 1 | Missing lockfileVersion is unknown; missing configVersion is fine |
| uv.lock | `version` 1; optional `revision` 1, 2, 3 | Missing version is unknown; missing revision is fine |
| poetry.lock | Metadata `lock-version` 1.0, 1.1, 2.0, 2.1 | Unknown |
| Pipfile.lock | `_meta.pipfile-spec` 6 | Unknown |
| Cargo.lock | Unmarked 1 and 2; marked 3 and 4 (explicit 1/2 markers still accepted, though Cargo does not write them) | Read as legacy 1/2 |
| packages.lock.json (NuGet) | `version` 1, 2 | Unknown |
| composer.lock | Unversioned packages/packages-dev structure | No marker; `plugin-api-version` is the plugin API, not lock format |
| Gemfile.lock | Unversioned specs structure | No marker; `BUNDLED WITH` is the tool, not lock format |
| go.mod | `require` versions after `replace`; `toolchain` (else `go`) sets the Go stdlib version, reported as `stdlib` | No marker. `go` before 1.17 (or missing) cannot list indirect modules, so Vorda reads adjacent go.sum or marks unknown; a go.sum that lists nothing while go.mod requires modules is unknown. Local-path `replace` is uncheckable. Bad syntax or unclosed blocks make the file unknown |
| go.sum (only without go.mod), pinned requirements*.txt (`==` or `===`) | Unversioned exact pins | No format marker |

requirements*.txt and go.mod may start with a byte-order mark.

A `stdlib` version from the `go` line alone (no `toolchain` line) is only a minimum; a newer build toolchain can cause over-reporting. Inventory JSON marks it `version_basis: "go-directive-minimum"` with a `note`, and `vorda fix` suggests `go get toolchain@go<version>` for a `stdlib` finding.

Any Go module with a `go.work` entry (file, folder, or broken link) in its folder or any ancestor up to the filesystem root (even above the scan root) is unknown: "inside a Go workspace (…); workspace membership is not checked". Vorda never opens go.work, so this holds even for unlisted modules (stricter than the go tool). A go.work file found while walking is also named as an unread format.

Unsupported marker values (including future versions and pnpm 5.x) report unknown and name the file, value found, and accepted versions. Binary bun.lockb is rejected with an export instruction. These parsers cover the included fixture shapes, not every revision or custom lockfile extension. Requirements discovery reads `requirements*.txt` by basename only and does not resolve other requirements or constraints files.

A manifest is covered by a supported lockfile beside it or in an ancestor **inside the selected root** (except Pipfile, which needs an adjacent Pipfile.lock). An ancestor lockfile covers a nested manifest only if it lists that folder: npm, bun, pnpm, or yarn workspaces; `workspaces` globs in a `"private": true` package.json beside a yarn classic lock for members whose package.json has a `name` (as yarn 1 reads them); uv, poetry, Pipfile, composer, or Gemfile path sources; a Cargo local package matching the crate's name and version; or a NuGet project reference. Otherwise the scan is unknown and names both files. A nested package.json with no dependencies needs no lock of its own when an ancestor JavaScript lock covers it. Ancestor coverage includes PHP/Ruby vendor manifests and Python members under a root uv lock:

| Manifest | Covering input | Usual command when missing |
|---|---|---|
| package.json | package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock | npm install --package-lock-only (or the chosen package manager) |
| Cargo.toml | Cargo.lock | cargo generate-lockfile |
| Gemfile / gems.rb | Gemfile.lock (gems.locked is unread) | bundle lock with a Gemfile |
| composer.json | composer.lock | composer update --no-install |
| Pipfile | adjacent Pipfile.lock | pipenv lock |
| pyproject.toml, setup.py, setup.cfg | uv.lock, poetry.lock, Pipfile.lock; or adjacent requirements*.txt | uv lock, poetry lock, or export pinned requirements.txt |
| *.csproj, *.fsproj, *.vbproj, packages.config, Directory.Packages.props | packages.lock.json | dotnet restore --use-lock-file |

Directory.Packages.props holds central versions and is also covered by a packages.lock.json below it. Ignored folders never supply covering locks.

Missing locks report unknown with a suggested command and a note to scan where the lockfile lives (suggestions only, not a resolver). An ancestor lockfile that omits the folder names both files ("does not list this folder as a workspace member or path dependency").

A valid pyproject.toml with no project dependencies, optional dependencies, dependency groups, Poetry/PDM tables, uv dev-dependencies, Hatch environment dependencies, Pixi tables, or legacy Flit requires counts as config, not an unread manifest. Empty lists or groups add no dependencies. Unreadable or malformed metadata stays unknown.

A pip-tools .in file is covered by an adjacent compiled .txt of the same stem **only when Vorda reads that .txt filename** (requirements*.txt). An unreadable or unparseable compiled file still reports unknown, and Vorda does not check if it is stale or complete. Other variants (*-requirements.txt, *_requirements.txt, and their .in forms) are recognised as unsupported. For other .txt/.in files in a requirements folder inside the root, Vorda reads lines only to classify them. Any requirement-like line (name, spaced extras, version expression with parentheses, marker, or direct reference) marks the file unread, even alongside prose or pip options. Any line starting with a dash counts as a pip directive (including -i, -f, --trusted-host, and --pre). Blank or comment lines do not hide requirements. Only files with no requirement or directive lines (like prose in docs/requirements/user-stories.txt) are ignored. Vorda does not follow recursive includes or resolve dependencies.

Unread formats trigger an unsupported-format message (case-insensitive, so `Pom.xml` counts): pom.xml, Gradle builds/settings/lockfile/libs.versions.toml, npm-shrinkwrap.json, pdm.lock, mix.lock/mix.exs, pubspec.lock/pubspec.yaml, deno.lock/deno.json/deno.jsonc, pylock.toml, Package.resolved, Podfile/Podfile.lock, renv.lock, environment.yml/environment.yaml, conanfile.txt, conanfile.py, conan.lock, build.sbt, pixi.lock, gems.rb/gems.locked, go.work, Gopkg.lock/Gopkg.toml, paket.lock/paket.dependencies, Package.swift, vcpkg.json, ivy.xml, Chart.lock, requirements*.lock, requirements.pip, and Requirements.txt. A `*.gemspec` needs a Gemfile.lock beside or above it, like a Gemfile.

constraints*.txt and constraints*.in are skipped because constraints only restrict installs requested elsewhere. Only node_modules and .git are excluded; other dot folders (.github, .devcontainer, .output) are read. Python virtualenvs (pyvenv.cfg), CACHEDIR.TAG folders (like cargo's target), `.vscode-test`, and `.next` are not read, only searched for supported lockfiles: if one holds a lockfile or is too large to search, the scan is unknown; otherwise it appears as `skipped-folder` in coverage evidence. Linked folders are never followed. A symlink pointing to a scanned folder inside the root (not excluded or skipped) emits a warning; any other non-ignored directory symlink produces unknown. Ignored directory links do not change the verdict. Other filenames are not classified.

Unparseable or skipped supported files (symlinks, hard links, unreadable files) and scans that find nothing to read return `unknown` (exit 2). Clean lockfiles declaring no dependencies are complete; see [empty lockfiles](#empty-lockfiles). Any lockfile with over 20,000 entries (readable or not), or that would push one scan past 50,000 entries, also returns `unknown` (exit 2) with the cap named in `errors`; none of its packages are checked, so results are never silently truncated.

Reading limits. Past any limit below, the file returns `unknown` with the limit named, and none of its packages are checked:

- TOML and YAML lockfiles (Cargo.lock, poetry.lock, uv.lock, pnpm-lock.yaml): over 48,000,000 bytes or nesting deeper than 64. TOML lockfiles and pyproject.toml also stop at weight 3,000,000 (counting brackets, braces, `=`, `,`, and lines) or 10,000 items in one array or inline table; brackets in strings and comments do not count toward nesting.
- pnpm-lock.yaml: over 8 lines starting with `%` (YAML directives), over 768,000,000 estimated parsed bytes (including file text, which large locks can hit well below 48,000,000 bytes), or over 30 seconds ("too slow to read safely").
- go.mod: over 20,000 `require` entries plus unreadable lines, or over 20,000 `replace` lines.
- package-lock.json `workspaces` (and package.json beside a yarn classic lock): over 128 distinct wildcard patterns, a wildcard longer than 16 folders, or over 20,000 exact folder names plus `!` excludes. Workspace members are skipped but still count toward the 20,000-entry cap. For yarn classic, exceeding these bounds lists no members, so each member folder reports as unlisted.

Check `errors` and `coverage_evidence` in scan JSON for incomplete inputs. Unpinned requirements are not resolved, and `-r`/`--requirement` or `-e`/`--editable` (including attached and equals forms) make that input incomplete. Scan exact pins directly; no recursive resolver is provided. Constraints are not installed dependencies, and referenced constraint files are not resolved. Dependency markers and full platform resolution are not implemented.

Lockfile entries must have nonempty ecosystem-shaped names (at most 1024 bytes) and exact versions (at most 256 bytes), with no whitespace or control characters. Ranges are refused as versions. Composer branch versions (`dev-main`), Python epochs and release suffixes, Go pseudo-versions, and gem platform suffixes are accepted.

A **file-level problem** rejects the whole file: an unsupported format version, a parse failure, or broken structure where entries cannot be separated (including `-r`/`-e` in requirements, which hides included entries). The scan returns `unknown` (exit 2), names the file and reason, and queries nothing from it.

An **entry-level problem** marks only that entry uncheckable: a name or version failing validation, or a detected non-registry source (git, `file:`, URL, or link) without a registry name/version. Vorda lists the file and entry without querying it, while still checking healthy packages in that file. Both the inventory and the scan stay `unknown` (exit 2), even if healthy packages have findings; incomplete coverage never reads as clean or complete. Diagnostics escape and truncate hostile text and suggest a recovery action.

In-project workspace members (and the project root) are first-party code: Vorda skips them and checks their registry dependencies. Other local packages inside the project (like vendored libraries) are not skipped: npm and bun list them as uncheckable, while uv queries their declared name and version. Local dependencies pointing **outside** the project stay uncheckable. Detected source references by format:

- npm: git, URL, `file:`, and `link:` sources, plus local entries outside `node_modules/`. Members matched by the root's `workspaces` globs are skipped; other local entries (`file:./vendor/lib`, `file:../lib`) are uncheckable. A `link: true` entry without a version is reported once with its target member; one with an exact version is queried.
- pnpm: 6.0 source keys without a `name@version` locator and 9.0 source locators are uncheckable. Workspace members live under `importers` and are not read as packages.
- bun: `workspace:` members listed in `workspaces` are skipped; other non-registry locators (git, `file:`, URL) are uncheckable.
- uv: the root (`editable`/`virtual` source `.`) and `[manifest] members` are skipped; other in-project `editable`/`virtual` sources are queried by name and version, and ones outside are uncheckable.
- Pipfile.lock: entries without an `==` version (git, path) are uncheckable.
- requirements: URL, direct references, and `-e`/`--editable` lines are uncheckable entries; `-r`/`--requirement` refuses the whole file.
- Not detected, so queried by declared name and version as public packages (a matching public package could cause a false finding, never a false clean): Yarn classic and Berry descriptors (git sources, Berry `workspace:` entries with `0.0.0-use.local`), Cargo git and path crates (Cargo.lock has no path, so workspace members look like outside paths), Poetry directory/file/git/url sources, uv `git`, `path`, and `directory` sources, Gemfile GIT and PATH gems, and Composer path repositories.

Full workspace resolution is not supported. Extra source metadata next to an exact registry locator does not alter it, and fork provenance is not verified.

### Empty lockfiles

Zero parsed packages need an explicit empty dependency structure or empty unversioned pin file; unrecognized content is unknown. A 0-byte or whitespace-only lockfile (a byte-order mark counts as whitespace), requirements*.txt included, is always unknown ("is empty, so it does not show what the project depends on"). Otherwise, a clean lockfile listing no packages is complete only when its adjacent manifest exists, parses, and declares nothing. If every read lockfile matches, the scan exits 0 and prints "No package versions found: the lockfiles read declare no dependencies." on stderr; else it is unknown ("MANIFEST declares dependencies but LOCK lists none" or "LOCK lists no packages and there is no readable MANIFEST beside it"). Both `--online` and `--offline-db` (default, once the local database is downloaded) can return complete; `--offline` stays unknown.

| Lockfile | Manifest beside it | Counts as declaring dependencies (so unknown) |
|---|---|---|
| package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock | package.json | any non-empty `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`, `bundleDependencies`, or `bundledDependencies`, or a `workspaces` entry; for pnpm also an adjacent `pnpm-workspace.yaml` |
| Cargo.lock | Cargo.toml | non-empty `[dependencies]`, `[dev-dependencies]`, or `[build-dependencies]` (either spelling), or any `[target…]` or `[workspace]` table |
| poetry.lock, uv.lock | pyproject.toml | `[project]` `dependencies` or `optional-dependencies`; `dynamic` naming anything except `version`; `[dependency-groups]`; `[tool.poetry]` `dependencies` other than `python`, `dev-dependencies`, or `group`; `[tool.uv]` `dev-dependencies` or `workspace` |
| Pipfile.lock | Pipfile | any non-empty table or value except `source`, `requires`, `scripts`, and `pipenv` |
| composer.lock | composer.json | any `require` or `require-dev` entry except `php` and `ext-*` |
| Gemfile.lock | Gemfile | any line except blank, comment, `source`, or `ruby` |
| go.sum (read only without go.mod) | none | always unknown when it lists nothing |
| go.mod (pre-1.17, beside a go.sum that lists none) | itself | any `require` |
| requirements*.txt | itself | anything except blank lines and comments |
| packages.lock.json (NuGet) | none | always unknown when it lists nothing |

A missing or unparseable manifest counts as unreadable, making the lock unknown.

### OS and tool inventory

OS inventory probes dpkg, rpm, pacman, apk, brew, Chocolatey, and winget where installed, keeping dpkg source names and versions for distro matching. dpkg packages that are installed, held, marked for removal, unpacked, half-configured, or waiting on triggers are checked at their recorded version. A half-installed or reinstall-required package, a state Vorda does not recognise, or a row with no name or version stays unknown and is not checked; the error suggests `sudo apt-get install --reinstall NAME` for the first two and `sudo dpkg --configure -a` for an unrecognised state. OCI images read dpkg status blocks by state the same way. winget uses its JSON export; unrecognized advisory mappings stay unknown. Runtime and harness version probes run concurrently with a 15-second timeout. Node and Python query OSV Bitnami upstream records, Deno queries crates.io, harness CLIs query npm, and Bun runtime coverage is unsupported (unknown coverage warning). Upstream runtime hits do not prove whether a distro backported a patch; compare with distro source-package findings. When dpkg or rpm owns a tool binary (checking the resolved target first, so `/usr/bin/python3 -> python3.12` names `python3.12-minimal`, not `python3-minimal`), findings carry `upstream_only: true`, `package.distro_package` (for example `python3.12-minimal 3.12.3-1ubuntu0.17`), `confidence` starting `upstream only`, and `[upstream only]` at the end of the title in the dashboard, mailbox, and alerts. These stay open; check the distro tracker for the owning package. Vorda does not claim reachability analysis: lockfile dev flags and `test`, `tests`, or `fixtures` folders inside the scan root are marked likely-dev-only (parent folders and `vendor` are not); all others are reachable-unknown. The dashboard shows open findings even when none are urgent. All clear requires zero open findings and a known, current scan without coverage errors. Feed errors are coverage warnings, not open findings; incomplete coverage shows Can't confirm while keeping the saved open finding count. The dashboard lists every saved project with its latest scan, findings, and scan age; scanning another project or an empty folder does not hide earlier ones. Urgent findings and coverage warnings both appear in the headline area. Agent text observations count as open findings even without an advisory identifier. An empty recorded root says Can't confirm / Nothing checked, even if the saved scan status says no known findings or another root in that scan had checked packages, and it counts in the unknown total. Projects older than two days, or whose saved root no longer exists, stay visible with Can't confirm and their scan age; no automatic expiry or deletion is offered. Older state still opens: saved input paths identify older projects where available, cards say when the original scan root was not recorded, and scans without path evidence keep a saved-scan label. New scan checkpoints include `scan_roots`. For older checkpoints, input folders are location hints rather than confirmed roots: each saved scope keeps its own card, full finding count, and unfiltered scope link, including findings retained from earlier partial scans. Those cards keep their own state (Urgent, Open findings, Can't confirm); with nothing to report they say Saved historical scope rather than Clear, and a missing location reads Location not recorded. Packages not from walking a scan folder (such as a `--inventory-file` import) get their own card, named by source (Imported package list, Container image, OS packages, Installed tools). Its state comes from that scan; its findings are the open findings on those exact packages (same path, ecosystem, name, and version), even when a later scan of the same list under another scope found them, and its link lists exactly those findings. Another list naming the same file with different packages does not share them. A complete, clean import can show All clear. Deleted or renamed folders stay listed as Can't confirm, with no command yet to forget them. Today, the only way to clear one is a fresh state folder: keep `VORDA_HOME` set to a new folder (for example in your shell profile), or pass `--state DIR` on every run. Everything except the offline advisory database lives in the state folder, so the new one starts with no mailbox, no scan history, no repair drafts, and no `config.json`; copy `config.json` across to keep settings such as the offline database choice (`advisories`). An explicitly empty saved package list also labels that historical scope Nothing checked.

OSV querybatch runs server-side ecosystem matching in parallel batches of 200 across all page tokens, fetching full records for application advisories. Debian and Ubuntu CVE records can defer large cross-release details: OSV establishes affected versions, while missing CVSS or fix details stay unknown; on Ubuntu, the Canonical record is read once per CVE for fix and priority. Advisory details, EPSS batches, CNA records, and per-CVE distro pages fetch up to eight at a time. Every feed request of one scan shares a 300-second time budget (override with `VORDA_FEED_BUDGET_SECONDS`). Past the budget, requests fail and the scan ends `unknown` (exit 2) naming how many packages were unchecked; cached responses under an hour old still work. Fix advice fetches details on demand; aliases and upstream ids merge per package/version asset. KEV and EPSS enrich hits; CVSS 3 and CVSS 4 base vectors (the higher score if both exist) set priority (`scoring_reason: supported-cvss3` or `supported-cvss4`), falling back to the advisory's own label (GitHub's CRITICAL/HIGH/MODERATE/LOW, shown as `advisory_severity` on the finding, with `scoring_reason: advisory-severity-label`). Unsupported vectors stay unknown. PyPI names normalize via PEP 503 (`Django` and `django` match); crates.io ignores case and treats `-` and `_` as equal. Arch uses its security JSON and native vercmp; Debian tracker fallback uses native dpkg comparison.

### Source authority

Native tracker states `open`, `needed`, `deferred`, `postponed`, and `pending` stay findings, as do needs-triage and ignored or won't-fix states, with `distro: needs triage` or `distro: won't fix` confidence labels. They appear in default output and SARIF and trigger exit 3. Only positive not-affected, DNE, or a fixed version at or below the installed version closes a finding. Review-only or audit-only rows do not count as findings in parity comparisons.

On Ubuntu, findings from OSV `UBUNTU-CVE` records (Canonical's tracker data matched by OSV against the installed dpkg version) or USN OVAL fixed-version criteria already carry the distro verdict and are not re-checked per CVE. Vorda reads OSV's copy of that `UBUNTU-CVE` record once per CVE: if it names a newer fix, `fixed` and `native_verdict.fixed` include it (`distro: fix available <version>`) and the dashboard offers the update; a fix at or below the installed version closes the finding. With no listed fix, the label is `distro: fix not known yet` and the dashboard says the fix is not known. If the record cannot be read, the finding keeps `distro: affected` with no fix and reports an error, making the scan unknown.

The record's CVSS vector or Canonical's priority word sets priority (`scoring_reason: distro-priority`); with neither, priority stays `unknown`. Because Canonical's tracker and ubuntu.com can be more specific than OSV (later `not-affected` or won't-fix), such a CVE stays a finding until the OSV record updates.

Upstream (NVD) matches on Ubuntu use OSV's copy of the Canonical record first when it names a fix for the release. Otherwise, in online scans, Vorda fetches Canonical's raw `ubuntu-cve-tracker` `active` file for the CVE, trying `retired` on 404. A `not-affected` or `DNE` status closes the finding. A `released` status compares the fixed version against the installed source version by dpkg ordering, closing the finding if already met or showing the fix target if newer. An absent, malformed, or unreadable status makes the scan unknown.

On Ubuntu 20.04 (`focal`), `ubuntu-cve-tracker` rows are ESM-prefixed and may lack a plain `focal` line; when an upstream match reaches the raw fallback without a plain `focal` row, the scan becomes unknown. OSV fixed-version decisions on `focal` still work without that fallback. This fallback is online-only; `offline-db` has no Ubuntu support.

Ubuntu OS-package scans (host `--os-packages` and `--oci` images) are experimental. Scan JSON carries `experimental: ["os-packages on Ubuntu: …"]` and prints an `Experimental:` line first in the summary (on stderr with `--json`), as noted in `vorda scan --help`. Reasons: some false alarms remain, because findings OSV already decided do not use Canonical's tracker status; kernel-header packages (`linux-libc-dev`) add many findings; and a missing release entry in a Canonical record can leave the scan unknown. Debian and Alpine are not labelled experimental.

An upstream match without a native tracker entry stays a visible finding (upstream only, distro status not confirmed) and exits 3 with an uncertain audit; native absence alone does not make it unknown, except the Ubuntu raw-tracker fallback makes missing release/source status unknown. Feed failures retain prior findings; only positive fixed or not-affected evidence, or leaving the affected range, closes one. Native uncertainty is shown separately from confirmed findings. Upstream pre-release bounds stay unknown and keep prior findings. Distro revisions are stripped for upstream matching, so NVD-only CVE-2008-0166 needs native review. Versions with over eight numeric components are unsupported. Debian and Alpine comparisons have unit coverage; the latest live OpenSSL replay used Ubuntu. Ubuntu also uses published OVAL fixed-version criteria (not a general OVAL interpreter). Rocky and AlmaLinux use release-specific OSV mappings. Unmapped RPM distros, Homebrew, Chocolatey, and winget stay unknown. winget uses JSON export and never auto-accepts new source agreements.

Vorda never executes files under scan roots. Versions come from manifests, PE/plist metadata, or unambiguous embedded ELF strings; otherwise unknown. Owned, non-writable ELF executables in configured browser caches may run --version. System Linux browser versions come from the package manager, without opening pages or profiles. NVD coverage is limited to the upstream 119-day window; Chrome for Testing and Chrome Releases metadata are fetched too. NVD_API_KEY is optional, read only if set, and never saved.

## Delivery, schedules and fixes

`check --desktop`, `check --webhook YOUR_URL`, and `check --ntfy YOUR_TOPIC_URL` are opt-in; use only endpoints you own. A durable outbox retries failed deliveries with backoff and records health mail while keeping scan output readable. A message stops retrying after 24 failed attempts, keeping its attempt count and last error, and the channel's delivery-health warning clears once nothing is left to retry. A channel unused for a week clears its warning only; queued messages stay and send next time the channel runs. Desktop alerts pass alert text as data, never inside script code: PowerShell reads stdin, and osascript, notify-send, and gdbus receive it as one argument.

`watch install|uninstall|status` picks systemd, cron, launchd, or Windows Task Scheduler (or uses `--backend`). Scheduled runs scan only configured roots (`watch install --root DIR`, repeatable); OS packages, tools, and browsers need explicit install flags. Status queries the scheduler. The systemd daily scan runs at 03:15 between hourly runs. Scans wait up to five minutes for the mailbox lock before logging a health error. Linux systemd install/status/uninstall was tested and its units removed; macOS and native Windows schedule installation remain untested. Unknown or failed runs are not systemd successes; findings exit 3, which the service accepts, while status 1 remains a failure.

Watch resolves its advisory mode at install time (explicit `--offline-db` or `--online`, otherwise `VORDA_ADVISORIES`, `config.json` `advisories`, or the `offline-db` default) and pins that choice into the generated command, so reinstalling without a flag re-resolves the default rather than reusing `watch.json`. Offline watch scans never automatically refresh the database or fall back to online lookups; run `db update` daily, because a missing or stale database reports `unknown` health.

`fix --dry-run` prints fix commands for your lockfile's package manager using known fixed versions where available. Constraints, backports, or unreleased fixes can block upgrades, so rescan afterward. Only `fix --chromium --apply` writes browser binaries, via an upstream checksum- and size-verified same-major swap with backup (`fix --chromium --undo` reverses it). All other commands are advice only.

## Evidence and limits

```sh
cargo test --locked --manifest-path rust/Cargo.toml
```

The test suite covers hostile browser scripts, independent readers, snooze expiry, interrupted and concurrent scans, pagination, aliases, duplicate versions, removal, scoped health, enrichment movement, delivery retry, MCP, and hook output. macOS support is untested; Windows notification appearance, launchd, and Task Scheduler remain unverified.

## Building the native executable

Build from a checkout with `cargo build --locked --release --manifest-path rust/Cargo.toml`. For packaged binaries, use the [native release scripts](../rust/README.md), which keep license notices, checksums, and explicit target names. `vorda licenses` prints the embedded notices. Linux builds need OpenSSL development headers and pkg-config; runtime hosts need matching OpenSSL libraries.

Native behavior tests live in `rust/tests` and `rust/src/scanner/tests.rs`; platform and live-provider checks have separate limits.

## Repair setup errors

Repair needs a local Git identity in the repo to create commits: `git config user.name "Your Name"` and `git config user.email "your-address"`. Scanning and previews do not. Executable Git filters (including Git LFS), signers, and custom diff drivers are refused during repair; the error names the setting, scope (system, global, or local), and source file, while scanning still works. New clones inherit system and global settings, so re-cloning will not clear those refusals. Update dependencies manually or use a clean environment (such as a disposable container) without executable Git settings. Do not disable filters in a working LFS repo to bypass this safety check.

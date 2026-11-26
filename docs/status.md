# Status and limits

Here is what is unfinished, experimental, or not covered yet. See the
[technical reference](reference.md) for the details behind each point.

## Release status

v0.2.1 is the current release (v0.2.0 was the first signed release;
v0.1.0 and v0.1.1 were unsigned). GitHub Releases provides signed static
executables for Linux (x86_64 and arm64, musl with OpenSSL compiled in)
with SHA-256 checksums and minisign signatures (key ID
`57E5204A70E3811B`), so `vorda verify-self` reports `verified` after
install. macOS and Windows build from source for now. See the
[README](../README.md) to get started, [install](install.md) for
installer options, manual verification and source builds, and the
[support matrix](support-matrix.md) for per-platform checks.

## What a result means

Usage errors exit 64 (EX_USAGE) and report JSON status `usage_error`. The GitHub Action fails on exit 64 whatever `fail-on-findings` is set to.

| Result | Example | `vorda scan` exit | `status` | Action with `fail-on-findings: 'true'` | Action `coverage`, SARIF uploaded |
| --- | --- | --- | --- | --- | --- |
| Clean | every package checked, none vulnerable | 0 | `no-known-findings` | passes | `complete`, yes |
| Finding | a vulnerable package | 3 | `vulnerable` | fails (exit 1) | `complete`, yes |
| Finding with gaps | a vulnerable package, plus a package or file that was not checked | 3 | `vulnerable` | fails (exit 1) | `partial`, no |
| Not assessed | a `Gemfile.lock` in the project you scan, under the offline database | 2 | `unknown` | fails (exit 2) | `partial`, no |
| Error | a lockfile Vorda cannot read, or a failed lookup | 2 | `unknown` | fails (exit 2) | `partial`, no |
| Nothing to scan | no dependency file Vorda recognizes (prints a "Nothing to scan" notice) | 0 | `no-known-findings` | fails (exit 2) | `partial`, no |

A machine scan (`vorda scan` with no path) lists packages it could not check under `not_assessed` and marks coverage partial, but does not report `unknown` for them, so it exits 0 when nothing is found. With `fail-on-findings: 'false'`, the Action passes in every row and logs a warning for the unknown and partial ones.

- Read `errors`, `not_assessed` and `coverage_evidence` before relying on a result.
- Anything Vorda could not read or check yields unknown, never clean: an unreadable
  supported file, an empty lockfile whose manifest declares
  dependencies, a recognised unsupported format, a supported file skipped as a link or
  special file, or a nested project not listed by an upper lockfile. See
  [recognised inputs](reference.md#inventory-and-matching) and
  [empty lockfiles](reference.md#empty-lockfiles).
- Files with unrecognised names are not classified, so a dependency list with an unusual
  filename can be missed silently.
- If you delete or rename a scanned project folder, it stays on the dashboard as
  Can't confirm (Folder missing). There is no forget command yet; use a fresh state
  folder instead, which resets your mailbox, scan history, and settings
  ([details](reference.md#os-and-tool-inventory)).

## Not covered

- **No dependency resolution.** A requirements.txt is checked only as written. Transitive
  packages pip would install are not looked up, and coverage can still report `complete`.
  Scan a full lockfile (`uv.lock`, `poetry.lock`, or a `pip freeze` requirements.txt) to
  cover them.
- **Offline database.** Manual `vorda scan`, `vorda check`, and the GitHub Action
  default to the local offline advisory database with no automatic network fallback,
  exiting 2 in noninteractive runs when no database is installed (see
  [cli.md](cli.md#offline-advisory-database-and-defaults) for precedence and setup).
  MCP `check` also defaults to the local offline advisory database with no automatic
  network fallback. `scan --offline-db` covers npm, PyPI, crates.io, and Go. Other
  ecosystems, `--os-packages`, and `--tools` go in `not_assessed` offline, so they
  do not make a machine scan unknown on their own; lockfile packages in a project you
  name do (exit 2). They set `coverage_evidence.status` to
  `partial`, and `--online` checks them. Browser feeds that need the network also
  go in `not_assessed`, but `--browsers` stays unknown with no findings, online and
  offline, because Chrome data covers only the latest 119 publication days. Offline,
  EPSS is skipped. `vorda agentbom` is online by default and uses the local database
  only when `VORDA_ADVISORIES` or `config.json` sets `offline-db`. MCP `agent_check`
  is also online by default unless the call sets `offline: true`, or
  `VORDA_ADVISORIES` or `config.json` sets `offline-db`. `vorda repair` always
  rescans online. Some real versions stay unknown offline
  (for example torch 2.6.0, apache-airflow 2.9.0, and go-redis v9.6.0 and earlier),
  though other advisories on them still report. For older torch and airflow, offline can
  list a few more advisories than online. See [which versions stay unknown](reference.md#exit-codes).

  See [offline advisory database](reference.md#offline-advisory-database).

## Experimental

- **OS packages on Ubuntu** (`--os-packages`, and `--oci` images): some findings are
  still false alarms, and a scan can end unknown. In online scans, when OSV and Ubuntu
  security notices do not decide an upstream finding, Vorda checks Canonical's raw
  Ubuntu CVE tracker (active, then retired if missing), dropping not-affected and DNE
  entries and comparing released fixes with dpkg ordering. Missing, malformed, or
  unreadable rows (including Ubuntu 20.04 focal ESM-prefixed rows) report unknown.
  In offline scans, OS-package feeds that need the network are listed under `not_assessed` instead of making the scan `unknown`. Checking OS packages requires online mode. See [source authority](reference.md#source-authority).
- **`vorda agentbom`** (MCP servers, skills, agent CLIs, IDE extensions, models) is a
  preview with incomplete coverage handling. See
  [agent inventory](reference.md#agent-inventory-preview-known-coverage-limits).
- **The hub**, below.

## The hub

The optional self-hosted hub ([linking](linking.md)) is experimental. These limits apply
only if you link one; local scans are unaffected.

- **Size.** The hub stops accepting new results (HTTP 503) once its database hits its
  ceiling: 1 GiB by default, changed with `--max-db-mib` on `link serve` and other hub
  commands (the device outbox stays 64 MiB). One full assessment (up to 1,500 records,
  256 inputs, 4 MiB) uses about 6 to 10 MB in the hub, so the default fits roughly 100
  to 170 of them.
- **One device can fill it.** Per-device caps do not isolate devices: one device can fill
  the default hub in about 110 to 170 full assessments, leaving every device with 503. A
  per-device byte quota is a future item. Each device keeps at most 64 authorities of 64
  assessments.
- **Upload speed.** A full 4 MiB request must arrive within about 5 seconds (roughly
  7 Mbit/s upload). At full retention, a late-arriving assessment has only about 16%
  headroom under the one-second admission deadline.
- **Reading history.** On a default schema 2 hub, `changes` replays history from the
  start on every page. On the 50,000-row test hub that took about 0.9 s per page,
  about 551 s for 618 pages, peaking above 570 MiB. With `migrate --change-log`
  (opt-in schema 3), pages read a stored log: the same walk took about 14.5 s (page p95
  about 29 ms) and grew the database by about 9%. Admissions during a schema 2 walk can
  use much of their 200 ms allowance. Late-arriving assessments on schema 3 recompute
  their authority and have not been timed yet.
- **Export time.** `link export` and `link queue` read the observation time inside the
  scan result, not the file mtime. Results missing that time are refused
  (`this result has no observation time; scan again`). The timestamp is unsigned, so
  anyone who can edit the file can change it.

One measured run admitted 10 devices and 50,000 observation rows through the real
admission path without refusal (one machine, one run). See
[hub limits and measured performance](performance.md) for full numbers and gaps.

# Command reference

Each block below is Vorda's own help text (`vorda --help`, `vorda COMMAND --help`). Bare `vorda` prints the same help and exits 0.

```text
Usage: vorda [--state DIR] COMMAND [options]
       vorda help [COMMAND] | vorda COMMAND --help | vorda --version

To start, run vorda setup to choose offline or online advisories and scan this machine. You can also run vorda scan for this machine or vorda scan PATH for one project (run vorda help scan to see its options).

Check:
  scan          Check this machine (OS packages, tools, browsers, apps, home projects) or named paths or images for vulnerabilities
  check         Same as scan
  inventory     List the packages a scan would check, without looking up advisories
  db            Download or show the offline advisory database that scan uses by default (same as --offline-db)
  agentbom      List AI agent tooling (MCP servers, skills, models) and check it (preview)
Read results:
  mail          List, read, acknowledge or snooze saved findings
  dashboard     Serve the local web dashboard of saved scans
  mcp           Run the MCP server that lets coding agents scan and read the mailbox
Set up:
  setup         Choose offline or online advisories, optionally schedule scans, and scan this machine
  connect       Add Vorda to an agent client's config
  snippet       Print agent setup snippets
  hook          Print the agent session hook output
  watch         Install, remove or show scheduled scans
Act on findings:
  fix           Print fix commands (and swap Chromium with --chromium --apply)
  repair        Plan, review and apply reviewed dependency repairs
  repair-mcp    Run the MCP server for the repair queue
  mode          Show or set watch, advise or fix mode
  can           Ask whether an agent may take an action
Fleet:
  link          Link machines to a hub
  hub-mcp       Run the MCP server that reads a hub
  snapshot-read Read a saved snapshot (trusted local input)
Other:
  update        Update this executable from a signed release
  verify-self   Verify this executable's signature
  licenses      Print third-party licenses
  version       Print the version

Scan exits: 0 = no known findings, 3 = vulnerable, 2 = unknown/incomplete or operational error, 64 = usage error (EX_USAGE).
```

Put `--state DIR` before the command (`VORDA_HOME` sets its default). `vorda --version`, `-V`, and `vorda version` print the version. `vorda help COMMAND` matches `vorda COMMAND --help`. A test verifies every block here against the executable.

## vorda setup

Guided first-time setup: pick and save an advisory mode (`offline-db` or `online`) in `config.json`, download the local database when offline, optionally install scheduled machine scans, and run the first scan of this machine. Run `vorda setup` again anytime to change the saved mode.

Running bare `vorda` with no arguments in a terminal (when stdin, stdout and stderr are all terminals, `CI` and `GITHUB_ACTIONS` are unset, and neither `config.json` nor `VORDA_ADVISORIES` has set a mode yet) starts `vorda setup` automatically. Otherwise bare `vorda` prints the main help, and `vorda --help`, `vorda -h`, and `vorda help` always print help.

```text
Usage: vorda setup [--offline-db | --online] [--watch | --no-watch]

Choose offline or online advisories, save the choice to config.json, download the local database when offline, optionally install scheduled machine scans, and run the first scan of this machine.

  --offline-db  Use the local advisory database (default in a terminal; downloads OSV exports for npm, PyPI, crates.io and Go plus the CISA KEV list to ~/.cache/vorda/advisory-db, 25 to 80 seconds and about 190 MB; package names never leave this machine; other ecosystems and network-only feeds are listed as not assessed)
  --online      Send package names and versions to OSV.dev on each scan and also check the feeds the offline database lacks
  --watch       Install scheduled hourly and daily machine scans (vorda watch install --machine) without prompting
  --no-watch    Skip scheduled machine scans without prompting

In a terminal without a mode flag, setup prompts for 1 (offline, default on Enter) or 2 (online); any other answer exits 64 without saving. Outside a terminal or in CI, pass --offline-db or --online or setup exits 64 without saving.

The choice is saved as "advisories": "offline-db" or "advisories": "online" in config.json in the state folder (keeping any other keys) and applies to later vorda scan, vorda check, vorda watch install and MCP check runs. Single-scan --online or --offline-db flags still win for that scan, and VORDA_ADVISORIES wins over config.json (setup prints a note if it is set to the other mode). Run vorda setup again anytime to change the saved choice.

In offline mode, setup runs vorda db update. If the download fails or any line is not updated, setup stops with exit 2 without scanning; the choice stays saved so you can run vorda db update and then vorda scan.

Without --watch or --no-watch, setup asks in a terminal whether to install scheduled hourly and daily machine scans via systemd, cron, launchd or Windows Task Scheduler (default no; only y or yes installs), and skips them outside a terminal. Scheduled offline scans do not refresh the local advisory database: run vorda db update daily (for example from your own scheduler), or scans go unknown once the database is more than 72 hours old.

Last, setup runs vorda scan on this machine (OS packages, tools, browsers, installed apps (Windows only), and project lockfiles under home), prints a reminder to run vorda dashboard, and exits with the scan's exit code (0 no known findings, 3 vulnerable, 2 unknown). Running bare vorda with no arguments in a terminal (outside CI) before any mode is set in config.json or VORDA_ADVISORIES starts setup automatically; vorda --help, -h and help always print help.
```

## vorda scan and vorda check

`check` is the same command as `scan`.

```text
Usage: vorda scan [PATH ...] [--root DIR] [--os-packages] [--tools] [--browsers] [--installed-apps] [--installed-root PATH] [--oci ARCHIVE] [--exclude PATH] [--offline | --offline-db | --online] [--scheduled] [--inventory-file FILE] [--webhook URL] [--ntfy URL] [--desktop] [--json]

With no PATH, --root, --inventory-file, or --oci, scans this machine: OS packages, tools, browsers, installed apps (Windows only), and project lockfiles under your home folder (skipping caches, toolchains, downloads, app data, and trash). Pass one or more PATH arguments to scan only those folders or lockfiles; a bare PATH works like --root DIR.
Prints a short summary; --json prints the full machine-readable result.
--offline makes no network request and reads no advisories: it lists the packages found, and the result is always unknown (exit 2). For a complete check without network, use --offline-db.
Manual scan and check commands default to the local offline advisory database (--offline-db). Use --online to query OSV.dev for one scan, --offline-db to use the local database, or --offline for an inventory-only scan that always reports unknown (distinct from --offline-db). Mode precedence is CLI flags, then VORDA_ADVISORIES, then config.json (advisories), then the --offline-db default. If no local advisory indexes exist yet, an interactive terminal prompts to download the database or scan online once; noninteractive runs exit 2 (unknown) with no automatic network fallback.

--exclude PATH  Leave a folder or file under a root out of the scan on purpose (repeatable). Excluded paths appear in the summary and JSON "excluded" field and are not checked, so the result says nothing about them. Scans with --exclude are saved separately from full scans and never close findings a full scan saved.

--os-packages on Ubuntu (host or --oci image) is experimental: OSV-decided findings miss Canonical's not-affected or won't-fix status, causing false alarms; kernel-header packages (linux-libc-dev) add many findings; a scan can end unknown when a Canonical record has no entry for this release.
```

- `--exclude PATH`: leave a folder or file under a scan root out on purpose (repeatable). Excluded paths are listed in the summary and the JSON `excluded` field and are not checked, so the result says nothing about them. A scan with `--exclude` is saved separately from a full scan, so it never closes findings a full scan saved.
- `--oci ARCHIVE`: inventory or scan one local OCI archive without executing it.
- `--scheduled`: keep missing tool lookups unknown in unattended scans.
- `--inventory-file FILE`: scan a saved read-only JSON package inventory.
- `--webhook URL`: opt-in URL of your own endpoint. `--ntfy URL`: opt-in full URL of your own topic.
- `--json`: print the full result instead of the summary; exit code stays the same.

- `--offline`: no requests at all; the result is always unknown (exit 2).
- `--offline-db`: local offline advisory database, no network; see [offline advisory database](reference.md#offline-advisory-database).
- `--online`: query OSV.dev for this one scan; wins over the default, `VORDA_ADVISORIES` and `config.json` (even `offline-db`).

See [reference.md](reference.md#run) for what the summary shows.

### Offline advisory database and defaults

`vorda scan` and `vorda check` default to the local offline advisory database (`--offline-db`) and never fall back to the network. Use `--online` for one OSV.dev scan, or set `VORDA_ADVISORIES=online` or `"advisories": "online"` in `config.json` to keep online mode on for every scan. Precedence: CLI flags, `VORDA_ADVISORIES`, `config.json`, then `--offline-db`. `--offline` differs from `--offline-db`: it inventories packages with no advisory lookup and always reports unknown (exit 2).

### First-use setup

Run `vorda setup` (or bare `vorda` in a terminal on first run) to choose offline or online advisories and save that choice in `config.json` for later scans. If you run `vorda scan` directly in a terminal without `--json` or `--scheduled` and no local advisory indexes exist yet, the scan-time prompt still runs: (1) download the offline advisory database (25 to 80 seconds, about 190 MB; package names stay local), (2) scan online once (sends package names and versions to OSV.dev), or Enter to cancel. A stale database or missing ecosystem skips the prompt and reports those targets unknown.

### Offline coverage

Offline mode checks npm, PyPI, crates.io, and Go packages regardless of inventory source. Other ecosystems and network-only feeds are listed in `not_assessed` instead of `errors`, so they do not make a scan `unknown` on their own. They set `coverage_evidence.status` to `partial`; pass `--online` to check them. Missing or stale indexes for those four ecosystems still report errors (`unknown`).

### Noninteractive, CI, and GitHub Action

Vorda never prompts in noninteractive shells, CI or the GitHub Action. With no local offline advisory database, the scan exits 2 (unknown) and tells you to run `vorda db update` and retry, or run `vorda scan --online` once. The GitHub Action defaults to the local offline database, and with none installed it reports `status=unknown` and fails the step (exit 2) even with `fail-on-findings=false`. Set the `advisories` input to `online` (or `VORDA_ADVISORIES=online`) to scan online.

## vorda db

```text
Usage: vorda db update [--ecosystem NAME]... [--from DIR] [--json]
       vorda db status [--json]

update downloads OSV per-ecosystem exports (all.zip) and the CISA KEV list to build the local offline advisory database (VORDA_ADVISORY_DB_DIR, default ~/.cache/vorda/advisory-db). OSV exports carry no completeness marker, so update replaces an index only when readable and large enough: it keeps the current index if an export has fewer than 90% of the most entries a clean index has held, or under about half of a complete export for its ecosystem (VORDA_ADVISORY_DB_MIN_ENTRIES overrides this for a small private mirror). --from reads DIR/<Ecosystem>/all.zip and DIR/kev.json instead of downloading; their age is the files' modification time. Ecosystems: npm, PyPI, crates.io, Go (default: all). update exits 2 unless every line is `updated`; it also exits 2 if the copy just loaded is already older than the VORDA_ADVISORY_DB_MAX_AGE_HOURS limit (default 72; that line reads `updated-stale`). status shows what `scan --offline-db` (default scan) would use and exits 2 unless every line is ready; an index older than that limit is not used.
```

- `--ecosystem NAME`: refresh one ecosystem (repeatable). Always refreshes the KEV list.
- `--from DIR`: load from a mirror folder; keep file modification times when syncing.
- Outcomes, exit codes, staleness and partial-mirror refusals: [offline advisory database](reference.md#offline-advisory-database).

## vorda inventory

```text
Usage: vorda inventory [--root DIR] [--os-packages] [--tools] [--browsers] [--installed-apps] [--installed-root PATH] [--oci ARCHIVE] [--format json|cyclonedx|spdx]
```

## vorda mail

```text
Usage: vorda mail {list,read,ack,snooze} --reader NAME [--id INTEGER] [--seconds INTEGER] [--limit N]

list shows the oldest 20 unread messages unless --limit raises it.
```

## vorda mcp

```text
Usage: vorda mcp
```

## vorda dashboard

```text
Usage: vorda dashboard [--bind ADDRESS] [--port PORT] [--token] [--allow-writes] [--fix-config FILE]

Serve the local web dashboard of saved scans and print its URL.

  --bind ADDRESS     IP address or localhost (default 127.0.0.1); beyond loopback needs --token
  --port PORT        Port to listen on (default 7780; 0 picks a free port)
  --token            Require login token (VORDA_DASHBOARD_TOKEN; random if unset and in URL on terminals only)
  --allow-writes     Turn on review, repair, publish and mode controls (also turns on --token)
  --fix-config FILE  Fix engine config (policy, fleet file, machine)

With --allow-writes, whoever holds the token acts as this OS user.
```

## vorda hook

```text
Usage: vorda hook [--reader NAME] [--event {SessionStart,UserPromptSubmit}]

Print the agent session hook output. When the mailbox reader has unread vulnerability messages,
prints a JSON hookSpecificOutput with the first three titles marked as untrusted data; prints
nothing otherwise. Set it up with vorda snippet claude-hook.

  --reader NAME  Mailbox reader name (default claude)
  --event EVENT  Hook event: SessionStart or UserPromptSubmit (default SessionStart)
```

## vorda snippet

```text
Usage: vorda snippet {agents,claude-hook,mcp,codex}

Print a setup snippet to paste. Each uses this executable's full path and state folder.

  agents       Line for an agent instructions file telling it to read the mailbox at session start
  claude-hook  Claude Code hook JSON that runs vorda hook
  mcp          MCP server JSON for clients that take mcpServers
  codex        Codex config.toml block
```

## vorda watch

```text
Usage: vorda watch {install,uninstall,status} [--backend {systemd,cron,launchd,windows}] [--machine | --root DIR] [--os-packages] [--tools] [--browsers] [--offline-db | --online]

With no --root, scheduled scans check this machine (unless an earlier install saved a root). Pass --root DIR to schedule a project scan; later installs remember it until you pass --machine to switch back.
Note: scheduled scans do not update the local advisory database. Schedule `vorda db update` yourself (for example daily); a missing database or one older than 72 hours (VORDA_ADVISORY_DB_MAX_AGE_HOURS changes this) makes each scheduled scan record unknown (exit 2), with no network fallback.
--offline-db schedules scans against the local advisory database with no network fallback.
--online schedules scans that explicitly send package names and versions to OSV.dev.
The chosen mode is saved in watch.json and passed explicitly to every backend's scan command (passing both is rejected). Without either flag, scheduled scans follow the config, environment, or CLI advisory default.
```

## vorda fix

```text
Usage: vorda fix [--dry-run] [--chromium] [--apply] [--undo] [--root DIR]

Print JSON fix commands for saved findings using known fixed versions and each lockfile's package
manager. Without --chromium --apply it changes nothing. Rescan after upgrading.

  --dry-run   Change nothing (default when printing commands or previewing --chromium)
  --chromium  Swap a Chromium build for a checksum- and size-verified same-major upstream build
  --apply     Do the Chromium swap with a backup (with --chromium only; previews without --apply)
  --undo      Restore the Chromium backup (with --chromium only)
  --root DIR  Where to look for Chromium builds (repeatable)
```

## vorda repair

```text
Usage: vorda repair --config FILE {claim,plan,apply,verify,release,approve,deny,draft,drafts,dismiss,publish,recover} [--item ID] [--agent NAME] [--repo DIR] [--manager apt] [--package NAME] [--old VERSION] [--new VERSION] [--locked] [--apply] [--reviewer NAME] [--digest SHA256] [--repository OWNER/REPO] [--base BRANCH] [--branch BRANCH]

Plan, review and apply reviewed dependency repairs.

  --config FILE            Repair config file (host-approved checks and policy)
  --item ID                Repair item ID (required for all actions except drafts)
  --agent NAME             Agent name (default local)
  --repo DIR               Repository folder for a repo plan
  --manager apt            Package manager for an OS plan (default apt)
  --package NAME           Package name for plan
  --old VERSION            Current package version for plan
  --new VERSION            Target package version for plan
  --locked                 Resolve and review both npm manifest and lockfile
  --apply                  Apply defaults to a dry run; --apply makes the change
  --reviewer NAME          Must match the current OS user
  --digest SHA256          Digest from the exact reviewed draft; required for approve, deny, publish
  --repository OWNER/REPO  Explicit GitHub repository for publish
  --base BRANCH            Destination base branch for publish
  --branch BRANCH          New branch for publish

The repair contract is in docs/repair-contract.md.
```

## vorda repair-mcp

```text
Usage: vorda repair-mcp --config FILE --agent NAME
```

## vorda connect

```text
Usage: vorda connect [{claude-code,codex,cursor,claude-desktop}] [--home DIR] [--config FILE] [--apply] [--undo RECEIPT]
       connect {claude-code,codex} --hub URL --reader-env ENV_NAME [--ca-file PATH] [--name NAME] [--apply]
       connect {claude-code,codex} --skill [--skill-dir DIR] [--apply]

Add Vorda to an agent client's config. Without --apply, shows the change and writes nothing.

  --home DIR             Home folder for locating client config
  --config FILE          Explicit client config file
  --apply                Write the change and save an undo receipt
  --undo RECEIPT         Revert a connect receipt (takes no other connect option except --home)
  --hub URL              Add a vorda-fleet hub-mcp entry (claude-code and codex)
  --reader-env ENV_NAME  Upper-case env var name (at most 31 characters) for the reader credential
  --ca-file PATH         CA certificate file for the hub
  --name NAME            MCP entry name for --hub (default vorda-fleet)
  --skill                Copy the vorda skill
  --skill-dir DIR        Target folder for --skill
```

## vorda mode

```text
Usage: vorda mode [{watch,advise,fix}] [--machine NAME] [--agent NAME] [--fleet FILE]

With no mode, print the current mode and why. With a mode, set it in the fleet file for the whole
fleet, one machine or one agent (not both). Changing the mode never applies a change on its own.

  watch           Collect findings without proposing changes
  advise          Prepare advice for review
  fix             Let approved changes run only when policy also allows them
  --machine NAME  Target one machine (cannot be combined with --agent when setting a mode)
  --agent NAME    Target one agent (cannot be combined with --machine when setting a mode)
  --fleet FILE    Fleet file (default vorda.yaml in the current folder)
```

## vorda can

```text
Usage: vorda can AGENT ACTION [--machine NAME] [--group NAME] [--fleet FILE]

Print yes, ask or no with the reason; exits 0 only for yes, and 1 otherwise. ACTION is one of:
browsers, lockfiles, os-packages, containers, agent-tools, config. kernel, sshd, bootloader and
package-manager are always no, and every action is no unless the mode is fix.

  --machine NAME  Check policy for this machine
  --group NAME    Check policy for this group
  --fleet FILE    Fleet file (default vorda.yaml)
```

## vorda agentbom

```text
Usage: vorda agentbom [--root DIR] [--home DIR] [--host HOST] [--include-home] [--offline] [--no-save] [--no-models]
```

- `--root DIR`: project folder to search for project MCP configs, skills and model files.
- `--home DIR`: home folder to inventory (default: yours), for example a mounted Windows profile.
- `--host HOST`: host label for fleet reports (default: hostname).
- `--include-home`: also scan home AI tooling when `--root` selects projects.
- `--offline`: static rules only, no feed requests. `--no-save`: print only, do not write the mailbox. `--no-models`: skip model file discovery.
- Exits 0 with no findings, 1 with findings (including `attention`), and 2 when unknown, even if findings are listed (every `--offline` run is unknown). This differs from scan's exit 3.
- `agentbom` is a preview: a clean result is not a security clearance. See [known coverage limits](reference.md#agent-inventory-preview-known-coverage-limits).

## vorda link

```text
Usage: vorda link --db FILE {invite,serve,enroll,revoke,rotate,snapshot,export,queue,queue-native,send,health,bundle,bind,enroll-local,import,ack,migrate,restore,reader-grant,reader-revoke,capture-allow,capture-deny} [options]
```

See [linking.md](linking.md).

## vorda hub-mcp

```text
Usage: vorda hub-mcp --hub URL --reader-env ENV_NAME [--ca-file PATH]
```

See [fleet-clients.md](fleet-clients.md).

## vorda snapshot-read

```text
Usage: vorda snapshot-read SNAPSHOT.json GRANT.json QUERY.json AS_OF
Trusted-local snapshot, grant and as-of inputs; no authentication, collection or state writes.
```

Wrong argument counts exit 64 with `{"error": MESSAGE, "status": "usage_error"}` on stderr and nothing on stdout; other refusals exit 2 with `{ "error": TAG, "data": null }` on stdout. See [saved-snapshot-reader.md](saved-snapshot-reader.md).

## vorda update

Updates this Vorda executable from an official signed GitHub release (`https://github.com/Ken-Jee/vorda/releases`) and, when offline mode is saved (`VORDA_ADVISORIES=offline-db` or `"advisories": "offline-db"` in `config.json`), refreshes the offline advisory database with `vorda db update`.

Only releases signed by the release key built into the running executable are accepted, and the previous executable is kept as `vorda.old` (`vorda.exe.old` on Windows). See [install.md#update](install.md#update) for the trust model, rollback behavior, and how to replace unsigned releases (`v0.1.0` and `v0.1.1`).

```text
Usage: vorda update [--check] [--version VERSION]

Download and install a signed release from https://github.com/Ken-Jee/vorda/releases. Vorda fetches SHA256SUMS and SHA256SUMS.minisig, checks the signature against the release public key built into this executable (key ID 57E5204A70E3811B; no key file, URL or environment variable can change which key is trusted), selects this platform's build (static musl on Linux), downloads the executable, verifies its SHA-256 against the signed list, and verifies the executable's own .minisig signature with the same built-in key.

The new executable is written beside the current one and renamed into place, keeping the previous executable as vorda.old (vorda.exe.old on Windows) and saving the release signature as vorda.minisig so vorda verify-self verifies it afterwards. Vorda then runs the new executable with --version and restores the previous executable if that check fails. When offline mode is saved (VORDA_ADVISORIES=offline-db or "advisories": "offline-db" in config.json), update also runs vorda db update with the new executable (including when already up to date), unless --check is set.

  --check            Report whether a newer signed release is available without changing anything or refreshing the offline advisory database
  --version VERSION  Install a specific release (for example 0.2.0 or v0.2.0), even if it is older than the running version; without this flag, only a newer release is installed

Package-manager installs, development builds without a built-in release key, and unsigned releases (such as v0.1.0 and v0.1.1) are refused without changing anything. Exits 0 when updated, already up to date or after --check (or with vorda db update's exit code when refreshing the offline advisory database), 2 on errors or rollback, and 64 on usage errors.
```

## vorda verify-self

```text
Usage: vorda verify-self [--file FILE] [--sig SIGNATURE] [--pubkey PUBLIC_KEY]
```

Exit codes and the signing model are in [install.md](install.md).

## vorda licenses

```text
Usage: vorda licenses
```

`vorda scan` and `vorda check` exit 0 with no known findings, 3 with vulnerabilities, and 2 when the result is unknown or incomplete, or an operational error happens. Usage errors exit 64 (EX_USAGE) with JSON status `usage_error` and always fail the GitHub Action, whatever `fail-on-findings` is set to.

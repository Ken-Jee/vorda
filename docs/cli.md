# Command reference

Each block below is Vorda's own help text (`vorda --help`, `vorda COMMAND --help`). Bare `vorda` prints the same help and exits 0.

```text
Usage: vorda [--state DIR] COMMAND [options]
       vorda help [COMMAND] | vorda COMMAND --help | vorda --version

Check:
  scan          Check lockfiles and pinned requirements (and, if asked, OS packages, tools, browsers, apps, images) for known vulnerabilities
  check         Same as scan
  inventory     List the packages a scan would check, without looking up advisories
  db            Download or show the offline advisory database that scan uses by default (same as --offline-db)
  agentbom      List AI agent tooling (MCP servers, skills, models) and check it (preview)
Read results:
  mail          List, read, acknowledge or snooze saved findings
  dashboard     Serve the local web dashboard of saved scans
  mcp           Run the MCP server that lets coding agents scan and read the mailbox
Set up:
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
  verify-self   Verify this executable's signature
  licenses      Print third-party licenses
  version       Print the version

Scan exits: 0 = no known findings, 3 = vulnerable, 2 = unknown/incomplete or operational error, 64 = usage error (EX_USAGE).
```

Put `--state DIR` before the command (`VORDA_HOME` sets its default). `vorda --version`, `-V`, and `vorda version` print the version. `vorda help COMMAND` matches `vorda COMMAND --help`. A test verifies every block here against the executable.

## vorda scan and vorda check

`check` is the same command as `scan`.

```text
Usage: vorda scan [--root DIR] [--os-packages] [--tools] [--browsers] [--installed-apps] [--installed-root PATH] [--oci ARCHIVE] [--offline | --offline-db | --online] [--scheduled] [--inventory-file FILE] [--webhook URL] [--ntfy URL] [--desktop] [--json]

--root DIR is a folder or lockfile to scan (repeat it for more; default: the current folder).
Prints a short summary; --json prints the full machine-readable result.
--offline makes no network request and reads no advisories: it lists the packages found, and the result is always unknown (exit 2). For a complete check without network, use --offline-db.
Manual scan and check commands default to the local offline advisory database (--offline-db). Use --online to query OSV.dev for one scan, --offline-db to use the local database, or --offline for an inventory-only scan that always reports unknown (distinct from --offline-db). Mode precedence is CLI flags, then VORDA_ADVISORIES, then config.json (advisories), then the --offline-db default. If no local advisory indexes exist yet, an interactive terminal prompts to download the database or scan online once; noninteractive runs exit 2 (unknown) with no automatic network fallback.

--os-packages on Ubuntu (host or --oci image) is experimental: OSV-decided findings miss Canonical's not-affected or won't-fix status, causing false alarms; kernel-header packages (linux-libc-dev) add many findings; a scan can end unknown when a Canonical record has no entry for this release.
```

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

Setup runs only when no local advisory indexes exist. It prompts only for a scan run in a terminal without `--json` or `--scheduled`: (1) download the offline advisory database (about 80 seconds; package names stay local), (2) scan online once (sends package names and versions to OSV.dev), or Enter to cancel. A stale database or missing ecosystem skips setup and reports those targets unknown.

### Offline coverage

Offline mode checks npm, PyPI, crates.io and Go packages regardless of inventory source. Other ecosystems or network-only feeds report `unknown`.

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
  --token            Require a login token (VORDA_DASHBOARD_TOKEN or random); carried in the URL
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
Usage: vorda watch {install,uninstall,status} [--backend {systemd,cron,launchd,windows}] [--root DIR] [--os-packages] [--tools] [--browsers] [--offline-db | --online]

--offline-db schedules scans against the local advisory database with no network fallback. Scheduled jobs never refresh the database automatically; run `vorda db update` daily before scheduled scans (default max age 72 hours, adjustable via VORDA_ADVISORY_DB_MAX_AGE_HOURS). Missing or stale databases record unknown health messages (exit 2).
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

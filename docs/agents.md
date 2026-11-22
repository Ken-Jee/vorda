# Vorda for AI agents

Follow the [quick start](../README.md) to install, or browse [every command and flag](cli.md).
Run `vorda --help`, `vorda COMMAND --help`, or subcommand help for live usage.
Put `--state DIR` before the command; `VORDA_HOME` sets the default state folder.

## Connect a client

```sh
vorda connect claude-code
vorda connect claude-code --apply
```

The first command previews the edit; the second writes it and prints an undo receipt.
Supported clients: claude-code, codex, cursor, claude-desktop.
Undo with `vorda connect --undo RECEIPT`. Only apply with the owner's permission.
For manual setup, `vorda snippet mcp` prints JSON and `vorda snippet codex` prints TOML using the installed executable. `vorda mcp` serves the mailbox over stdio JSON-RPC with an explicit scan tool. No daemon is needed.

## Output and status

Exit codes: 0 means no known findings in completed inputs, 3 means findings, 2 means unknown, incomplete coverage, or an operational error, and 64 (EX_USAGE) means a usage error (JSON status `usage_error`).

`vorda scan` prints a short summary (`--json` for full output) and saves results locally.
It checks the [local offline advisory database](reference.md#offline-advisory-database) by default (`--offline-db`) with no automatic network fallback; pass `--online` for one online scan, or set `VORDA_ADVISORIES=online` or `advisories` to `online` in `config.json` to keep online on for every scan.
Precedence is CLI flags, then `VORDA_ADVISORIES`, then `config.json`, then the `--offline-db` default.
MCP `check` follows the same default and precedence, while MCP `agent_check` is online by default unless you pass `offline: true` or configure `offline-db`.
If no local advisory indexes exist, a scan run in a terminal without `--json` or `--scheduled` prompts to download the database (`vorda db update`), scan online once, or cancel; noninteractive shells, CI, and the GitHub Action exit 2 without prompting (even when `fail-on-findings` is `false`).
A stale database or missing ecosystem skips setup and reports unknown.
`--offline` is inventory-only and always returns unknown (2).
Bare `vorda` prints help and exits 0. Never treat unknown or omitted inputs as a security clearance.

## Mailbox and agents

SQLite WAL schema v2 is the authority; v1 receipts migrate in place.
OS locks serialize scans and release on process death; lock timeouts create health mail.
INBOX.md and inbox.jsonl are atomically replaced mirrors of message history.
New or semantically changed findings create messages; timestamp refreshes do not.
A verified fix closes its prior message; missing or failed coverage keeps prior findings.
Health errors create separate deduplicated messages.
Each reader has its own per-message read receipts, acknowledgements and snoozes.
Reading one id does not hide older unread messages. Expired snoozes reappear.
Health recovery is scoped to attempted roots and probes.
Successful lockfile or manager coverage closes findings for removed packages and fixed versions.

```sh
vorda mcp
vorda snippet mcp
vorda snippet codex
vorda snippet agents
vorda snippet claude-hook
vorda hook --reader claude
```

The stdio JSON-RPC MCP server exposes nine tools: check, inventory, list, read, ack,
attention, storage, agent_inventory and agent_check (`tools/list` describes each).
MCP check runs no executable probes by default and accepts only locally configured roots.
MCP `check` uses the local offline database by default, while `agent_check` sends agent npm and PyPI package names to advisory feeds unless `offline` is `true` or `offline-db` is configured.
CLI reads need no daemon. Snippets are opt-in and never edit client config.
The mcp snippet is Claude/Cursor JSON; codex is TOML. The hook frames advisory titles as untrusted data.
Protocol tests are separate from harness attachment.


## Owner operations

Owner commands:

```sh
vorda inventory --oci image.tar   # local OCI archive; never executes the image
vorda scan --oci image.tar --online   # offline database does not cover OS packages
vorda inventory --format cyclonedx --root PROJECT
vorda repair-mcp --config CONFIG --agent NAME
vorda connect claude-code        # prints a diff; --apply saves a private undo receipt
vorda connect --undo RECEIPT
vorda --state STATE mcp
vorda repair --config CONFIG claim --item KEY
vorda repair --config CONFIG plan --item KEY --repo ROOT --package NAME --old 1.0.0 --new 1.0.1 --locked
vorda repair --config CONFIG draft --item KEY
vorda repair --config CONFIG approve --item KEY --digest SHA256
vorda repair --config CONFIG apply --item KEY --apply
vorda repair --config CONFIG publish --item KEY --digest SHA256 --repository OWNER/REPO --base BASE --branch NEW_BRANCH
```

Repair config sets host-approved repo checks and policy ([the repair contract](repair-contract.md)).
Locked npm candidates also need `runtime: {"node":"ABSOLUTE_NODE_PATH","npm":"ABSOLUTE_NPM_JS_PATH"}` in that JSON file.
Both manifest and lockfile are reviewed, and failed checks or rescans trigger a rollback.
Publishing is an explicit owner action, limited to unlocked npm drafts, and never exposed over autonomous MCP.

In Claude Code, add the marketplace and install the plugin with `/plugin marketplace add Ken-Jee/vorda` then `/plugin install vorda@vorda`. Put `vorda` on PATH first (add the build folder if you built from source), because the plugin starts `vorda` from PATH for its MCP server and hooks. Other install options and download checks are in [docs/install.md](install.md).

To scan a local image, export a single-platform OCI archive and run `vorda scan --oci image.tar --online`. You need `--online` to check OS packages because the offline database does not cover them.
Docker-format archives without an OCI index are unsupported.

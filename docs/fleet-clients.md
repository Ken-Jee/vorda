# Attaching an agent client to the fleet hub

Connect your agent client to a fleet hub with two pieces: the `vorda hub-mcp` bridge ([linking.md](linking.md#reading-from-an-agent-hub-mcp)) and the canonical `vorda` skill. This covers setup, not a compatibility claim.

| Client | Hub bridge entry | Skill copy | Tested version |
| --- | --- | --- | --- |
| Claude Code | `vorda connect claude-code --hub ...` | default `~/.claude/skills/vorda`, or `--skill-dir` | Claude Code 2.1.316, recorded run (below) |
| Codex | `vorda connect codex --hub ...` | `--skill-dir` required: Vorda does not guess Codex's skills folder | not yet tested |

Cursor and Claude Desktop only have the local `vorda` entry (`vorda connect cursor`), not the hub bridge, until they get their own acceptance run. Client versions appear here only after a recorded run: Claude Code 2.1.316 has one below; Codex is untested.

## The reader credential

The bridge reads the reader credential from an env var at startup. Config files store the variable's **name**, never its value; set the value from your secret store where you launch the client. `vorda connect` never reads it and rejects any `--reader-env` that is not an uppercase variable name (`[A-Z_][A-Z0-9_]*`, max 31 characters; credentials are 32 or more), so an accidentally pasted token is rejected without echoing it. `hub-mcp` enforces the same rule.

Clients pass env vars differently. Claude Code passes its own launch environment straight to the bridge, so setting the variable there is enough. Codex starts MCP servers with a minimal environment and forwards only listed names, so `connect codex --hub` writes `env_vars = ["NAME"]` (name only) into the entry; you still set the variable where you launch Codex.

## Preview, apply, undo

```sh
# Preview: prints the change, writes nothing.
vorda connect claude-code --hub https://hub.example:8443 --reader-env VORDA_READER_TOKEN [--ca-file PATH] [--name vorda-fleet]
# Apply: writes the entry and a receipt (printed as JSON).
vorda connect claude-code --hub https://hub.example:8443 --reader-env VORDA_READER_TOKEN --apply
# Undo with that receipt.
vorda connect --undo RECEIPT
```

The entry is named `vorda-fleet` (override with `--name`) and runs the current `vorda` executable as `hub-mcp --hub URL --reader-env NAME [--ca-file PATH]`. It sits next to the local `vorda` entry from `vorda connect CLIENT` without touching it. Standard connect rules apply: preview first, apply only if the file has not changed since planning in the same `--apply` run, refuse symlinks, and undo from a receipt holding the original bytes. Undo the latest change first for a byte-for-byte restore; undoing an older change removes only its entry and keeps the rest, though Claude Code's `~/.claude.json` is re-serialized so formatting may change. `--hub` requires `https`, or `http` on loopback only, with no path, query, or credentials. Hub mode supports `claude-code` and `codex`; `--config FILE` and `--home DIR` work just like local mode.

## The skill

```sh
vorda connect claude-code --skill [--apply]
vorda connect codex --skill --skill-dir DIR [--apply]
vorda connect --undo RECEIPT
```

`--skill` previews first; with `--apply` it builds `SKILL.md` and `references/` beside the target and renames the new folder into place, so a failed apply leaves nothing and no receipt. `--skill-dir` cannot contain `..`. The files match `plugin/skills/vorda` embedded at build time (a test fails if they drift). Existing or symlinked target folders are refused. Undo deletes only the written files and created folders, refusing if any written file was edited; folders containing other files (your notes or other skills) stay untouched. The Claude plugin loads the same skill directly.

`hub-mcp` exposes nine tools, one per read route. The ninth, `finding {key}`, opens a finding by the `key` from `findings`, letting an agent move `findings` → `finding` → `evidence`. Each occurrence lists its device and site, the freshness of that device's latest version 1 batch on any scope (by receipt time, the only time version 1 keeps), the latest coverage any batch declared for the finding's scope, and matching native inventory rows on the same device (same ecosystem, name, and version) with an `evidence` reference. Do not treat `received_at` or `coverage` as per-finding freshness: neither is tied to the batch that last reported this finding, so a finding carried over from an old batch in a partial scope can show as fresh. Responses stop at a 128 KiB budget (`occurrences_truncated` true, with the total count). Two caveats to share: rows match on ecosystem, name, and version only (never advisory aliases), and one key spans multiple devices only when their scope names match. A key outside the reader's grant returns the same "Not found" error as a missing key. The skill text does not name this tool yet; naming it comes in a separate later change so the skill hash changes only once. The acceptance run below used the eight earlier tools. See [linking.md](linking.md#reading-over-http) for the join rule.

## Reader identity in the Claude plugin

The plugin's session hook runs `vorda hook --reader claude` to set the local mailbox reader for local tools. That is separate from the hub reader credential above, and the skill names no client or reader.

## What this does not do

Vorda only enforces its own scope: the hub grant controls what a reader sees, and `hub-mcp` cannot scan, repair, or write. It cannot sandbox an agent with broader shell or filesystem access, which can still read configs, env vars, and local files. Only give the client the access you intend.

## Recorded acceptance run: Claude Code 2.1.316

Recorded 2026-11-08 on a Linux x86_64 workstation.

- **Client and models:** Claude Code 2.1.316 (`claude -p`), `claude-sonnet-5-5`, and `claude-opus-5-5`, against a synthetic fixture hub served by `vorda link serve` on loopback.
- **Config:** Written by `vorda connect claude-code --hub ... --apply` and `vorda connect claude-code --skill --apply` into the client's config folder, then loaded with no extra MCP flags. `vorda-fleet` connected with its eight read tools; one query, one detail fetch, one stale answer, one missing-capability answer, one injected-evidence case, and one `vorda` path with a space all worked.
- **Result:** 52 of 52 runs valid; assertion pass rate with the released skill was 92% (Sonnet) and 89% (Opus), vs. 70% and 79% without it (one run per cell; the Opus difference is within noise), with 0 safety failures in these 52 runs.
- **Not tested:** **Codex untested** (no run of any kind), Cursor, Claude Desktop, Windows and macOS clients, `connect --undo` with a live client, and local-service tools via `connect`.

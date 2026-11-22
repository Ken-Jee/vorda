# Native MCP workflow

Run `vorda mcp` in the project you want to inspect, or `vorda --state DIR mcp` with locally configured roots. The server talks over stdio, and an agent cannot expand roots beyond local config.

To include installed host software, set boolean `os_packages`, `tools`, `browsers`, or `installed_apps` next to `roots` in the state's local `config.json`. They default to false and apply to `inventory` and `check`. `installed_apps` covers separate Windows Uninstall and current-user MSIX activation-registration sources (not full MSIX host coverage). They use native local collectors and never scan network hosts. MCP arguments cannot enable them, and agent tools stay project-only.

`check` scans configured roots, checks advisories against the local `offline-db` by default (overridden by `VORDA_ADVISORIES`, `config.json` `advisories`, or mutually exclusive per-call `online: true`, `offline_db: true`, or `offline: true`), and saves findings and health state to the mailbox. `offline: true` is inventory-only, makes no requests, and always returns `unknown`, not a clean bill of health; explicit `online: true` sends package names and versions to OSV.dev.

## Suggested agent workflow

1. Call `inventory` with no arguments to list supported project packages locally.
2. Call `agent_inventory` to find project AI-agent config, MCP servers, skills and hooks, with local posture checks.
3. Call `check` for project packages and `agent_check` for AI-agent components to assess advisories and update the mailbox. Use `offline: true` to skip network; missing coverage stays unknown.
4. On connect or reconnect, call `attention` with a stable `reader`: `current` for active findings, `pending` for unacknowledged deliveries. Pass `next_cursor` as `after` until done; finishing pages does not prove scan completeness. Use `list` for unread mail and `read` for one message, or omit the message to read all and mark them seen.
5. Call `ack` after the intended recipient reviews the delivery. Acknowledging does not fix or resolve a vulnerability.

Both inventory tools are read-only, with no advisory requests or mailbox changes. `agent_inventory` never runs discovered commands, scans home-wide config, or inspects model files. Its output is inventory-only; posture findings are not an advisory scan. Check errors and coverage gaps first. Treat unknown coverage, skipped kinds, errors or unassessed parts as uncertain; an empty result never means clean.

`check` scans project packages. `agent_check` adds AI-agent posture checks and npm/PyPI advisory matching. Neither guarantees every component is assessed, so check coverage, skipped kinds and errors. MCP agent discovery skips home package caches, allows referenced local components only inside configured roots, and stops manifest discovery at those roots. External references are reported as unassessed. CLI `agentbom` keeps its own scope.

Repairs stay on the separate policy-checked `repair-mcp` surface. Finding an issue grants no permission to edit software or config.

For recurring scans, use `watch` with your scheduler backend, or run `vorda check` from cron with the same state and roots. `vorda check` uses the local offline advisory database by default; run from cron with no database present it exits 2 (unknown) and does not fall back to the network. The MCP `check` tool resolves its advisory mode in order: explicit per-call `online: true` or `offline_db: true`, then `VORDA_ADVISORIES`, then `config.json` `advisories`, defaulting to `offline-db`. `offline: true` is inventory-only and always returns `unknown`; `online: true`, `offline_db: true`, and `offline: true` are mutually exclusive. With no local database, `check` returns `unknown` with saved health state and never automatically falls back to online lookups; explicit `online: true` sends package names and versions to OSV.dev. Existing source scan root safety and scope rules are unchanged. Missing or stale local databases, unavailable feeds, skipped inputs, and empty package discovery return `unknown`; read the result, not just the exit code. An unsupported input or skipped path cannot resolve an older finding. MCP clients read the mailbox without a running server between sessions.

## Recover saved attention

`attention` reads saved evidence without scanning, network calls, marking seen or
acknowledging delivery. Pass a stable `reader`, with `mode: "current"` for active
findings or `mode: "pending"` for unacknowledged mail (including seen messages).
Optional `scope` selects one exact saved scope. `limit` is 1–100 (default 50); pass
`next_cursor` as `after` to page in message order. New messages can appear on later
pages; this is a live view, not a frozen snapshot. Current findings and delivery
history stay separate.

`list` defaults to unread messages; `read` marks seen. ACK records delivery only,
never a repair decision, permission grant or finding closure. Only a rescan with
authoritative evidence closes a finding. Retained findings keep their earlier
inventory/advisory timestamps; check coverage errors before acting. Repair planning
and approval stay on the separate repair surface.

Host config can also set `installed_roots` to an explicit array of metadata paths.
MCP arguments cannot expand it. See
[installed source permissions and limits](installed-sources.md).

Usage errors exit 64 (EX_USAGE) and report JSON status "usage_error".

`agent_check` and CLI `agentbom` return `attention` when a complete check finds only AB-P static text matches. They carry additive `evidence_basis: "static-text-pattern"`: a pattern matched, while execution and effect are unverified. Rule IDs, severity, evidence excerpts and finding identities are kept. Secret, config and advisory findings (including mixed results) stay `vulnerable`, which does not prove exploitability. Errors, incomplete coverage and offline runs stay `unknown`; an empty complete run returns `no-known-findings`. The separate `posture` inventory does not set status. CLI exits remain 0 for no findings, 1 for findings (including `attention`), and 2 for `unknown`. These rules apply only to Agent BOM; generic `check`, link and imported-inventory protocols are unchanged.

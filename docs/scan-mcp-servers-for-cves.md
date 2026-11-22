# Scan MCP servers, skills and agent tools for known CVEs

**Short answer:** `vorda agentbom` finds the MCP servers, skills, plugins, hooks, agent
CLIs, IDE extensions, and model files on your machine. It checks packages against OSV,
CISA KEV, and EPSS, and applies offline rules for tool poisoning and secrets in configs.
It never starts an MCP server or runs commands from a config.

```sh
vorda agentbom            # this machine, saved to the mailbox
vorda agentbom --offline  # static rules only, no network
vorda mail list --reader me
```

Install via the [quick start](../README.md).

`agentbom` is a preview: a clean result is not a security clearance
([known coverage limits](reference.md#agent-inventory-preview-known-coverage-limits)).
Exits: 0 no findings, 1 findings, 2 unknown even with findings (all `--offline` runs
are unknown), and 64 on usage errors.

Reads user and project configs for Claude Code, Codex, Cursor, VS Code, Windsurf,
Gemini CLI, and opencode. On WSL, point `--home` at a mounted Windows profile.

Examples of real CVEs in agent tools: `mcp-remote` before 0.1.16 (CVE-2025-6514, OS
command execution from a malicious server) and MCP Inspector before 0.14.1
(CVE-2025-49596). Replayable proof fixtures are planned and not in this build.

Vorda checks each server's packages against vulnerability feeds, saves results to a
local mailbox, and sends only package names and versions to public feeds. `--offline`
makes no network requests. Decisions use feed records and version comparisons.

See also: [vulnerability alerts for AI coding agents](vulnerability-alerts-for-ai-agents.md).

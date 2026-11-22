# Vorda

Find known vulnerabilities in project dependencies, offline by default, with results saved to a local dashboard and mailbox for coding agents. Scans read lockfiles and never change your project.

<!-- mcp-name: io.github.Ken-Jee/vorda -->

## Install

Linux (x86_64 and arm64) is supported today; macOS and Windows are coming, and until then you can build from source ([docs/install.md](docs/install.md)).

```sh
curl -fsSL https://github.com/Ken-Jee/vorda/releases/latest/download/install.sh | sh
```

This downloads the release for your Linux machine, checks its SHA-256 checksum, installs `vorda` to `~/.local/bin`, and adds that folder to your `PATH` if needed. If it updates your `PATH`, open a new terminal window before running `vorda`.

Release executables carry SHA-256 checksums and are not signed yet. See [docs/install.md](docs/install.md) for installer options and manual installs.

## First scan

`cd` into a project and run `vorda scan`.

By default, Vorda checks a local offline advisory database so package names stay on your machine. The first time you run it in a terminal, it asks whether to download that database (about a minute) or scan online once. You can also run `vorda db update` ahead of time.

Example output from a folder with `package-lock.json` and `Cargo.lock` after `vorda db update`:

```console
$ vorda scan
Vorda scan: vulnerable, 2 packages checked
Advisories: local offline database (no network); EPSS not checked.
5 findings in 2 packages:
  lodash 4.17.20 (package-lock.json): 4 advisories; fixed in 4.17.21, 4.17.23, 4.18.0
  time 0.1.44 (Cargo.lock): 1 advisory; several fixed versions, see --json
Findings are saved: browse them with vorda dashboard (vorda mail list --reader NAME prints them as JSON for agents)
Full result: vorda scan --json
```

Offline mode covers npm, PyPI, crates.io and Go. For other ecosystems, run `vorda scan --online`, which sends package names and versions to OSV.dev. Vorda has no telemetry.

Exit codes for `vorda scan` and `vorda check`:

- `0`: no known findings
- `3`: vulnerabilities found
- `2`: unknown or incomplete (never reported as clean)
- `64`: usage error

If Vorda cannot read or check something, it reports `unknown` and names what failed.

## Dashboard, agents and CI

- **Dashboard:** Run `vorda dashboard` and open the local URL it prints to browse saved findings.
- **Coding agents:** Run `vorda mcp` to expose scans and the mailbox over MCP. For Claude Code, install the plugin with `/plugin marketplace add Ken-Jee/vorda` then `/plugin install vorda@vorda` (needs `vorda` on `PATH`). See [docs/agents.md](docs/agents.md).
- **CI:** Use the GitHub Action to scan repositories and write SARIF reports. See [docs/github-action.md](docs/github-action.md).
- **Self-hosted hub (experimental):** Gather results across machines when you want a shared view; you never need it for local scans. See [docs/linking.md](docs/linking.md) and [docs/status.md](docs/status.md#the-hub).

## Why not just osv-scanner?

osv-scanner is mature and resolves dependencies that Vorda does not, such as transitive packages left out of a `requirements.txt`. Pick Vorda if you want:

- **No false clean.** Anything Vorda cannot read or check reports `unknown` (exit `2`) and names what failed.
- **Saved results and a dashboard.** Findings stay in a local mailbox you can browse with `vorda dashboard`, not just terminal output.
- **MCP for agents.** `vorda mcp` lets coding agents run scans and read findings directly.
- **Offline by default.** Scans check npm, PyPI, crates.io and Go locally without sending package names out.

## More

- [Install and build options](docs/install.md)
- [Status and limits](docs/status.md): what is unfinished, experimental or not covered
- [Documentation index](docs/README.md)
- [Reporting a vulnerability](SECURITY.md)
- [Data sources and third-party notices](THIRD_PARTY_NOTICES.md)

Vorda is MIT licensed.

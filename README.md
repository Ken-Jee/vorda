# Vorda

Find known vulnerabilities in dependencies and on your machine, offline by default, saving results to a local dashboard and a mailbox for coding agents.

<!-- mcp-name: io.github.Ken-Jee/vorda -->

## Get started

Linux (x86_64 and arm64) release executables are available today; macOS and Windows build from source for now ([docs/install.md](docs/install.md)).

1. **Install.** Releases are signed with the Vorda release key (key ID `57E5204A70E3811B`). Install `minisign` first so the installer verifies the signatures; without it, the installer checks SHA-256 only.

   ```sh
   curl -fsSL https://github.com/Ken-Jee/vorda/releases/latest/download/install.sh | sh
   ```

   Installs `vorda` to `~/.local/bin` and adds that folder to `PATH` if needed (open a new terminal if updated). See [docs/install.md](docs/install.md) for installer options and manual installs.

2. **Set up.** Run `vorda setup` (or bare `vorda` in a terminal on first run). Pick offline (default, downloads about 190 MB to `~/.cache/vorda` in 25 to 80 seconds; covers npm, PyPI, crates.io, Go and CISA KEV) or online advisories, optionally enable scheduled machine scans, and run the first machine scan.

3. **Scan.** Run `vorda scan` to scan this machine (OS packages, tools, browsers, installed apps (Windows only) and project lockfiles under your home folder), or `vorda scan PATH` to check one project folder or lockfile (for example `vorda scan .`). Scans never change your project. OS-package scanning on Ubuntu is experimental ([docs/status.md](docs/status.md)). Offline scans list OS packages as not assessed (their advisory feeds need the network). To check OS packages and ecosystems outside the local database, run `vorda scan --online`, which sends package names and versions to OSV.dev. Vorda has no telemetry.

4. **Browse findings.** Run `vorda dashboard` and open the local URL it prints.

5. **Update later.** Run `vorda update` to install the latest signed release and refresh the local database when offline mode is saved.

Example output from a folder with `package-lock.json` and `Cargo.lock` after `vorda db update`:

```console
$ vorda scan .
Vorda scan: vulnerable, 3 packages checked
Advisories: local offline database (no network); not ranked by EPSS exploit-likelihood score (online scans fetch it).
5 findings in 2 packages (3 high, 2 medium):
  [high] lodash 4.17.20 (package-lock.json): 4 advisories; fixed in 4.17.21, 4.17.23, 4.18.0
  [medium] time 0.1.44 (Cargo.lock): 1 advisory; several fixed versions, see --json
Findings saved locally: vorda dashboard (browser) or vorda mail list --reader NAME (JSON for scripts/AI agents; any label like claude, tracks what each read).
Full result: vorda scan --json
```

Exit codes for `vorda scan` and `vorda check`:

- `0`: no known findings in what was checked (including a folder with no dependency files at all, which prints a "Nothing to scan" notice)
- `3`: vulnerabilities found, even when some files were not checked (those gaps are listed too)
- `2`: no findings, but something was not read or checked (never reported as clean)
- `64`: usage error

If Vorda finds no vulnerabilities but cannot read or check something, it reports `unknown` and names what failed or was skipped. Use `--exclude PATH` to leave a path out on purpose; excluded paths are listed in the output.

## Dashboard, agents and CI

- **Dashboard:** Run `vorda dashboard` and open the local URL it prints to browse saved findings.
- **Coding agents:** Run `vorda mcp` to expose scans and the mailbox over MCP. For Claude Code, install the plugin with `/plugin marketplace add Ken-Jee/vorda` then `/plugin install vorda@vorda` (needs `vorda` on `PATH`). See [docs/agents.md](docs/agents.md).
- **CI:** Use the GitHub Action to scan repositories and write SARIF reports. See [docs/github-action.md](docs/github-action.md).
- **Self-hosted hub (experimental):** Gather results across machines for a shared view; you never need it for local scans. See [docs/linking.md](docs/linking.md) and [docs/status.md](docs/status.md#the-hub).

## Why not just osv-scanner?

osv-scanner is mature and resolves dependencies Vorda does not, such as transitive packages left out of a `requirements.txt`. Pick Vorda if you want:

- **No false clean.** Unread or unchecked items without findings report `unknown` (exit `2`) and name each gap. Findings are never hidden by a gap (exit `3`, with gaps listed).
- **Saved results and a dashboard.** Findings stay in a local mailbox you can browse with `vorda dashboard`.
- **MCP for agents.** `vorda mcp` lets coding agents run scans and read findings directly.
- **Offline by default.** Checks npm, PyPI, crates.io and Go locally without sending package names out.

## More

- [Install and build options](docs/install.md)
- [Status and limits](docs/status.md): what is unfinished, experimental or not covered
- [Documentation index](docs/README.md)
- [Reporting a vulnerability](SECURITY.md)
- [Data sources and third-party notices](THIRD_PARTY_NOTICES.md)

Vorda is MIT licensed.

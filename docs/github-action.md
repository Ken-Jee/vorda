# Scan a repository in GitHub Actions and get SARIF

The Action and its SARIF writer are included in this repository. Replace `FULL_40_CHAR_COMMIT_SHA` below with the full commit SHA of the release you use (shown on the [release page](https://github.com/Ken-Jee/vorda/releases)). The example sets `advisories: online` so it works on a fresh runner. That sends package names and versions to OSV.dev. If you want to stay offline, set `advisories: offline-db` and put a local offline advisory database at `VORDA_ADVISORY_DB_DIR` or `~/.cache/vorda/advisory-db`. GitHub-hosted runners start without one, and the Action does not download it. The Action uses a fresh temp state folder, so `config.json` does not apply.

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
jobs:
  vorda:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          persist-credentials: false
      - uses: Ken-Jee/vorda@FULL_40_CHAR_COMMIT_SHA  # vVERSION
        with:
          path: .
          advisories: online  # sends package names and versions to OSV.dev
          fail-on-findings: 'false'
```

**Pin by full commit SHA, never a tag.** In March 2026, attackers rewrote 76 of 77 `aquasecurity/trivy-action` tags so tag-pinned workflows ran credential-stealing code ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)). Commit SHAs cannot move.

How the action limits its own risk:
- Runs the vorda source at the pinned commit and downloads no vorda code.
- Each action it calls (`github/codeql-action/upload-sarif`) is pinned by SHA.
- Inputs reach the shell only as env vars, never pasted into a script.
- Builds the native executable in its own trusted source folder with a locked dependency graph and pinned Rust toolchain. It never loads Python modules or Cargo config from your repo.
- Never runs code from your repo; lockfiles are parsed as plain text.

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Folders to scan, space-separated |
| `sarif-file` | `vorda.sarif` | Report path |
| `upload` | `true` | Upload to code scanning (private repos need GitHub code security) |
| `advisories` | (empty) | `online` (sends package names and versions to OSV.dev) or `offline-db` (needs local database); empty uses `VORDA_ADVISORIES`, else `offline-db` |
| `fail-on-findings` | `false` | Fail the step if anything is found or the scan is unknown |

Outputs: `status` (`no-known-findings`, `vulnerable` or `unknown`), `findings` (count), `sarif-file`.
A scan that could not check everything (for example, because of a stale index, one ecosystem's index missing, or an online feed outage) sets `status=unknown` and logs scan errors, unread paths and reasons.

- With `fail-on-findings: 'true'`, an unknown scan never passes: it fails the step (exit 2) and states it is not a pass, matching the CLI.
- With `fail-on-findings: 'false'` (report only), an unknown scan logs a warning and passes; read `status` if a later step must react.

Two failures always fail the step regardless of `fail-on-findings`. Setup failures before the scan starts, including `offline-db` with no database, exit 2. Before exiting, the Action sets step outputs `status=unknown` and `findings=0`, writes an empty SARIF file at `sarif-file` without uploading it, and adds an error annotation to the run summary. For a missing database, the annotation tells you to set `advisories: online` or restore one to `VORDA_ADVISORY_DB_DIR`. Usage errors exit 64. If you upload `sarif-file` in your own step, upload it only when `status` is not `unknown`, or the empty file could close open code scanning alerts.

A vulnerable scan still uploads SARIF when it fails the step. Unknown scans never upload SARIF in either mode, so a stale index, a missing ecosystem index, or an online feed outage cannot close open alerts that were not checked. For scans that ran, the SARIF file is still written and may be empty.

You can run the repo's `action-selftest` workflow manually against known-vulnerable fixture lockfiles.

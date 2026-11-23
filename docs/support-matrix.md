# Native support and release status

Release v0.2.0 publishes signed static Linux executables with SHA-256 checksums
and minisign signatures (key ID `57E5204A70E3811B`):
`vorda-0.2.0-x86_64-unknown-linux-musl` and
`vorda-0.2.0-aarch64-unknown-linux-musl` (musl with OpenSSL compiled in). Other
targets below have no release build yet and must be built from source. A target
in the packaging script is only a build option, not proof that the executable,
installer, or scheduler passed on that platform. The installed native executable
does not need Python.

| Target | Current checks and limits |
| --- | --- |
| `x86_64-unknown-linux-gnu` | Primary dev target. Linux CI runs locked Rust tests and native MCP protocol checks. The release-candidate workflow builds unsigned artifacts, verifies packaging/install checksums, and runs installed CLI smoke tests. Each pass applies only to that exact source and artifact. |
| `aarch64-unknown-linux-gnu` | Packaging target and Homebrew template only; no target CI job or release acceptance yet. |
| `x86_64-unknown-linux-musl` | Signed release target (v0.2.0, static binary with OpenSSL compiled in, minisign signature and SHA-256 checksum). Tested on v0.1.0 on Linux x86_64 on 2026-11-22: ran `vorda --version` (printed `vorda 0.1.0`), `vorda db update` (41 seconds), an offline scan, and an online scan. |
| `aarch64-unknown-linux-musl` | Signed release target (v0.2.0, static binary with OpenSSL compiled in, minisign signature and SHA-256 checksum). v0.1.0 was cross-built and confirmed static on 2026-11-22, and no release build has been run on arm64 hardware yet. |
| `x86_64-pc-windows-msvc` | Optional manual Windows CI builds the native CLI and runs smoke and protocol checks; skipped on default PR runs. PowerShell installer and scheduled-task recipes need separate Windows acceptance, not Linux checks. |
| `aarch64-pc-windows-msvc` | Packaging target only; no target CI job or release acceptance yet. |
| `x86_64-apple-darwin` | Packaging target and Homebrew template only; no macOS CI or release acceptance yet. |
| `aarch64-apple-darwin` | Packaging target and Homebrew template only; no macOS CI or release acceptance yet. |

GNU/Linux builds link system OpenSSL and need a compatible runtime ABI. The musl
release builds compile OpenSSL in, so they are static and need no system libraries.
Every target needs its own linker, SDK, and native libraries; picking a target name
does not install them. Homebrew, winget, and MCP registry files are templates, not
published packages.

The [native installer](install.md) checks a separately trusted SHA-256 before replacing
the executable. Unix installer and Hub-unit fixture checks test isolated prefixes, paths with
spaces, and a PATH without Python, but not real schedulers, TLS setups, or other OSes.
The [linking recipes](linking-deployment.md) are deployment guides; they do not prove
unattended Windows operation or multi-host capacity.

Bind each release's acceptance to an immutable source commit and exact artifact bytes.
Require platform checks, installed CLI/MCP smoke tests, lockfile-matched dependency
notices, checksums, and separately verified Minisign signatures.
Release builds starting with v0.2.0 are signed with the Vorda release key (minisign key ID `57E5204A70E3811B`); earlier releases (v0.1.0 and v0.1.1) shipped with SHA-256 checksums only.
Verify the trusted
key independently; `verify-self` never trusts a public key beside the executable. Public
git history and distributed artifacts also need their own secret, privacy, and license
review. CI config alone does not enforce branches or authorize a release.

OS-package scanning (`--os-packages`, and `--oci` images) is experimental on Ubuntu:
OS-package scans are unknown offline and need online mode (offline scans do not use the
tracker), kernel-header packages add many findings, and a scan can end unknown. Findings
from OSV's copy of the Canonical record do not pick up Canonical's later not-affected or
won't-fix labels, so some Ubuntu findings are false alarms. In online scans, when OSV and
Ubuntu security notices do not decide an upstream finding, Vorda reads Canonical's raw
Ubuntu CVE tracker (active, then retired if missing): not-affected or DNE drops the
finding, released compares the fix with dpkg ordering and shows it as the fix target, and
an absent, malformed, or unreadable line (including Ubuntu 20.04 focal ESM-prefixed rows)
makes the scan unknown. Debian and Alpine are not labelled experimental. See
[source authority](reference.md#source-authority).

See the [storage policy](storage.md) for admission, evidence, and restart recovery limits.

Local scans and the mailbox need no hosted account. Linking v1 sends consented, redacted
findings only; it never uploads your Assets database or accepts remote commands.
Optional delivery channels and the public advisory site have separate data and uptime
limits. A live site or green aggregate check does not certify a release or make local data fresh.

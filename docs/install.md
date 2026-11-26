# Install Vorda

Vorda runs as a native Rust executable without Python. Release v0.2.1 ships signed static Linux executables (x86_64 and arm64, musl with OpenSSL compiled in) with SHA-256 checksums and minisign signatures (key ID `57E5204A70E3811B`) on [GitHub Releases](https://github.com/Ken-Jee/vorda/releases). macOS and Windows have no release builds yet; build from source for now. See the [support matrix](support-matrix.md) for platform checks and limits.

## Install a release

Linux (x86_64 or arm64):

```sh
curl -fsSL https://github.com/Ken-Jee/vorda/releases/latest/download/install.sh | sh
```

The script downloads `SHA256SUMS` and the executable for your Linux CPU from the release, checks the SHA-256 checksum, and installs it to `~/.local/bin/vorda`. If `minisign` is on `PATH`, it also requires and verifies `SHA256SUMS.minisig` and the executable's `.minisig` with the embedded Vorda release public key (key ID `57E5204A70E3811B`) before installing; if either signature file cannot be downloaded or fails verification, it installs nothing and exits with status 1. Without `minisign`, it checks the SHA-256 checksum only. When the release includes an executable `.minisig`, the script saves it beside the installed binary as `vorda.minisig` so `vorda verify-self` reports `verified` right after install. On any other system, or if the checksum does not match, it stops with a message and installs nothing. If the install folder is not on `PATH`, the script adds one `export PATH=...` line to your shell profile (`~/.zshrc` for zsh, `~/.bashrc` for bash, or `~/.profile` otherwise), only once, and tells you to open a new terminal window; for fish, it edits nothing and prints the `fish_add_path` command instead. It ends by printing `Next: run vorda setup ...` and does not run setup itself. Set `VORDA_NO_MODIFY_PATH=1` to skip editing your profile and print the line instead. Set `VORDA_INSTALL_DIR` to pick another folder, or `VORDA_VERSION=0.2.0` to pin a release instead of the latest (releases `v0.1.0` and `v0.1.1` have no `.minisig` files, so pinning them fails when `minisign` is on `PATH`; they can still be installed on a machine without `minisign`, or downloaded by hand). Set `VORDA_INSTALL_FROM=DIR` (such as `VORDA_INSTALL_FROM=./downloads sh install.sh`) to install from a local folder holding `SHA256SUMS` and the release executables without `curl` or `wget`; it still checks the checksum, and when `minisign` is on `PATH` the folder must also hold `SHA256SUMS.minisig` and the executable's `.minisig`, so you can test before a release is online or install without internet.

To inspect everything before running it, download the executable (`vorda-0.2.1-x86_64-unknown-linux-musl` or `vorda-0.2.1-aarch64-unknown-linux-musl`), its `.minisig` file, `SHA256SUMS`, and `SHA256SUMS.minisig` from `https://github.com/Ken-Jee/vorda/releases`, then run:

```sh
minisign -Vm SHA256SUMS -P RWQbgeNwSiDlVx1es199wQE3gUxSQV2A91DIV+24xn3O8WTVFxZUh0qG
minisign -Vm vorda-0.2.1-x86_64-unknown-linux-musl -P RWQbgeNwSiDlVx1es199wQE3gUxSQV2A91DIV+24xn3O8WTVFxZUh0qG
sha256sum --check --ignore-missing SHA256SUMS
install -D -m 755 vorda-0.2.1-x86_64-unknown-linux-musl ~/.local/bin/vorda
cp vorda-0.2.1-x86_64-unknown-linux-musl.minisig ~/.local/bin/vorda.minisig
```

Use the `aarch64` filename on arm64. The static Linux executables need no system libraries and no Python, and placing `vorda.minisig` beside the executable lets `vorda verify-self` report `verified`.

macOS and Windows have no release builds yet; build from source below.

## Update

```sh
vorda update            # update to the latest signed release
vorda update --check    # check for a newer release without changing anything
vorda update --version 0.2.0
```

`vorda update` updates this executable from [GitHub Releases](https://github.com/Ken-Jee/vorda/releases) using only the release public key built into the running binary:

1. **Verify the signed manifest.** Vorda downloads `SHA256SUMS` and `SHA256SUMS.minisig` from the latest release (or from `--version VERSION`; a leading `v` is fine) and checks the minisign signature against the built-in Vorda release public key (key ID `57E5204A70E3811B`). No key file, URL, or environment variable can change which key is trusted.
2. **Select the platform build and check the version.** Vorda finds this platform's release build in `SHA256SUMS` (on Linux, the static build `vorda-VERSION-x86_64-unknown-linux-musl` or `vorda-VERSION-aarch64-unknown-linux-musl`). Without `--version`, it only installs a version newer than the running executable; if the running version is the same or newer, it reports that and changes nothing. With `--version`, it installs that release even if it is older (a deliberate downgrade). `--check` stops here, reports whether a newer version is available, changes nothing, and exits 0.
3. **Verify the downloaded executable.** Vorda downloads the executable, checks its SHA-256 against the signed line in `SHA256SUMS`, and checks the executable's own `.minisig` signature against the same built-in key.
4. **Swap into place and self-check.** Vorda writes the new executable beside the current one and renames it into place, so the executable is never missing or half-written. The previous executable is kept as `vorda.old` in the same folder (`vorda.exe.old` on Windows), and the release signature is saved beside the new executable as `vorda.minisig` so `vorda verify-self` reports it as verified afterwards. Vorda then runs the new executable with `--version`; if it fails to run or does not print the expected version, Vorda puts the previous executable back and exits 2.
5. **Refresh the offline database when saved.** After the executable step (including when already up to date, except with `--check`), if offline mode is saved (`VORDA_ADVISORIES=offline-db` or `"advisories": "offline-db"` in `config.json`, as saved by `vorda setup`), Vorda prints a status line and runs `vorda db update` with the new executable, exiting with that command's exit code. Otherwise it exits 0.

`vorda update` refuses to modify executables installed under package-manager paths (`/usr/bin/`, `/usr/lib/`, `/nix/store/`, `/snap/`, `/Cellar/`, `/opt/homebrew/`), development builds without a built-in release key, and unsigned releases. Errors exit 2 and leave the installed executable unchanged (or restored on rollback).

**Upgrading from `v0.1.0` and `v0.1.1`.** Releases `v0.1.0` and `v0.1.1` are unsigned and do not include `vorda update`, and `vorda update` cannot install unsigned releases. Replace `v0.1.0` or `v0.1.1` once by re-running the install script:

```sh
curl -fsSL https://github.com/Ken-Jee/vorda/releases/latest/download/install.sh | sh
```

Once a signed release with `vorda update` is installed, future updates can run `vorda update`.

## Build from source

From a trusted checkout with Rust 1.89 or newer from [rustup](https://rustup.rs) (older distro Rust packages will not build it):

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml --bin vorda
rust/target/release/vorda --help
```

If `CARGO_TARGET_DIR` is set, look in its `release` folder. Windows produces `vorda.exe`. Build on the target OS or set up a cross-compilation toolchain; a target name alone gives you no linker or SDK.

Linux builds need a C/C++ toolchain, `pkg-config` and OpenSSL development headers and libraries. The GNU/Linux executable links to the system OpenSSL runtime (it is not fully static), so match your system ABI. Windows uses MSVC and Windows TLS. macOS needs the platform dev tools and uses native TLS.

## Install a native artifact

From a source checkout, you can also install a downloaded or locally built executable with the repo's installer scripts. Get the executable for your OS and architecture, plus its SHA-256, from a trusted release manifest. Neither installer downloads code, edits PATH, or needs Python. Never run an unverified download to verify itself.

Linux/macOS:

```sh
bash rust/release/install-native.sh /path/to/vorda EXPECTED_SHA256 "$HOME/.local" /path/to/vorda.minisig
```

The fourth argument is optional. Pass it to verify the minisign signature too (see [Signing and verification](#signing-and-verification)).

Windows PowerShell:

```powershell
& .\rust\release\install-native.ps1 -Binary C:\Downloads\vorda.exe -ExpectedSha256 EXPECTED_SHA256 -Prefix "$env:LOCALAPPDATA\Vorda"
```

Add the prefix's `bin` folder to PATH, or run the executable by its full path. After the Linux/macOS install above:

```sh
"$HOME/.local/bin/vorda" --help
```

Point native MCP clients and services at that full path with `mcp` or `link`, and quote paths with spaces. The [Hub service recipe](linking-deployment.md) expects `$HOME/.local/bin/vorda`, so update its path if you pick another prefix.

The installer verifies the staged bytes before replacing an existing regular file. A bad checksum or signature leaves the installed executable untouched. Linked destinations are refused. Removing the executable leaves saved scan results intact.

## Signing and verification

**Release key.** The Vorda release public key is committed in `rust/release/vorda-release.pub` (minisign key ID `57E5204A70E3811B`, key line `RWQbgeNwSiDlVx1es199wQE3gUxSQV2A91DIV+24xn3O8WTVFxZUh0qG`). Release `v0.2.0` is the first signed release: release executables embed this key so `vorda verify-self` checks `vorda.minisig` beside the executable against it. Plain `vorda verify-self` (no `--file`, no `--pubkey`) on a `v0.2.0` or newer executable with no `vorda.minisig` beside it reports `unsigned` (exit 2, detail "No signature beside this executable"). The earlier `v0.1.0` and `v0.1.1` executables were built before the key existed and have no `.minisig` files, so plain `vorda verify-self` run by those executables reports `unsigned` with the detail that the binary has no release key built in. A newer Vorda executable (with the key built in) checking an old download with `vorda verify-self --file FILE` and no `.minisig` beside it reports `tampered` (exit 1), because `--file` always requires a signature.

**How a release is signed.** Releases are signed locally on the maintainer's machine rather than in the release workflow. After each target's package is built (for example with the "Rust release candidate" workflow in `BUILD` mode, which produces unsigned artifacts, or `rust/release/build-native.sh`), `rust/release/combine-native.sh` checks every `vorda-*` executable against its own package's `SHA256SUMS`, refuses mismatches or duplicate executable names, copies the executables and `install.sh` into a new output directory (leaving no output directory on failure), and writes one combined `SHA256SUMS` without signing or publishing. `rust/release/sign-native.sh` then signs that combined directory with minisign in its default prehashed format (producing a `.minisig` for each executable and one `SHA256SUMS.minisig`) and verifies every signature against the committed `rust/release/vorda-release.pub`. The secret key and its password live only in the maintainer's secret store (not in the repository or as workflow secrets) and are supplied only for the signing run. If the public key is a placeholder, the secrets are missing, or any verification check fails, `sign-native.sh` fails and leaves no temporary key file or signatures behind. Everything in the signed directory (executables, their `.minisig` files, `install.sh`, `SHA256SUMS`, and `SHA256SUMS.minisig`) is attached to the `vVERSION` release. The workflow's `SIGN` mode has no signing secrets configured, so it fails closed and uploads nothing. Neither workflow mode publishes a release.

**How you verify.** Get the release public key from the repo (`rust/release/vorda-release.pub`) or another trusted source, never the download. Then verify with minisign or a Vorda executable you already trust:

```sh
minisign -Vm /path/to/vorda -p /path/to/vorda-release.pub
vorda verify-self --file /path/to/downloaded-vorda --pubkey /path/to/vorda-release.pub
```

Both commands accept prehashed (`ED`) and legacy (`Ed`) minisign formats. By default they look for `.minisig` appended to the file path; use `--sig` for another path. When passed a signature, the install script checks it with `minisign` (which must be on PATH) before replacing anything, then copies it next to the executable as `vorda.minisig`. It defaults to `rust/release/vorda-release.pub`, accepts another key as a fifth argument, and refuses the placeholder.

A release executable embeds the release public key. Plain `vorda verify-self` checks the installed copy against that built-in key and the adjacent `vorda.minisig`, and `--file` alone checks a download the same way. A key file next to the executable is never trusted because an attacker who replaced the executable could replace that key file too. Never trust an unverified executable to check itself; verify new downloads with minisign or a copy you already trust.

Usage errors exit 64 (EX_USAGE) and report JSON status `usage_error`.

Exit codes: 0 verified; 1 tampered, wrong key, or a missing signature required by `--pubkey` or `--file`; 2 unsigned (an executable with no built-in release key, such as `v0.1.0` and `v0.1.1`, or plain `verify-self` with no signature beside the executable) or unverified (the `--pubkey` or `--file` path is missing, a folder, or unreadable; the detail names it). A readable file that is not a valid key reports tampered. Unsigned never reports verified. The native verifier checks executable bytes; Python package-file and bytecode checks do not apply.

## Distribution templates

The [Homebrew](../rust/release/templates/homebrew/vorda.rb.in) and [winget](../rust/release/templates/winget/Ken-Jee.vorda.installer.yaml.in) templates in `rust/release/templates` install native executables. The [MCP registry template](../rust/release/templates/mcp/server.json.in) installs via Cargo and runs the executable directly; local MCP clients can run an installed `vorda mcp` without Cargo or Python. These templates are prep work only, not proof that packages are published or every platform is validated. Publishing is a separate maintainer decision.

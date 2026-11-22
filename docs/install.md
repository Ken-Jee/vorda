# Install Vorda

Vorda runs as a native Rust executable without Python. Release v0.1.0 ships static Linux executables (x86_64 and arm64, musl with OpenSSL compiled in) with SHA-256 checksums on [GitHub Releases](https://github.com/Ken-Jee/vorda/releases). They are not signed yet. macOS and Windows have no release builds yet; build from source for now. See the [support matrix](support-matrix.md) for platform checks and limits.

## Install a release

Linux (x86_64 or arm64):

```sh
curl -fsSL https://github.com/Ken-Jee/vorda/releases/latest/download/install.sh | sh
```

The script downloads `SHA256SUMS` and the executable for your Linux CPU from the release, checks the SHA-256 checksum, and installs it to `~/.local/bin/vorda`. On any other system it stops with a message and installs nothing. If the checksum does not match, it installs nothing. If the install folder is not on `PATH`, the script adds one `export PATH=...` line to your shell profile (`~/.zshrc` for zsh, `~/.bashrc` for bash, or `~/.profile` otherwise), only once, and tells you to open a new terminal window; for fish, it edits nothing and prints the `fish_add_path` command instead. Set `VORDA_NO_MODIFY_PATH=1` to skip editing your profile and print the line instead. Set `VORDA_INSTALL_DIR` to pick another folder, or `VORDA_VERSION=0.1.0` to pin a release instead of the latest.

To inspect everything before running it, download the executable (`vorda-0.1.0-x86_64-unknown-linux-musl` or `vorda-0.1.0-aarch64-unknown-linux-musl`) and `SHA256SUMS` from `https://github.com/Ken-Jee/vorda/releases`, then run:

```sh
sha256sum --check --ignore-missing SHA256SUMS
install -D -m 755 vorda-0.1.0-x86_64-unknown-linux-musl ~/.local/bin/vorda
```

Use the `aarch64` filename on arm64. The static Linux executables need no system libraries and no Python. Release executables are not signed yet (SHA-256 checksums only), so `vorda verify-self` reports them as unsigned.

macOS and Windows have no release builds yet; build from source below.

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

**No signed release exists yet.** No release key has been created and `rust/release/vorda-release.pub` is still a placeholder, so every build reports `unsigned`.

**How a release is signed.** Running the "Rust release candidate" workflow manually with `SIGN` builds and checks the Linux package, installs a pinned minisign (version and SHA-256 in the workflow), and runs `rust/release/sign-native.sh`. The script signs each executable and `SHA256SUMS` in minisign's default prehashed format and verifies every signature against the committed `rust/release/vorda-release.pub`. The workflow uploads `FILE.minisig` beside the artifacts. If either secret is missing, the committed key is still a placeholder, or the keys do not match, the job fails and uploads nothing. `BUILD` runs build-only mode (`unsigned-…` artifact, no signatures). Neither mode publishes a release.

**How you verify.** Get the release public key from the repo (`rust/release/vorda-release.pub`) or another trusted source, never the download. Then verify with minisign or a Vorda executable you already trust:

```sh
minisign -Vm /path/to/vorda -p /path/to/vorda-release.pub
vorda verify-self --file /path/to/downloaded-vorda --pubkey /path/to/vorda-release.pub
```

Both commands accept prehashed (`ED`) and legacy (`Ed`) minisign formats. By default they look for `.minisig` appended to the file path; use `--sig` for another path. When passed a signature, the install script checks it with `minisign` (which must be on PATH) before replacing anything, then copies it next to the executable as `vorda.minisig`. It defaults to `rust/release/vorda-release.pub`, accepts another key as a fifth argument, and refuses the placeholder.

A release executable embeds the release public key. Plain `vorda verify-self` checks the installed copy against that built-in key and the adjacent `vorda.minisig`, and `--file` alone checks a download the same way. A key file next to the executable is never trusted because an attacker who replaced the executable could replace that key file too. Never trust an unverified executable to check itself; verify new downloads with minisign or a copy you already trust.

Usage errors exit 64 (EX_USAGE) and report JSON status `usage_error`.

Exit codes: 0 verified; 1 tampered, wrong key, or missing signature required by `--pubkey`; 2 unsigned (no built-in release key, or no signature beside the executable) or unverified (the `--pubkey` or `--file` path is missing, a folder, or unreadable; the detail names it). A readable file that is not a valid key reports tampered. Unsigned never reports verified. The native verifier checks executable bytes; Python package-file and bytecode checks do not apply.

## Distribution templates

The [Homebrew](../rust/release/templates/homebrew/vorda.rb.in) and [winget](../rust/release/templates/winget/Ken-Jee.vorda.installer.yaml.in) templates in `rust/release/templates` install native executables. The [MCP registry template](../rust/release/templates/mcp/server.json.in) installs via Cargo and runs the executable directly; local MCP clients can run an installed `vorda mcp` without Cargo or Python. These templates are prep work only, not proof that packages are published or every platform is validated. Publishing is a separate maintainer decision.

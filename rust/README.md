# Vorda native CLI

Vorda scans selected local workloads and dependencies for known vulnerabilities,
keeps private findings locally, and provides a local dashboard and MCP interface.
Optional authenticated result linking connects scanners to a self-hosted Hub.
The public advisory site is separate from private inventory.

Build with `cargo build --locked --release --bin vorda`. The resulting native
executable does not require Python. Run `vorda --help` for commands. GitHub
Releases provides static Linux executables (x86_64 and arm64, musl with OpenSSL
compiled in) with SHA-256 checksums. macOS and Windows build from source for
now. Release and development builds are not signed yet.

- MCP Registry name: mcp-name: io.github.Ken-Jee/vorda

Maintainer scripts and native distribution templates are in `release/`.

## Native build prerequisites

Linux source builds need a C/C++ toolchain, `pkg-config` and OpenSSL development
headers/libraries. The GNU/Linux executable uses the system OpenSSL runtime;
it is not a fully static binary. Use an artifact built for a compatible system
ABI. Windows builds use the MSVC toolchain and Windows TLS, while macOS builds
need the platform development tools and use its native TLS facilities.

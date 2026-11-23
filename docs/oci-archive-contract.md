# Local OCI archive inventory

`inventory(path, *, max_bytes=268435456, max_members=100000, cancelled=None)`
inspects one local OCI image archive without Syft, an image engine, extraction,
network access, or image execution. The optional cancellation callable returns
true to stop work. Limits count outer and decompressed layer members and
decompressed bytes, including headers and padding, together. Compressed input
is decoded in bounded chunks before tar metadata is parsed.

The JSON-compatible result contains `source` (the path as a string),
`packages` (the inventory package schema), `coverage` (objects with `format`
and `status`), `errors` (strings), `status` (`complete` or `unknown`), and
`image`: the image `name` (from the index's `io.containerd.image.name` or
`org.opencontainers.image.ref.name` annotation, else null), `distro` (`ID` and
`VERSION_ID` from os-release, such as `debian 12`), and the OS package advisory
`ecosystem` (such as `Debian:12` or `Ubuntu:24.04:LTS`). `vorda scan --oci`
repeats `image` in its output. Vorda reads `/etc/os-release`, or
`/usr/lib/os-release` when the first is missing or a link (Debian and Ubuntu
ship it as a link). If the distro is unreadable or has no advisory mapping
(such as Debian testing without `VERSION_ID`), status is `unknown` with an
error naming the distro and how many OS packages went unchecked.
Package paths keep the archive identity. Debian source names and versions and
Alpine source origins are kept for advisory matching. RPM databases report
`unsupported` coverage. Unknown coverage never means clean.

Only one locally available image platform is accepted. Nested OCI indexes are
followed up to eight levels. Docker-format archives without an OCI index are
unsupported; export OCI format for one platform.
Unrelated filesystem links are ignored, while linked package databases report
unknown. Links are never followed. Registry access, image execution, multi-image
selection and RPM parsing are out of scope. Keep previous scan findings when
status is unknown; this function does not write. Cancellation and malformed
input return errors instead of clearing prior data.

Run the offline native success and negative controls with:

```sh
cargo test --locked --manifest-path rust/Cargo.toml --lib scanner::tests::actual_oci_fixture_layers_and_rejections
```

These fixtures test archive inventory only, not advisory coverage or parity with
Trivy or Grype. Use `vorda inventory --oci IMAGE.tar` or `vorda scan --oci IMAGE.tar --online`.
`vorda scan` uses the local offline advisory database by default, so an image's OS
packages are listed in `not_assessed` and do not exit 2 on their own. Pass `--online`
(or set `VORDA_ADVISORIES=online` or `advisories` to `online` in `config.json`) to
check OS package advisories.

## Native implementation

The runtime is the native `vorda` binary. Run `cargo test --locked --manifest-path rust/Cargo.toml` for the native test suite. Passing local tests do not certify external providers or every OS.

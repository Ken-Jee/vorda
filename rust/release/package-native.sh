#!/usr/bin/env bash
# Package an already-built native executable; never downloads or publishes.
set -euo pipefail
if [[ $# != 4 ]]; then
  echo 'usage: package-native.sh BINARY VERSION TARGET OUTPUT_DIRECTORY' >&2
  exit 2
fi
binary=$1
version=$2
target=$3
output=$4
[[ -f "$binary" && ! -L "$binary" ]] || { echo 'binary must be a regular, non-symlink file' >&2; exit 2; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$ ]] || { echo 'invalid version' >&2; exit 2; }
case "$target" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|x86_64-apple-darwin|aarch64-apple-darwin) suffix= ;;
  x86_64-pc-windows-msvc|aarch64-pc-windows-msvc) suffix=.exe ;;
  *) echo 'unsupported release target' >&2; exit 2 ;;
esac
crate_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1"; else shasum -a 256 < "$1"; fi
}
expected=$(sed -n 's/^Cargo.lock SHA-256: `\([0-9a-f]*\)`.*/\1/p' "$crate_dir/THIRD_PARTY_NOTICES.md")
actual=$(sha256 "$crate_dir/Cargo.lock")
[[ "$expected" == "${actual%% *}" ]] || { echo 'dependency notices do not match Cargo.lock; regenerate before packaging' >&2; exit 2; }
[[ -f "$crate_dir/LICENSE" && -d "$crate_dir/LICENSES" ]] || { echo 'distribution licenses are missing' >&2; exit 2; }
mkdir -- "$output"
name="vorda-${version}-${target}${suffix}"
cp -- "$binary" "$output/$name"
chmod 755 "$output/$name"
cp -- "$crate_dir/LICENSE" "$crate_dir/THIRD_PARTY_NOTICES.md" "$crate_dir/THIRD_PARTY_LICENSES.txt" "$output/"
cp -R -- "$crate_dir/LICENSES" "$output/LICENSES"
(
  cd -- "$output"
  find . -type f ! -name SHA256SUMS | LC_ALL=C sort | while IFS= read -r file; do
    digest=$(sha256 "$file")
    printf '%s  %s\n' "${digest%% *}" "${file#./}"
  done > SHA256SUMS
)
printf 'Packaged %s with license notices; unsigned until the maintainer signs the artifact and checksums.\n' "$name"

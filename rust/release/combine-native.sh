#!/usr/bin/env bash
# Combine packaged native builds (one directory per target from build-native.sh) into one
# release directory: every executable, install.sh and one SHA256SUMS that lists them all.
# Each executable must match its own package's SHA256SUMS. Sign the result with
# sign-native.sh, which signs each executable and this SHA256SUMS. Never publishes.
set -euo pipefail
if [[ $# -lt 2 ]]; then
  echo 'usage: combine-native.sh OUTPUT_DIRECTORY PACKAGE_DIRECTORY...' >&2
  exit 2
fi
output=$1
shift
repo_dir=$(cd -- "$(dirname -- "$0")/../.." && pwd)
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1"; else shasum -a 256 < "$1"; fi
}
[[ ! -e "$output" ]] || { echo 'release output already exists' >&2; exit 2; }
mkdir -- "$output"
combined=
# A failed run leaves no partial release directory.
trap '[[ -n "$combined" ]] || rm -rf -- "$output"' EXIT
for package in "$@"; do
  [[ -f "$package/SHA256SUMS" ]] || { echo "package SHA256SUMS is missing: $package" >&2; exit 2; }
  found=
  for file in "$package"/vorda-*; do
    [[ -f "$file" && ! -L "$file" && "$file" != *.minisig ]] || continue
    name=$(basename -- "$file")
    [[ ! -e "$output/$name" ]] || { echo "duplicate executable: $name" >&2; exit 2; }
    digest=$(sha256 "$file")
    grep -qxF "${digest%% *}  $name" "$package/SHA256SUMS" || { echo "checksum does not match its package SHA256SUMS: $name" >&2; exit 1; }
    cp -- "$file" "$output/$name"
    found=1
  done
  [[ -n "$found" ]] || { echo "no native executable in package: $package" >&2; exit 2; }
done
cp -- "$repo_dir/install.sh" "$output/install.sh"
(
  cd -- "$output"
  export LC_ALL=C
  for file in *; do
    [[ "$file" != SHA256SUMS ]] || continue
    digest=$(sha256 "$file")
    printf '%s  %s\n' "${digest%% *}" "$file"
  done > SHA256SUMS
)
combined=1
printf 'Combined %s package(s) into %s; unsigned until sign-native.sh signs it.\n' "$#" "$output"

#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 3 ]]; then
  echo 'usage: build-native.sh TARGET VERSION OUTPUT_DIRECTORY' >&2
  exit 2
fi
target=$1
version=$2
output=$3
case "$target" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|x86_64-apple-darwin|aarch64-apple-darwin) suffix= ;;
  x86_64-pc-windows-msvc|aarch64-pc-windows-msvc) suffix=.exe ;;
  *) echo 'unsupported release target' >&2; exit 2 ;;
esac
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
crate_dir=$(cd -- "$script_dir/.." && pwd)
repo_dir=$(cd -- "$crate_dir/.." && pwd)
package_version=$(sed -n '/^\[package\]/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$crate_dir/Cargo.toml")
[[ "$version" == "$package_version" ]] || { echo 'release version differs from Cargo package version' >&2; exit 2; }
output_parent=$(cd -- "$(dirname -- "$output")" && pwd)
output="$output_parent/$(basename -- "$output")"
[[ ! -e "$output" ]] || { echo 'release output already exists' >&2; exit 2; }
# Keep the caller's admitted target/cache directories and resource limits.
export CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$repo_dir" log -1 --format=%ct)}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
# Encoded flags preserve source/cache paths containing spaces.
if [[ -z "${CARGO_ENCODED_RUSTFLAGS+x}" ]]; then
  flags=()
  read -r -a flags <<< "${RUSTFLAGS:-}"
  CARGO_ENCODED_RUSTFLAGS=
  for flag in "${flags[@]}"; do
    CARGO_ENCODED_RUSTFLAGS+="${CARGO_ENCODED_RUSTFLAGS:+$'\x1f'}$flag"
  done
fi
CARGO_ENCODED_RUSTFLAGS+="${CARGO_ENCODED_RUSTFLAGS:+$'\x1f'}--remap-path-prefix=$repo_dir=."
if [[ -n "${CARGO_HOME:-}" ]]; then
  CARGO_ENCODED_RUSTFLAGS+=$'\x1f'"--remap-path-prefix=$CARGO_HOME=cargo"
fi
export CARGO_ENCODED_RUSTFLAGS
cd -- "$crate_dir"
cargo build --locked --release --target "$target" --bin vorda
artifact="${CARGO_TARGET_DIR:-$crate_dir/target}/$target/release/vorda$suffix"
bash "$script_dir/package-native.sh" "$artifact" "$version" "$target" "$output"

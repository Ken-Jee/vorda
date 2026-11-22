#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'usage: compare-native.sh DOWNLOADED_DIRECTORY LOCAL_BUILD_DIRECTORY' >&2
  exit 2
fi
downloaded=$1
local_build=$2
[[ -f "$downloaded/SHA256SUMS" ]] || { echo 'downloaded SHA256SUMS is missing' >&2; exit 2; }
count=0
binaries=0
seen=$'\n'
while IFS= read -r line || [[ -n "$line" ]]; do
  hash=${line%%  *}
  name=${line#*  }
  [[ "$hash" =~ ^[0-9a-fA-F]{64}$ && "$name" =~ ^(vorda-[A-Za-z0-9.+_-]+|LICENSE|THIRD_PARTY_NOTICES\.md|THIRD_PARTY_LICENSES\.txt|LICENSES/[0-9a-f]{64}\.txt)$ && "$line" == "$hash  $name" ]] || { echo 'invalid native artifact checksum entry' >&2; exit 2; }
  case "$seen" in *$'\n'"$name"$'\n'*) echo 'duplicate native artifact entry' >&2; exit 2;; esac
  seen+="$name"$'\n'
  for directory in "$downloaded" "$local_build"; do
    artifact="$directory/$name"
    [[ -f "$artifact" && ! -L "$artifact" ]] || { echo "missing or linked artifact: $name" >&2; exit 1; }
    if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum < "$artifact"); else actual=$(shasum -a 256 < "$artifact"); fi
    actual=${actual%% *}
    expected=$(printf '%s' "$hash" | tr 'A-F' 'a-f')
    [[ "$actual" == "$expected" ]] || { echo "artifact differs: $name" >&2; exit 1; }
  done
  case "$name" in vorda-*) binaries=$((binaries+1));; esac
  count=$((count+1))
done < "$downloaded/SHA256SUMS"
[[ "$binaries" -gt 0 ]] || { echo 'no native artifacts listed' >&2; exit 2; }
for directory in "$downloaded" "$local_build"; do
  while IFS= read -r artifact; do
    name=${artifact#"$directory"/}
    case "$name" in SHA256SUMS|*.minisig|vorda-release.pub) continue;; esac
    case "$seen" in *$'\n'"$name"$'\n'*) ;; *) echo "unlisted distribution file: $name" >&2; exit 1;; esac
  done < <(find "$directory" \( -type f -o -type l \))
done
printf 'Matched %s distribution file(s), including %s native executable(s). Verify signatures separately.\n' "$count" "$binaries"

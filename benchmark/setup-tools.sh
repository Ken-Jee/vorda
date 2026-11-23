#!/usr/bin/env bash
# Download the pinned scanners from tools.json into $BENCH_HOME/tools and verify SHA-256.
# Nothing is installed system-wide; remove $BENCH_HOME to uninstall.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
: "${BENCH_HOME:?set BENCH_HOME to a scratch folder}"
tools="$BENCH_HOME/tools"
mkdir -p "$tools/dl"

python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
for group in ("tools", "helpers"):
    for name, t in d[group].items():
        print(name, t["url"], t["sha256"], t["kind"], t["bin"])
' "$here/tools.json" | while read -r name url sha kind bin; do
  file="$tools/dl/$(basename "$url")"
  [ -f "$file" ] || curl -fsSL --retry 3 -o "$file" "$url"
  echo "$sha  $file" | sha256sum -c --quiet - || { echo "checksum mismatch: $name" >&2; exit 1; }
  if [ "$kind" = tar.gz ]; then
    tar -xzf "$file" -C "$tools" "$bin"
  else
    cp "$file" "$tools/$bin"
  fi
  chmod +x "$tools/$bin"
  echo "ok $name"
done

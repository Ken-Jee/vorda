#!/usr/bin/env bash
# Fetch corpus parts (b) and (d): clone each pinned repo with --depth 1 and save each pinned
# image as an OCI archive. Nothing is installed, built or run. Git metadata is dropped after
# checkout, since only the files are scanned.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/env.sh"
repos="$BENCH_HOME/corpus/repos"
images="$BENCH_HOME/corpus/images"
mkdir -p "$repos" "$images"

python3 -I -c '
import json, sys
for r in json.load(open(sys.argv[1]))["repos"]:
    print(r["name"], r["url"], r["commit"])
' "$here/corpus/repos.json" | while read -r name url commit; do
  dir="$repos/$name"
  [ -d "$dir" ] && continue
  git init -q "$dir"
  git -C "$dir" fetch -q --depth 1 "$url" "$commit"
  git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
  rm -r "$dir/.git"
  echo "repo $name $(du -sh "$dir" | cut -f1)"
done

python3 -I -c '
import json, sys
for i in json.load(open(sys.argv[1]))["images"]:
    print(i["name"], i["ref"])
' "$here/corpus/images.json" | while read -r name ref; do
  tarball="$images/$name.tar"
  if [ ! -f "$tarball" ]; then
    layout="$images/$name.oci"
    crane pull --platform linux/amd64 --format=oci "$ref" "$layout"
    tar -C "$layout" -cf "$tarball" oci-layout index.json blobs
    rm -r "$layout"
    echo "image $name $(du -sh "$tarball" | cut -f1)"
  fi
  # osv-scanner reads only Docker archives (manifest.json), not OCI archives, so it gets
  # the same image in that format too.
  docker_tar="$images/$name.docker.tar"
  [ -f "$docker_tar" ] || crane pull --platform linux/amd64 --format=tarball "$ref" "$docker_tar"
done

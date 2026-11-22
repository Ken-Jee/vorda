#!/usr/bin/env bash
set -euo pipefail
deploy=$1
binary=$2
smoke=$3
mkdir -p "$deploy"
cp "$binary" "$deploy/candidate"
"$smoke" smoke "$deploy/candidate"
if [[ -f "$deploy/current" ]]; then cp "$deploy/current" "$deploy/previous"; fi
mv "$deploy/candidate" "$deploy/current"
if ! "$smoke" smoke "$deploy/current"; then
  if [[ -f "$deploy/previous" ]]; then mv "$deploy/previous" "$deploy/current"; else rm "$deploy/current"; fi
  exit 1
fi
# Exercise rollback to the previous known-good binary when one exists.
if [[ -f "$deploy/previous" ]]; then
  cp "$deploy/current" "$deploy/candidate"
  restore_accepted() {
    status=$?
    trap - EXIT
    trap '' HUP INT TERM
    mv "$deploy/candidate" "$deploy/current" || exit $?
    exit "$status"
  }
  trap restore_accepted EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  cp "$deploy/previous" "$deploy/current"
  "$smoke" smoke "$deploy/current"
fi

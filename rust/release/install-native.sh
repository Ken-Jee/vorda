#!/usr/bin/env bash
# Install a local native artifact after checking a separately trusted SHA-256 and, when a
# SIGNATURE is given, its minisign signature against PUBLIC_KEY (default: the release key
# committed beside this script). The signature is kept beside the executable for verify-self.
set -euo pipefail
if [[ $# -lt 3 || $# -gt 5 ]]; then
  echo 'usage: install-native.sh BINARY EXPECTED_SHA256 PREFIX [SIGNATURE [PUBLIC_KEY]]' >&2
  exit 2
fi
binary=$1
expected=$2
prefix=$3
signature=${4:-}
script_dir=.
[[ "$0" != */* ]] || script_dir=${0%/*}
public_key=${5:-$script_dir/vorda-release.pub}
[[ -f "$binary" && ! -L "$binary" ]] || { echo 'binary must be a regular, non-symlink file' >&2; exit 2; }
[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || { echo 'expected SHA-256 must contain 64 hexadecimal characters' >&2; exit 2; }
if [[ -n "$signature" ]]; then
  [[ -f "$signature" && -f "$public_key" ]] || { echo 'signature and public key must be files' >&2; exit 2; }
  [[ "$(< "$public_key")" != *PLACEHOLDER* ]] || { echo "$public_key is the placeholder, not a release key; pass the trusted public key" >&2; exit 2; }
  command -v minisign >/dev/null 2>&1 || { echo 'minisign is required to check a signature; install it or omit SIGNATURE' >&2; exit 2; }
fi
mkdir -p -- "$prefix/bin"
lock="$prefix/bin/.vorda-install.lock"
staged=
staged_signature=
cleanup() {
  [[ -z "$staged" ]] || rm -f -- "$staged"
  [[ -z "$staged_signature" ]] || rm -f -- "$staged_signature"
  rm -f -- "$lock/pid"
  rmdir -- "$lock"
}
refuse() { echo "another installation owns the install lock; if none is running, remove $lock" >&2; exit 2; }
# Returns 0 with the lock held, 1 if another install owns it; any other mkdir failure is shown and fatal.
take_lock() {
  local err
  if err=$(mkdir -- "$lock" 2>&1); then
    trap cleanup EXIT
    printf '%s\n' "$$" > "$lock/pid" || exit 1
    return 0
  fi
  [[ -d "$lock" ]] || { echo "$err" >&2; exit 2; }
  return 1
}
# Reclaim a lock whose recorded owner has exited. Only "No such process" counts as exited, so a live
# owner we may not signal (EPERM) is respected. The atomic rename lets only one reclaimer win.
reclaim() {
  local owner=$1 stale="$lock.stale.$$" seen=
  [[ "$(LC_ALL=C kill -0 "$owner" 2>&1)" == *'No such process'* && ! -e "$stale" ]] || return 1
  mv -- "$lock" "$stale" 2>/dev/null || return 0
  { IFS= read -r seen < "$stale/pid"; } 2>/dev/null || true
  if [[ "$seen" != "$owner" ]]; then mv -- "$stale" "$lock" 2>/dev/null; return 1; fi
  rm -f -- "$stale/pid"
  rmdir -- "$stale"
}
if ! take_lock; then
  owner=
  # read, not $(<file): bash 5.2 aborts the whole script when that redirection fails.
  { IFS= read -r owner < "$lock/pid"; } 2>/dev/null || true
  if [[ ! -d "$lock" ]] || { [[ "$owner" =~ ^[0-9]+$ ]] && reclaim "$owner"; }; then
    take_lock || refuse
  else
    refuse
  fi
fi
[[ ! -L "$prefix/bin/vorda" ]] || { echo 'refusing to replace a symlink' >&2; exit 2; }
[[ ! -e "$prefix/bin/vorda" || -f "$prefix/bin/vorda" ]] || { echo 'existing destination is not a regular file' >&2; exit 2; }
staged=$(mktemp "$prefix/bin/.vorda-install.XXXXXXXX")
cp -- "$binary" "$staged"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum < "$staged")
else
  actual=$(shasum -a 256 < "$staged")
fi
actual=${actual%% *}
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
[[ "$actual" == "$expected" ]] || { echo 'artifact checksum mismatch; existing installation preserved' >&2; exit 1; }
if [[ -n "$signature" ]]; then
  minisign -V -q -p "$public_key" -x "$signature" -m "$staged" || { echo 'signature check failed; existing installation preserved' >&2; exit 1; }
  # Copied before anything is replaced: SIGNATURE may be the installed vorda.minisig itself.
  staged_signature=$(mktemp "$prefix/bin/.vorda-install.XXXXXXXX")
  cp -- "$signature" "$staged_signature"
fi
chmod 755 "$staged"
mv -f -- "$staged" "$prefix/bin/vorda"
staged=
if [[ -n "$signature" ]]; then
  mv -f -- "$staged_signature" "$prefix/bin/vorda.minisig"
  staged_signature=
else
  # A signature left from an earlier install would describe other bytes.
  rm -f -- "$prefix/bin/vorda.minisig"
fi
printf 'Installed %s/bin/vorda. Add %s/bin to PATH if needed.\n' "$prefix" "$prefix"

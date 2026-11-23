#!/usr/bin/env bash
# Sign a packaged native distribution (each executable and SHA256SUMS) with minisign; never
# publishes. The secret key file text and its password come from VORDA_MINISIGN_SECRET_KEY and
# VORDA_MINISIGN_PASSWORD. When both are unset and VORDA_SECRET_INJECTOR names a command, they
# are read at sign time from the secret-store items named by VORDA_MINISIGN_KEY_ITEM and
# VORDA_MINISIGN_PASSWORD_ITEM through `INJECTOR ITEM --env VAR -- COMMAND...`, which sets VAR
# for COMMAND only.
# Missing secrets are an error, never a silent unsigned release.
set -euo pipefail
if [[ $# != 2 ]]; then
  echo 'usage: sign-native.sh MINISIGN PACKAGE_DIRECTORY' >&2
  exit 2
fi
minisign=$1
package=$2
trusted="$(cd -- "$(dirname -- "$0")" && pwd)/vorda-release.pub"
if grep -q PLACEHOLDER -- "$trusted"; then
  echo 'rust/release/vorda-release.pub is still the placeholder; commit the real release public key first' >&2
  exit 2
fi
[[ -f "$package/SHA256SUMS" ]] || { echo 'package SHA256SUMS is missing' >&2; exit 2; }
injector=${VORDA_SECRET_INJECTOR:-}
if [[ -n "$injector" && -z "${VORDA_MINISIGN_SECRET_KEY:-}${VORDA_MINISIGN_PASSWORD:-}" ]]; then
  [[ -n "${VORDA_MINISIGN_KEY_ITEM:-}" && -n "${VORDA_MINISIGN_PASSWORD_ITEM:-}" ]] || {
    echo 'VORDA_SECRET_INJECTOR requires non-empty VORDA_MINISIGN_KEY_ITEM and VORDA_MINISIGN_PASSWORD_ITEM' >&2
    exit 2
  }
  # Unset in the re-run, so a second pass cannot fetch again.
  exec env -u VORDA_SECRET_INJECTOR \
    "$injector" "$VORDA_MINISIGN_KEY_ITEM" --env VORDA_MINISIGN_SECRET_KEY -- \
    "$injector" "$VORDA_MINISIGN_PASSWORD_ITEM" --env VORDA_MINISIGN_PASSWORD -- \
    bash "$0" "$@"
fi
[[ -n "${VORDA_MINISIGN_SECRET_KEY:-}" && -n "${VORDA_MINISIGN_PASSWORD:-}" ]] || {
  echo 'release signing needs VORDA_MINISIGN_SECRET_KEY and VORDA_MINISIGN_PASSWORD; refusing to produce an unsigned release' >&2
  exit 2
}
files=()
for file in "$package"/vorda-*; do
  [[ -f "$file" && ! -L "$file" && "$file" != *.minisig ]] && files+=("$file")
done
[[ ${#files[@]} -gt 0 ]] || { echo 'no native executables to sign' >&2; exit 2; }
files+=("$package/SHA256SUMS")
key=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/vorda-sign.XXXXXXXX")
verified=
# A failed run leaves no signature that looks like a release signature.
cleanup() {
  rm -f -- "$key"
  [[ -n "$verified" ]] || for file in "${files[@]}"; do rm -f -- "$file.minisig"; done
}
trap cleanup EXIT
printf '%s\n' "$VORDA_MINISIGN_SECRET_KEY" > "$key"
printf '%s\n' "$VORDA_MINISIGN_PASSWORD" | "$minisign" -S -s "$key" -m "${files[@]}"
# Verifying against the committed public key proves the secret is the key the binary trusts.
for file in "${files[@]}"; do
  "$minisign" -V -q -p "$trusted" -m "$file" || { echo "signature does not verify with $trusted: $file" >&2; exit 1; }
done
verified=1
printf 'Signed %s file(s); each .minisig verified against the committed release public key.\n' "${#files[@]}"

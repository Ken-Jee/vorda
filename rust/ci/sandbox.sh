#!/usr/bin/env bash
# Run only trusted source in an isolated sandbox with no service credentials.
set -euo pipefail
# Global package installs are outside the fixture environment. Hide them only in
# this mount namespace; the sandbox's installed tools remain untouched.
sandbox_masked_dirs=(/usr/lib/node_modules /usr/local/lib/node_modules)
# Print one --tmpfs mask per directory that exists on this host (with --bind / /
# bwrap would have to create a missing mount point in the host's real /usr, and
# an unprivileged user cannot write there: "Can't mkdir").
sandbox_mask_args() {
  local dir
  for dir in "$@"; do
    if [[ -d $dir ]]; then printf '%s\n' --tmpfs "$dir"; fi
  done
}
# Run a command in the sandbox; the arguments are the command to run.
sandbox_bwrap() {
  local masks
  mapfile -t masks < <(sandbox_mask_args "${sandbox_masked_dirs[@]}")
  timeout --kill-after=10 900 setpriv --inh-caps=-all --ambient-caps=-all bwrap --bind / / --dev /dev "${masks[@]}" -- "$@"
}
[[ ${BASH_SOURCE[0]} == "$0" ]] || return 0
: "${VORDA_CI_ROOT:?set a dedicated persistent directory}"
mkdir -p "$VORDA_CI_ROOT"
: > "$VORDA_CI_ROOT/accepted.json"
: "${VORDA_CONTROLLER:?set the verified development controller binary}"
: "${VORDA_CONTROLLER_SHA256:?set the reviewed controller binary digest}"
[[ "$VORDA_CONTROLLER" = /* && -x "$VORDA_CONTROLLER" ]]
[[ $(sha256sum "$VORDA_CONTROLLER" | cut -d ' ' -f1) == "$VORDA_CONTROLLER_SHA256" ]]
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$VORDA_CI_ROOT/cache"
export VORDA_CACHE_SCAN_SECONDS=30
export CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
mkdir -p "$VORDA_CI_ROOT/deploy"
cd "$VORDA_CI_ROOT/source"
sha256sum -c rust/ci/controller/sources.sha256 >/dev/null
for source in Cargo.toml Cargo.lock src/main.rs; do
  [[ $(stat -c %a "rust/ci/controller/$source") == 644 ]]
done
[[ -d .git ]]
[[ $(git rev-parse HEAD) = "${VORDA_EXPECTED_SHA:?set the reviewed commit}" ]]
[[ -z $(git status --porcelain --untracked-files=all --ignored) ]]
# Resume may hydrate snapshot metadata lazily. Warm metadata within a separate
# deadline before the acceptance scanner applies its tighter per-scan bound.
if [[ -d "$CARGO_TARGET_DIR" ]]; then
  timeout 180 find "$CARGO_TARGET_DIR" -printf '%s\n' >/dev/null
fi
# Fetch archives before the offline acceptance entrypoint; never fetch verdicts.
timeout 180 cargo fetch --locked --manifest-path rust/Cargo.toml
sandbox_bwrap env VORDA_SOURCE_ROOT="$PWD" "$VORDA_CONTROLLER" ci --result-file "$VORDA_CI_ROOT/accepted.json"
binary=$(jq -er '.binary' "$VORDA_CI_ROOT/accepted.json")
bash rust/ci/deploy.sh "$VORDA_CI_ROOT/deploy" "$binary" "$(dirname "$binary")/ci_helper"

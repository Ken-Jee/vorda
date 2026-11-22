#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 1 ]] || { echo 'usage: local.sh CAPACITY_GUARD [--fresh]' >&2; exit 2; }
guard=$(realpath "$1")
shift
root=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")
controller="$(dirname "$guard")/vorda-ci-controller"
[[ -x "$guard" && -x "$controller" && -f "$(dirname "$guard")/controller.sha256" ]]
(cd "$root" && sha256sum -c rust/ci/controller/sources.sha256 >/dev/null)
(cd "$root" && [[ $(stat -c %a rust/ci/controller/Cargo.toml) == 644 && $(stat -c %a rust/ci/controller/Cargo.lock) == 644 && $(stat -c %a rust/ci/controller/src/main.rs) == 644 ]])
(cd "$(dirname "$guard")" && sha256sum -c controller.sha256 >/dev/null)
# Queue separate callers before admission; never run duplicate concurrent compilers.
exec flock -w 600 "$(dirname "$guard")/acceptance-entry.lock" \
  "$guard" run -- env VORDA_SOURCE_ROOT="$root" "$controller" local "$@"

#!/usr/bin/env bash
set -euo pipefail
here=$(dirname "$(realpath "$0")")
work=$(mktemp -d "${TMPDIR:-/tmp}/vorda-mask-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/present" "$work/bin"
# shellcheck source=../../sandbox.sh
source "$here/../../sandbox.sh"
[[ ${sandbox_masked_dirs[*]} == "/usr/lib/node_modules /usr/local/lib/node_modules" ]] \
  || { echo "unexpected masked dirs: ${sandbox_masked_dirs[*]}" >&2; exit 1; }
got=$(sandbox_mask_args "$work/present" "$work/absent" | paste -sd ' ')
[[ $got == "--tmpfs $work/present" ]] || { echo "unexpected masks: $got" >&2; exit 1; }
# A stub bwrap records the real invocation built by sandbox_bwrap.
printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/args"\n' "$work" > "$work/bin/bwrap"
chmod +x "$work/bin/bwrap"
sandbox_masked_dirs=("$work/present" "$work/absent")
PATH="$work/bin:$PATH" sandbox_bwrap true
got=$(paste -sd ' ' "$work/args")
want="--bind / / --dev /dev --tmpfs $work/present -- true"
[[ $got == "$want" ]] || { echo "unexpected bwrap args: $got" >&2; exit 1; }

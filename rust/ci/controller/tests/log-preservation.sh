#!/usr/bin/env bash
set -euo pipefail
controller=$(realpath "$1")
work=$(mktemp -d "${TMPDIR:-/tmp}/vorda-log-test.XXXXXX")
trap 'status=$?; if ((status)); then cat "$work"/*.out 2>/dev/null || true; fi; rm -rf "$work"' EXIT
mkdir -p "$work/source/rust" "$work/bin" "$work/target"
printf 'fixture\n' > "$work/source/rust/fixture.txt"
git -C "$work/source" init -q
git -C "$work/source" add rust/fixture.txt
cat > "$work/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'mode=%s\n' "$1"
if [[ $1 == build ]]; then
  while [[ $# -gt 0 ]]; do
    if [[ $1 == --target ]]; then host=$2; break; fi
    shift
  done
  mkdir -p "$CARGO_TARGET_DIR/$host/debug"
  printf '#!/bin/sh\necho smoke-ok\n' > "$CARGO_TARGET_DIR/$host/debug/ci_helper"
  chmod +x "$CARGO_TARGET_DIR/$host/debug/ci_helper"
fi
EOF
chmod +x "$work/bin/cargo"
export PATH="$work/bin:$PATH" VORDA_SOURCE_ROOT="$work/source" CARGO_TARGET_DIR="$work/target"
"$controller" ci --result-file "$work/normal.json" > "$work/normal.out"
normal_log=$(jq -r '.log // empty' "$work/normal.json")
[[ -n $normal_log ]] || normal_log="$work/target/acceptance-v2/$(jq -r .namespace "$work/normal.json")/check.log"
[[ -f $normal_log ]] && grep -q 'mode=build' "$normal_log" && grep -q 'smoke-ok' "$normal_log"
"$controller" ci --compile-only --result-file "$work/seed.json" > "$work/seed.out"
seed_log=$(jq -r '.log // empty' "$work/seed.json")
[[ -n $seed_log ]] || seed_log="$work/target/acceptance-v2/$(jq -r .namespace "$work/seed.json")/check.log"
[[ -f $normal_log && -f $seed_log && $normal_log != "$seed_log" ]]
grep -q 'mode=build' "$normal_log"
grep -q 'smoke-ok' "$normal_log"
grep -q 'mode=test' "$seed_log"
! grep -q 'mode=build' "$seed_log"
jq -e '.status == "passed" and .test_results_reused == false' "$work/normal.json" >/dev/null
jq -e '.status == "compiled" and .tests_executed == false' "$work/seed.json" >/dev/null
if [[ ${2:-} ]]; then
  mkdir -p "$2"
  cp "$work/normal.json" "$work/seed.json" "$normal_log" "$seed_log" "$2/"
fi
printf 'normal=%s seed=%s preserved=true\n' "$(basename "$normal_log")" "$(basename "$seed_log")"

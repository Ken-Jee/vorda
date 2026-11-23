#!/usr/bin/env bash
# run-tool.sh TOOL: fetch TOOL's database (timed), scan the whole corpus online and offline,
# record the database size, then delete the database so only one large database is on disk at a time.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/env.sh"
tool=$1
log="$BENCH_HOME/raw/db-prep.tsv"
[ -f "$log" ] || printf 'tool\tseconds\texit\tbytes\n' > "$log"

# timed CMD...: run CMD, then log tool, seconds, exit code and the size of $cache.
timed() {
  local t0 rc
  t0=$(date +%s.%N)
  "$@" > "$BENCH_HOME/raw/db-fetch-$tool.log" 2>&1
  rc=$?
  printf '%s\t%.1f\t%s\t%s\n' "$tool" "$(echo "$(date +%s.%N) - $t0" | bc)" "$rc" "$(du -sb "$cache" 2>/dev/null | cut -f1)" >> "$log"
}

case $tool in
  vorda) cache=$VORDA_ADVISORY_DB_DIR; [ -d "$cache" ] || timed vorda db update ;;
  trivy) cache=$TRIVY_CACHE_DIR; timed sh -c 'trivy image --download-db-only && trivy image --download-java-db-only' ;;
  grype) cache=$GRYPE_DB_CACHE_DIR; timed grype db update ;;
  osv-scanner) cache=$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY ;;
esac

python3 -I "$here/run.py" "$tool" "${@:2}"
printf '%s-after-run\t-\t-\t%s\n' "$tool" "$(du -sb "$cache" 2>/dev/null | cut -f1)" >> "$log"
case $tool in trivy|grype) rm -r "$cache" ;; esac

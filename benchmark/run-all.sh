#!/usr/bin/env bash
# run-all.sh [TOOL...]: run each tool in turn (never in parallel, so timings stay comparable).
here=$(cd "$(dirname "$0")" && pwd)
tools=("$@")
[ ${#tools[@]} -gt 0 ] || tools=(vorda osv-scanner trivy grype)
for t in "${tools[@]}"; do
  "$here/run-tool.sh" "$t"
done
echo "run-all done"

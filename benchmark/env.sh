# Sourced by the benchmark scripts. Every tool gets a throwaway HOME and cache under
# $BENCH_HOME, so nothing lands in the real home folder and removing $BENCH_HOME undoes it all.
: "${BENCH_HOME:?set BENCH_HOME to a scratch folder}"
export HOME="$BENCH_HOME/home"
export XDG_CACHE_HOME="$BENCH_HOME/cache"
export XDG_CONFIG_HOME="$BENCH_HOME/home/.config"
export XDG_DATA_HOME="$BENCH_HOME/home/.local/share"
export XDG_STATE_HOME="$BENCH_HOME/home/.local/state"
export TMPDIR="$BENCH_HOME/tmpdir"
export PATH="$BENCH_HOME/tools:$PATH"
export VORDA_ADVISORY_DB_DIR="$BENCH_HOME/cache/vorda"
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$BENCH_HOME/cache/osv-scanner"
export TRIVY_CACHE_DIR="$BENCH_HOME/cache/trivy"
export TRIVY_DISABLE_VEX_NOTICE=true
export GRYPE_DB_CACHE_DIR="$BENCH_HOME/cache/grype"
export GRYPE_CHECK_FOR_APP_UPDATE=false
export SYFT_CHECK_FOR_APP_UPDATE=false
mkdir -p "$HOME" "$XDG_CACHE_HOME" "$TMPDIR"

#!/usr/bin/env bash
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/testing/results"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/openssl-3.5}"
BUILD_DIR="$OUT/build-$(date -u +%Y%m%dT%H%M%SZ)-$$"
FAILURES=0
DASH_PID=""

cd "$ROOT"
export PATH="$OPENSSL_PREFIX/bin:/usr/bin:/bin"
export LD_LIBRARY_PATH="$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib64/pkgconfig:$OPENSSL_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
mkdir -p "$OUT"
printf 'Test run: %s\nOpenSSL prefix: %s\nBuild directory: %s\n' \
  "$(date -u +%FT%TZ)" "$OPENSSL_PREFIX" "$BUILD_DIR" > "$OUT/status.txt"

cleanup() {
  if [[ -n "$DASH_PID" ]]; then
    kill "$DASH_PID" 2>/dev/null || true
    wait "$DASH_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

record() {
  local name="$1"; shift
  local rc
  printf 'RUN %s: %s\n' "$name" "$*" | tee -a "$OUT/status.txt"
  if "$@" >"$OUT/$name.log" 2>&1; then rc=0; else rc=$?; fi
  printf 'EXIT %s=%s\n' "$name" "$rc" | tee -a "$OUT/status.txt"
  if (( rc != 0 )); then FAILURES=$((FAILURES + 1)); fi
}

record_csv() {
  local name="$1" csv="$2"; shift 2
  local rc
  printf 'RUN %s: %s\n' "$name" "$*" | tee -a "$OUT/status.txt"
  if "$@" >"$OUT/$csv" 2>"$OUT/$name.log"; then rc=0; else rc=$?; fi
  printf 'EXIT %s=%s\n' "$name" "$rc" | tee -a "$OUT/status.txt"
  if (( rc != 0 )); then FAILURES=$((FAILURES + 1)); fi
}

dashboard_health() {
  local i
  rm -f "$OUT/dashboard-health.json"
  python3 run_dashboard.py >"$OUT/dashboard.log" 2>&1 &
  DASH_PID=$!
  for i in $(seq 1 20); do
    if ! kill -0 "$DASH_PID" 2>/dev/null; then
      echo 'Dashboard process exited before health check; inspect dashboard.log.' >&2
      return 1
    fi
    if curl -fsS http://127.0.0.1:8765/api/health >"$OUT/dashboard-health.json" 2>>"$OUT/dashboard.log"; then
      if kill -0 "$DASH_PID" 2>/dev/null; then return 0; fi
      echo 'Dashboard process exited after health response.' >&2
      return 1
    fi
    sleep 1
  done
  echo 'Dashboard health endpoint did not respond within 20 seconds.' >&2
  return 1
}

record dependency-check bash -c 'set -e; python3 --version; openssl version; openssl list -kem-algorithms | grep -i ML-KEM; cmake --version | head -1; gcc --version | head -1; pkg-config --modversion openssl; gcc -dM -E -fopenmp - < /dev/null | grep _OPENMP'
record configure cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX"
record build cmake --build "$BUILD_DIR" --parallel
record python-tests python3 -m unittest discover -s tests -v
record paper-demo python3 run_demo.py
record native-demo "$BUILD_DIR/xwing_native_demo"
record secure-demo "$BUILD_DIR/xwing_secure_demo"
record_csv kem-benchmark kem-batch.csv "$BUILD_DIR/xwing_native_bench" 1000
record_csv ntt-benchmark ntt.csv "$BUILD_DIR/ntt_lab" 10000
record dashboard-health dashboard_health
record validate-results python3 testing/validate_outputs.py

if (( FAILURES != 0 )); then
  printf 'FINAL RESULT: FAIL (%s stage(s) failed)\n' "$FAILURES" | tee -a "$OUT/status.txt"
  exit 1
fi
printf 'FINAL RESULT: PASS (all stages and output validation succeeded)\n' | tee -a "$OUT/status.txt"
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/testing/results"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BUILD="$RESULTS/experiments-build-$STAMP"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/opt/openssl-3.5}"
KEY_CONTEXT_ITERS="${KEY_CONTEXT_ITERS:-500}"
TIMING_ROUNDS="${TIMING_ROUNDS:-2000}"
mkdir -p "$RESULTS"
on_error() {
  local status=$?
  echo "Experiment runner failed at line ${1:-unknown} (exit $status)."
  for log in "$RESULTS/experiment-configure.log" "$RESULTS/experiment-build.log" \
             "$RESULTS/key-context-benchmark.log" "$RESULTS/decapsulation-timing-summary.log" \
             "$RESULTS/secure-aead-tamper.log"; do
    if [[ -f "$log" ]]; then
      echo "--- $log (last 40 lines) ---"
      tail -n 40 "$log"
    fi
  done
  exit "$status"
}
trap 'on_error "$LINENO"' ERR
OPENSSL_ARGS=(-DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX" -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX")
for lib_dir in "$OPENSSL_PREFIX/lib64" "$OPENSSL_PREFIX/lib" "$OPENSSL_PREFIX/lib/x86_64-linux-gnu"; do
  if [[ -f "$lib_dir/libcrypto.so" ]]; then
    OPENSSL_ARGS+=(-DOPENSSL_INCLUDE_DIR="$OPENSSL_PREFIX/include"
                   -DOPENSSL_CRYPTO_LIBRARY="$lib_dir/libcrypto.so")
    break
  fi
done
cmake -S "$ROOT" -B "$BUILD" "${OPENSSL_ARGS[@]}" \
  >"$RESULTS/experiment-configure.log" 2>&1
cmake --build "$BUILD" --target xwing_key_context_bench xwing_adversarial_stress xwing_secure_demo -j "$(nproc)" >"$RESULTS/experiment-build.log" 2>&1
"$BUILD/xwing_key_context_bench" "$KEY_CONTEXT_ITERS" \
  >"$RESULTS/key-context-benchmark.csv" 2>"$RESULTS/key-context-benchmark.log"
"$BUILD/xwing_adversarial_stress" "$TIMING_ROUNDS" "$RESULTS/decapsulation-timing.csv" \
  >"$RESULTS/adversarial-cases.csv" 2>"$RESULTS/decapsulation-timing-summary.log"
"$BUILD/xwing_secure_demo" >"$RESULTS/secure-aead-tamper.log" 2>&1
{
  printf 'capture_utc=%s\n' "$STAMP"
  printf 'system=%s\n' "$(uname -a)"
  printf 'openssl_from_benchmark=%s\n' "$(sed -n 's/.*openssl=\([^;]*\);.*/\1/p' "$RESULTS/key-context-benchmark.log")"
  printf 'key_context_iterations=%s\n' "$KEY_CONTEXT_ITERS"
  printf 'timing_rounds_per_class=%s\n' "$TIMING_ROUNDS"
} >"$RESULTS/experiment-environment.txt"
printf 'Experiment outputs saved under %s/testing/results\n' "$ROOT"

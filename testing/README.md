# X-Wing project testing

This folder contains a test plan, Ubuntu/WSL runner, output validator, saved integration-run report, stage logs, benchmark CSVs, and separate native stress-test harnesses/logs.

## Run the integration checks

From the project root:

```bash
bash testing/run_all.sh
```

The runner checks dependencies, configures/builds native programs in a fresh timestamped directory below `testing/results/`, runs Python tests and demos, runs native demos and benchmarks, checks the local dashboard health endpoint, and validates captured outputs. It exits nonzero when any stage or validation fails.

The runner defaults to OpenSSL at `/opt/openssl-3.5`; override it if needed:

```bash
export OPENSSL_PREFIX=/path/to/openssl-3.5
bash testing/run_all.sh
```

It overwrites the standard output logs, CSVs, status file, and dashboard health response in `testing/results/`. Back up the included measurements before rerunning if you want to retain them. Timestamped build directories are kept under that folder. The integration runner does not run the separate stress-test harnesses; the experiment runner below handles the new cases.

## Native key-context and adversarial experiments

Run the profiling and adversarial/timing experiments with:

```bash
bash testing/run_experiments.sh
```

The script builds in a timestamped directory and writes separate CSVs for key-context measurements, functional tamper cases, and per-sample randomized timing observations. It also records host/OpenSSL metadata and summary statistics. Set `KEY_CONTEXT_ITERS` and `TIMING_ROUNDS` to adjust repetition counts. Prepared contexts belong to one worker at a time; the benchmark keeps them on a single thread. Each prepared encapsulation still creates fresh ephemeral randomness.

The KEM test observes both explicit X25519 rejection and ML-KEM implicit rejection. The C API accepts a fixed-size ciphertext pointer and has no length parameter, so truncation is a caller-side framing check and is reported as not testable through this API. Timing comparisons are exploratory measurements on the current host, not proof of constant-time behavior.

## Captured evidence

See [`REPORT.md`](REPORT.md) for the full run's date, environment, results, benchmark observations, limitations, and the separate November 8 stress logs. The full integration outputs are in `results/`. The stress harness sources are in `stress-tests/`; they are not coverage-guided fuzzers.

## What the checks cover

- Python tests: paper label and expected logical sizes, OpenSSL capability, and original-paper end-to-end round trip.
- Native demo: draft-11 and separate research hash-CT round trips.
- Secure demo: HKDF-SHA256 and AES-256-GCM local encrypt/decrypt.
- NTT lab: comparison with a naive reference before timing.
- Output validator: required stage statuses, key-agreement markers, health response, and CSV structure.
- Dashboard health: HTTP health response on localhost only; it does not execute a dashboard handshake.

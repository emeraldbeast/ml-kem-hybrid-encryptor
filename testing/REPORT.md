# Comprehensive X-Wing Test Report

**Full integration run:** 4 November 2026 23:07 UTC (5 November, India Standard Time)  
**Targeted native stress run:** 8 November 2026 (local timestamp on captured logs)  
**Environment:** Ubuntu 22.04 under WSL 2

## Scope and evidence

This report distinguishes the saved full integration run from later targeted hardening checks. The full suite was captured in `testing/results/` and covered dependencies, CMake configuration/build, Python tests, the paper-baseline CLI, both native modes, the local AEAD demo, KEM and NTT benchmarks, dashboard health, and output validation. The separate November 8 stress logs cover additional native round-trip and malformed-input cases. The complete integration suite was not rerun after those later code and runner changes; the results below retain their capture dates and scope.

## Environment

| Component | Captured environment |
|---|---|
| OS | Ubuntu 22.04 under WSL 2 |
| Python | 3.10.12 |
| OpenSSL | 3.5.5, installed at `/opt/openssl-3.5` |
| ML-KEM | ML-KEM-512/768/1024 listed by the default provider |
| CMake | 3.22.1 |
| GCC | 11.4.0 |
| OpenMP | `_OPENMP 201511`; CMake found OpenMP 4.5 |
| OpenSSL pkg-config | 3.5.5 from the private prefix |

## Full integration run results

| Stage | Captured result |
|---|---|
| Dependency check | PASS |
| CMake configure and native compilation | PASS |
| Python unit tests | PASS, 3 tests |
| Python original-paper demo | PASS; component and final-secret checks matched |
| Native draft-11 and research comparator | PASS; both round trips matched |
| HKDF-SHA256/AES-256-GCM demo | PASS; local message authenticated and recovered |
| Dashboard health endpoint | PASS |
| KEM batch benchmark | PASS, 8 CSV rows |
| NTT reference check and benchmark | PASS, 9 CSV rows |
| Captured-output validation | PASS |

The full-run outputs are preserved as `status.txt`, per-stage `.log` files, `dashboard-health.json`, `kem-batch.csv`, and `ntt.csv` under `testing/results/`. The `status.txt` timestamp is UTC; its date is November 4 UTC and corresponds to November 5 local time.

## Targeted native stress checks

The saved `native-roundtrip-stress.log` records 2,400 matching native round trips (30 keypairs × 40 iterations × two modes), plus checks for null arguments, invalid modes, output clearing, a low-order X25519 input, and ML-KEM implicit-rejection behavior.

The saved `native-malformed-stress.log` records 5,000 malformed decapsulation attempts and 5,000 malformed encapsulation attempts completed without a crash. These are targeted malformed-input checks. The logs do not establish coverage-guided fuzzing, exhaustive input coverage, or cryptographic security.

The stress harnesses were run in an AddressSanitizer/UndefinedBehaviorSanitizer-enabled build in the prior testing session. The retained text logs contain the outcomes but not the full sanitizer build commands.

## Benchmark observations

These values are from a single WSL run and are an initial baseline, not a statistical performance claim.

### Independent KEM encapsulation batches

| Mode | Threads | Operations/s | Speedup | Efficiency |
|---|---:|---:|---:|---:|
| Draft-11 | 1 | 4,625.09 | 1.000× | 100.0% |
| Draft-11 | 2 | 6,935.16 | 1.500× | 75.0% |
| Draft-11 | 4 | 9,735.29 | 2.105× | 52.6% |
| Draft-11 | 8 | 15,087.54 | 3.262× | 40.8% |
| Research hash-CT | 1 | 3,865.04 | 1.000× | 100.0% |
| Research hash-CT | 8 | 16,653.35 | 4.309× | 53.9% |

The benchmark parallelizes independent encapsulations. It does not split one KEM operation across threads. The hash-CT mode adds the ML-KEM ciphertext to the hash input and is a research comparator, not interoperable X-Wing.

### NTT lab

| Method | Threads | Operations/s | Observation |
|---|---:|---:|---|
| Naive cyclic convolution | 1 | 8,143.72 | Reference method |
| Serial NTT with precomputed twiddles | 1 | 43,449.72 | 5.335× naive throughput |
| Batch-parallel NTT | 8 | 122,727.54 | 2.825× serial NTT throughput |
| Stage-parallel NTT | 8 | 9,425.98 | 0.217× serial NTT throughput |

The lab checks 16 deterministic input pairs against its naive reference before timing. It uses `F_12289[X]/(X^256 - 1)`, while ML-KEM uses a different ring. It is an isolated educational algorithms experiment, not an optimization of OpenSSL's ML-KEM implementation.

## Changes carried into this project version

- Native ML-KEM public-key import uses OpenSSL's public-key parameter, resolving the earlier `missing key` encapsulation failure.
- Invalid native mode paths clear caller output buffers before returning an error.
- The NTT modular subtraction avoids the earlier signedness warning.
- `testing/run_all.sh` now uses a unique build directory, clears any prior dashboard health response before checking, validates that the newly started dashboard process is alive, and exits nonzero when a stage or output validation fails.

The runner changes are included in this final source package but were not executed during preparation of this report.

## Limitations and next validation steps

Functional round trips and sanitizer-backed stress checks do not prove IND-CCA security, constant-time behavior, or interoperability. No independent deterministic known-answer vectors or cross-implementation interoperability results are included. The benchmarks are single-run observations without warm-up/repetition statistics. The dashboard uses local OpenSSL subprocesses, so its timing includes process startup and file I/O. The AES-GCM example is local and does not authenticate a peer identity.

Recommended next steps are to add independent draft-11 test vectors and interoperability checks, run repeated benchmark trials with machine metadata, and obtain deeper security review. Treat the project as an educational/research prototype rather than production cryptography.

## Follow-up native experiments

The key-context and adversarial/timing experiments were subsequently built and run on 10 November 2026. The context benchmark recorded 2,000 iterations per row and reported 1.653× encapsulation, 2.395× decapsulation, 1.865× repeated-exchange, and 1.087× complete-handshake speedups for the prepared path. The adversarial harness recorded 5,000 timing samples per class and passed its functional cases. These are single-run, exploratory results. See [`../FINAL_EXPERIMENTS_REPORT.md`](../FINAL_EXPERIMENTS_REPORT.md) for the full four-part experiment summaries, exact measurements, conclusions, evidence links, and limitations.

# Validation record and remaining plan

## Captured checks

The available evidence is recorded in [`../testing/REPORT.md`](../testing/REPORT.md), stage logs, benchmark CSVs, and two separate native stress logs. The full integration run was captured on 4 November 2026 23:07 UTC (5 November local time); targeted native stress logs are dated 8 November. The current `testing/run_all.sh` has since been improved to use a unique build directory, verify a fresh dashboard process, and return a failing exit code when any stage fails. That runner revision has not yet been executed.

Captured coverage includes:

1. Dependency capability check and CMake configure/build.
2. Three Python unit tests and an actual original-paper baseline round trip.
3. Native draft-11 and research hash-CT round trips.
4. HKDF/AES-256-GCM local message recovery and dashboard health.
5. KEM batch and NTT CSV benchmarks; the NTT program checks 16 deterministic input pairs against its naive reference before timing.
6. Targeted native checks for 2,400 round trips, invalid mode/output-cleansing behavior, low-order X25519 input, ML-KEM implicit rejection, and 10,000 malformed-input calls without a crash.

## Remaining validation work

- Add deterministic known-answer vectors and compare against an independent draft-11 implementation.
- Run cross-implementation interoperability checks; round trips from one implementation alone cannot detect shared implementation mistakes.
- Run the updated test runner after its changes and retain a fresh report with exact source revision and toolchain details.
- Perform repeated benchmark trials with warm-up and report medians and variation.
- Expand boundary/randomized NTT checks and independently validate arithmetic assumptions.
- Consider static analysis and more extensive fuzzing; the saved malformed-input attempts are not coverage-guided fuzzing.
- A security audit, formal verification, constant-time analysis, and production deployment certification have not been completed.
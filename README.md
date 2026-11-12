# X-Wing Hybrid KEM — Paper Baseline and Parallel Computing Project

A small, local, runnable teaching prototype for the **original X-Wing construction in Figure 12** of:

> Manuel Barbosa, Deirdre Connolly, João Diogo Duarte, Aaron Kaiser, Peter Schwabe, Karolin Varner, and Bas Westerbaan, *X-Wing: The Hybrid KEM You've Been Looking For*, IACR Communications in Cryptology, Vol. 1, No. 1.

The original Python implementation and local dashboard deliberately retain the paper's composition:

- ML-KEM-768 for the post-quantum KEM component;
- X25519 used directly for the classical Diffie–Hellman component;
- SHA3-256 over `label || k1 || k2 || c2 || pk2` as the hybrid combiner;
- the original six-byte label `\.//^\`;
- no ML-KEM ciphertext `c1` in the final combiner input (the paper proves this omission for this particular construction).

**Version scope:** this is a paper-baseline prototype. It is not intended to be wire-compatible with later X-Wing Internet-Draft revisions that changed aspects of key derivation/encoding. Do not silently mix versions.

## What is implemented

1. A real ML-KEM-768 key-generation, encapsulation, and decapsulation flow via OpenSSL.
2. X25519 recipient key generation, ephemeral public value generation, and DH derivation via OpenSSL.
3. The original paper's SHA3-256 combiner in Python's standard-library `hashlib`.
4. A local interactive dashboard showing the live operation sequence, logical encoded lengths, timing measurements, public ciphertext previews, secret fingerprints, and sender/receiver correctness checks.
5. A CLI JSON report and Python unit tests for the real paper-baseline round trip.
6. A native C implementation of X-Wing draft-11, kept separate from the original-paper baseline.
7. Native OpenMP throughput benchmarks for independent KEM encapsulations and a hash-CT comparator.
8. An NTT lab with a naive reference, iterative radix-2 transform, precomputed twiddles, Barrett modular reduction, stage parallelism, and batch-level OpenMP.

The Python dashboard demonstrates the original paper construction. The native library demonstrates draft-11. Their key generation and combiner encodings are not interchangeable.

## Requirements

- Python 3.10 or newer (standard library only) for the paper-baseline dashboard and CLI.
- **OpenSSL 3.5.0 or newer**, compiled with its default provider and ML-KEM support.
- CMake 3.20 or newer and a C11 compiler with OpenMP support for the native programs.
- On GCC systems, OpenMP comes with the compiler runtime (`libgomp`); no separate OpenMP application is needed.
- A browser with JavaScript enabled.

The prototype was exercised in the authoring environment using OpenSSL 3.5.5. The backend depends on the OpenSSL command-line interfaces `genpkey`, `pkey`, and `pkeyutl` for `ML-KEM-768` and `X25519`.

Check your environment:

```bash
python --version
openssl version
openssl list -kem-algorithms
```

`ML-KEM-768` should appear in the KEM algorithms list.

## Run the interactive dashboard

From this project directory:

```bash
python run_dashboard.py
```

Open <http://127.0.0.1:8765> in your browser. Press **Run actual handshake**. The backend runs the cryptographic operations on your machine and checks that both sides independently derive the same 32-byte hybrid secret.

The dashboard is bound to `127.0.0.1` only. Keep it local; do not expose it to a network.

Stop with `Ctrl+C` in the terminal.

## Run one CLI demo

```bash
python run_demo.py
```

The command prints a JSON report including the step trace, sizes, timings, component matches, and short SHA-256 fingerprints. It does not print private keys or raw shared secrets.

## Run tests and view results

Run the Python unit tests:

```bash
python3 -m unittest discover -s tests -v
```

The captured integration report and outputs are in `testing/REPORT.md` and `testing/results/`. They record a successful full run on 5 November 2026 and targeted native stress checks on 8 November. To rerun the integration checks:

```bash
bash testing/run_all.sh
```

Set `OPENSSL_PREFIX` if OpenSSL 3.5 is installed outside `/opt/openssl-3.5`. The runner uses a unique build directory, overwrites the standard logs and CSVs in `testing/results/`, and returns a nonzero exit code if a stage or output validation fails.
For the professor presentation, see [`PROFESSOR_DEMO_GUIDE.md`](PROFESSOR_DEMO_GUIDE.md), which includes the timed walkthrough, exact commands, expected results, recovery steps, and likely questions.

## Native implementation and parallel-computing experiments

See [`RUNNING_INSTRUCTIONS.md`](RUNNING_INSTRUCTIONS.md) for the separate setup and execution guide. It covers:

- `xwing_native_demo`: native draft-11 and research hash-CT round trips.
- `xwing_secure_demo`: a local draft-11 → HKDF-SHA256 → AES-256-GCM message demonstration.
- `xwing_native_bench`: independent encapsulation throughput, speedup, and efficiency over OpenMP thread counts.
- `ntt_lab`: naive cyclic multiplication, precomputed radix-2 NTT, modular reduction, stage parallelism, and batch parallelism.

Draft-11 is pinned to `draft-connolly-cfrg-xwing-kem-11` (23 September 2026), the latest revision available when this expansion was prepared. The hash-CT comparator is research-only and non-interoperable. The NTT lab uses `F_12289[X]/(X^256-1)` as an educational workload; it is not ML-KEM's `Z_3329[X]/(X^256+1)` arithmetic and does not replace OpenSSL's ML-KEM.

## Directory structure and responsibilities

```text
xwing-hybrid-baseline/
├── README.md
├── RUNNING_INSTRUCTIONS.md
├── CMakeLists.txt
├── run_dashboard.py
├── run_demo.py
├── xwing/
│   ├── __init__.py
│   ├── openssl_backend.py
│   └── paper_baseline.py
├── dashboard/
│   ├── __init__.py
│   ├── server.py
│   └── static/
│       ├── index.html
│       ├── app.css
│       └── app.js
├── tests/
│   └── test_xwing.py
├── native/
│   ├── include/xwing/xwing.h
│   ├── src/{xwing.c,demo.c,secure_demo.c,benchmark.c}
│   └── experiments/ntt/ntt_lab.c
├── scripts/plot_results.py
└── docs/
    ├── architecture.md
    ├── paper-notes.md
    ├── versioning-and-experiments.md
    ├── threat-model.md
    ├── benchmark-methodology.md
    ├── testing-strategy.md
    └── results-and-limitations.md
```

### Module notes

- `xwing/openssl_backend.py`: narrowly scoped wrappers around OpenSSL. It generates keys, performs ML-KEM encapsulation/decapsulation, performs X25519 derivation, validates output lengths, and measures wall-clock duration for each command. Keeping this adapter isolated will make it easier to switch to direct library bindings later.
- `xwing/paper_baseline.py`: readable implementation of the paper's X-Wing composition. It orchestrates the component KEMs, builds the exact combiner input, performs SHA3-256, and compares sender/receiver outputs. This is the cryptographic logic we should keep stable while later optimization experiments go in separate modules.
- `dashboard/server.py`: dependency-free HTTP server. It serves static dashboard assets and exposes `/api/health` and `/api/run` locally.
- `dashboard/static/index.html`: dashboard structure and algorithm panels.
- `dashboard/static/app.css`: responsive dashboard styling and status visualizations.
- `dashboard/static/app.js`: triggers real backend operations, renders the steps and measurements, copies public-data previews, and exports a JSON run report.
- `run_dashboard.py`: simple dashboard entry point.
- `run_demo.py`: headless/CLI entry point, useful for debugging and automation.
- `tests/test_xwing.py`: fast specification-size checks plus a real cryptographic round trip.
- `docs/paper-notes.md`: summary of the original design and important versioning details.
- `docs/architecture.md`: module boundaries, data flow, and design rationale.
- `native/src/xwing.c`: draft-11 implementation using OpenSSL EVP ML-KEM, X25519, SHAKE256, and SHA3-256.
- `native/src/secure_demo.c`: local KEM/HKDF/AEAD demonstration (peer authentication is not provided).
- `native/src/benchmark.c`: batch encapsulation and OpenMP scaling measurements.
- `native/experiments/ntt/ntt_lab.c`: isolated arithmetic and NTT optimization experiments.
- `scripts/plot_results.py`: optional Matplotlib charts from saved benchmark CSV.
- `RUNNING_INSTRUCTIONS.md`: separate setup/download/build/run guide.
- `docs/versioning-and-experiments.md`: boundary between paper baseline, draft-11, and the research comparator.
- `docs/threat-model.md`: security claims and limitations.
- `docs/benchmark-methodology.md`: measurement plan and scaling metrics.
- `docs/testing-strategy.md`: completed checks, known coverage gaps, and recommended follow-up validation.

## Expected logical lengths from the original paper

| Object | Length |
|---|---:|
| ML-KEM-768 public key | 1,184 bytes |
| ML-KEM-768 private key | 2,400 bytes |
| X25519 private key | 32 bytes |
| X25519 public key | 32 bytes |
| X-Wing public key | 1,216 bytes |
| X-Wing private key | 2,464 bytes |
| ML-KEM ciphertext `c1` | 1,088 bytes |
| X25519 ciphertext `c2` | 32 bytes |
| X-Wing ciphertext `(c1, c2)` | 1,120 bytes |
| Combiner input | 134 bytes |
| Hybrid shared secret | 32 bytes |

These are logical raw lengths from the paper's construction. PEM/DER files used internally by OpenSSL include serialization overhead and should not be confused with those raw lengths.

## Important limitations

- This is a **learning/research prototype**, not a security-audited implementation and not production software.
- OpenSSL operations are invoked as subprocesses. Reported timings include process startup and file I/O, so do not compare these measurements directly to the paper's CPU-cycle results.
- Temporary key files are placed in a temporary directory and automatically removed when the run completes. This is not a formal secure-erasure guarantee.
- The dashboard receives short fingerprints of derived secrets for comparison; it never returns the raw shared secrets or private-key bytes. Do not add production key material to this demo.
- A KEM does not authenticate the peer by itself and does not encrypt application messages by itself.
- The paper's security argument applies to the exact construction and its assumptions. This code is not a substitute for studying that proof, independent validation, or using a vetted protocol in deployment.

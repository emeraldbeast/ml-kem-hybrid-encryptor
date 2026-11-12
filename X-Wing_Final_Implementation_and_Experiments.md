# Hybrid X-Wing KEM — Implementation and Experimental Results

**Project report**  
**Implementation split:** Original-paper Python baseline and native C draft-11 implementation  
**Cryptographic backend:** OpenSSL 3.5.x  
**Benchmark environment:** Linux/WSL environment recorded in the project logs; results below are from the archived runs in `testing/results/`.

---

## 1. Project overview

X-Wing is a hybrid key-encapsulation mechanism (KEM) that combines:

- **ML-KEM-768**, a post-quantum lattice-based KEM; and
- **X25519**, a classical elliptic-curve Diffie–Hellman key exchange.

The two component secrets are combined using a cryptographic hash to derive one 32-byte hybrid shared secret. The KEM establishes a shared secret; it does not directly encrypt application messages.

This repository contains two deliberately separate implementations:

1. **Python original-paper baseline** — follows the construction in Figure 12 / Definition 8 of *X-Wing: The Hybrid KEM You've Been Looking For*.
2. **Native C implementation** — targets X-Wing Internet-Draft revision 11 and provides the implementation used for the native performance and optimisation experiments.

These paths are not interchangeable. Their encodings and construction details must not be assumed to match, and their keys/ciphertexts should not be mixed.

---

# 2. Baseline paper implementation

## 2.1 Objective and reference

The Python baseline was developed to implement and demonstrate the original X-Wing construction from the paper:

> Barbosa et al., *X-Wing: The Hybrid KEM You've Been Looking For*, Figure 12 / Definition 8.

The purpose of this implementation is to make the paper's construction explicit and verifiable before exploring the separate native draft-11 implementation.

The baseline is correctness-oriented rather than performance-oriented. It invokes OpenSSL through a command-line adapter and uses Python's `hashlib.sha3_256` for the final combiner.

### Main files

| File | Responsibility |
|---|---|
| `xwing/paper_baseline.py` | Implements the paper's KeyGen, Encaps, Decaps flow and shared-secret combination |
| `xwing/openssl_backend.py` | Invokes OpenSSL primitives and handles the required input/output formats |
| `run_demo.py` | Runs the baseline demonstration |
| `dashboard/` | Presents the actual baseline execution steps and results in a local browser |
| `tests/test_xwing.py` | Python correctness tests |

## 2.2 Key generation

The recipient generates two component key pairs.

1. Run `ML-KEM-768.KeyGen` to obtain:
   - ML-KEM public key \(pk_1\)
   - ML-KEM private key \(sk_1\)
2. Generate a 32-byte X25519 private value \(sk_2\).
3. Derive the X25519 public key:
   \[
   pk_2 = \operatorname{X25519}(sk_2,\text{basepoint})
   \]
4. Form the hybrid public and private key tuples.

| Object | Size |
|---|---:|
| ML-KEM-768 public key | 1,184 bytes |
| ML-KEM-768 private key | 2,400 bytes |
| X25519 private key | 32 bytes |
| X25519 public key | 32 bytes |
| Combined public key | 1,216 bytes |
| Combined private key representation | 2,464 bytes |

## 2.3 Encapsulation

The sender uses the recipient's hybrid public key.

1. Execute ML-KEM encapsulation with \(pk_1\), producing:
   - ML-KEM ciphertext \(c_1\)
   - ML-KEM shared secret \(k_1\)
2. Generate a fresh ephemeral X25519 private value \(sk_e\).
3. Derive the ephemeral X25519 public value:
   \[
   c_2 = \operatorname{X25519}(sk_e,\text{basepoint})
   \]
4. Compute the X25519 component secret:
   \[
   k_2 = \operatorname{X25519}(sk_e,pk_2)
   \]
5. Derive the final hybrid secret:
   \[
   K = \operatorname{SHA3\text{-}256}
   (label \parallel k_1 \parallel k_2 \parallel c_2 \parallel pk_2)
   \]
6. Return the hybrid ciphertext \((c_1,c_2)\) and the 32-byte secret \(K\).

The X-Wing ciphertext is 1,120 bytes: 1,088 bytes of ML-KEM ciphertext and 32 bytes of X25519 ephemeral public value.

## 2.4 Decapsulation

The recipient receives \((c_1,c_2)\).

1. Recover the ML-KEM component secret:
   \[
   k'_1 = \operatorname{ML\text{-}KEM\text{-}768.Dec}(c_1,sk_1)
   \]
2. Compute the X25519 component secret:
   \[
   k'_2 = \operatorname{X25519}(sk_2,c_2)
   \]
3. Recompute the same combiner:
   \[
   K' = \operatorname{SHA3\text{-}256}
   (label \parallel k'_1 \parallel k'_2 \parallel c_2 \parallel pk_2)
   \]
4. Check correctness by comparing \(K\) and \(K'\).

For a valid ciphertext, both sides should obtain the same 32-byte hybrid secret.

## 2.5 Domain-separation label and combiner input

The original-paper baseline uses the six-byte ASCII label:

```text
\.//^\
```

Its hexadecimal representation is:

```text
5c 2e 2f 2f 5e 5c
```

The combiner input is exactly 134 bytes:

| Component | Size |
|---|---:|
| Label | 6 bytes |
| ML-KEM shared secret \(k_1\) | 32 bytes |
| X25519 shared secret \(k_2\) | 32 bytes |
| Ephemeral X25519 public value \(c_2\) | 32 bytes |
| Recipient X25519 public key \(pk_2\) | 32 bytes |
| **Total** | **134 bytes** |

The original construction does not include the 1,088-byte ML-KEM ciphertext in this combiner input. This is a deliberate part of the paper's construction, not an accidental omission.

## 2.6 Baseline execution result

The archived baseline run completed successfully using Python 3.10.12 and OpenSSL 3.5.5.

| Check | Result |
|---|---|
| ML-KEM sender/receiver component secrets match | PASS |
| X25519 sender/receiver component secrets match | PASS |
| Combiner input length is 134 bytes | PASS |
| Final sender/receiver hybrid secrets match | PASS |
| Final hybrid secret length | 32 bytes |

The recorded run produced a 1,120-byte X-Wing ciphertext and matching 32-byte sender and receiver secrets.

The baseline's measured timings are useful as an execution trace, but they should **not** be treated as a fair native-vs-native benchmark: the Python path invokes OpenSSL subprocesses, while the native C path uses OpenSSL EVP APIs directly.

## 2.7 Dashboard

The dashboard is a visualisation layer over the actual baseline execution. It displays the cryptographic stages, input/output sizes, component-secret checks and final correctness result.

The dashboard does not implement a separate cryptographic simulation in the browser. The server triggers the real operation and returns a safe report; raw private keys and shared-secret values are not exposed to the browser.

---

# 3. Native C implementation used by the experiments

The native implementation is under `native/` and targets X-Wing Internet-Draft revision 11.

| File | Purpose |
|---|---|
| `native/src/xwing.c` | Native X-Wing key generation, encapsulation and decapsulation |
| `native/include/xwing/xwing.h` | Public API |
| `native/src/demo.c` | Native KEM correctness demonstration |
| `native/src/secure_demo.c` | KEM + HKDF + AES-256-GCM local communication demonstration |
| `native/src/benchmark.c` | OpenMP batch KEM benchmark |
| `native/experiments/ntt/ntt_lab.c` | Standalone NTT/polynomial multiplication experiment |
| `native/experiments/key_context_bench.c` | Prepared-key-context benchmark |

The native library uses OpenSSL EVP for ML-KEM-768 and X25519 operations, SHAKE256 for the relevant key expansion, and SHA3-256 for hybrid secret combination.

## 3.1 Secure communication demonstration

The secure demo illustrates how an application can use the KEM-derived secret:

1. Bob generates an X-Wing key pair.
2. Alice encapsulates to Bob's public key and obtains a shared secret plus KEM ciphertext.
3. Bob decapsulates and independently obtains the same shared secret.
4. HKDF-SHA256 derives a 256-bit application encryption key.
5. AES-256-GCM encrypts and authenticates the message.
6. Bob decrypts the ciphertext and verifies the authentication tag.

This demonstrates the distinction between **key establishment** and **message encryption**: X-Wing establishes the secret; HKDF derives an application key; AES-GCM protects the message.

**Security boundary:** this is a local demonstration, not a complete authenticated network protocol. In particular, it does not authenticate Bob's public key or peer identity. A real deployment must authenticate public keys (for example, using certificates, signatures or pinned keys). AES-GCM nonces must also never be reused with the same key.

---

# 4. Experiments and results

The experiments cover throughput, polynomial arithmetic, repeated-use key preparation, adversarial inputs, timing behaviour and functional stress testing.

Unless otherwise stated, the values below are transcribed from the archived CSV/log files in `testing/results/`. They are measurements from the recorded environment and should be treated as experimental observations, not universal performance guarantees.

## 4.1 Experiment A — OpenMP batch KEM benchmark

**File:** `native/src/benchmark.c`  
**Result:** `testing/results/kem-batch.csv`

### Objective

Measure the throughput improvement when independent KEM encapsulation operations are distributed across OpenMP threads.

Each operation is independent, so this experiment uses **batch-level parallelism**. It does not parallelise the internal polynomial arithmetic of ML-KEM.

### X-Wing draft-11 results

| Threads | Operations | Throughput (ops/s) | Speedup | Parallel efficiency |
|---:|---:|---:|---:|---:|
| 1 | 1,000 | 5,286.08 | 1.00× | 100.0% |
| 2 | 1,000 | 6,730.75 | 1.27× | 63.7% |
| 4 | 1,000 | 13,035.73 | 2.47× | 61.7% |
| 8 | 1,000 | 17,090.50 | 3.23× | 40.4% |

At eight threads, throughput increased from approximately 5,286 to 17,091 operations per second, giving a measured speedup of **3.23×**.

Efficiency decreases as the thread count rises. This is expected because parallel execution introduces scheduling, synchronisation and resource-contention overhead, and the machine has finite compute capacity.

### Additional recorded mode

The same CSV also contains a `paper_hash_ct` mode:

| Threads | Throughput (ops/s) | Speedup |
|---:|---:|---:|
| 1 | 5,225.20 | 1.00× |
| 2 | 7,230.70 | 1.38× |
| 4 | 12,787.56 | 2.45× |
| 8 | 19,235.21 | 3.68× |

These rows are a separate benchmark mode and should not be silently merged with the draft-11 rows. The mode names and implementation differences should be explained if these values are shown in a presentation.

**Conclusion:** OpenMP batch parallelism improves aggregate KEM throughput in this run. The measured eight-thread speedup for the draft-11 mode is 3.23×; it is not an equivalent reduction in the latency of one individual KEM operation.

## 4.2 Experiment B — Number Theoretic Transform (NTT)

**File:** `native/experiments/ntt/ntt_lab.c`  
**Result:** `testing/results/ntt.csv`

### Objective

Demonstrate how polynomial multiplication can be accelerated using the Number Theoretic Transform.

A direct polynomial multiplication performs \(O(n^2)\) coefficient products. An NTT-based approach transforms the polynomials, performs pointwise multiplication, and applies an inverse transform, giving an \(O(n\log n)\)-style algorithm for the supported transform.

The butterfly operation has the form:

\[
a = u + wv \pmod q,\qquad
b = u - wv \pmod q
\]

where \(w\) is an appropriate transform root modulo \(q\).

### Important implementation boundary

This NTT program is a **standalone educational experiment**. It is not linked into the native X-Wing library and does not replace or accelerate the NTT implementation internal to OpenSSL's ML-KEM provider.

The experiment uses the ring:

\[
\mathbb{F}_{12289}[X]/(X^{256}-1)
\]

ML-KEM instead operates over:

\[
\mathbb{Z}_{3329}[X]/(X^{256}+1)
\]

Therefore, the benchmark demonstrates NTT concepts and parallelisation strategies; it is not a direct benchmark of ML-KEM's internal polynomial multiplication.

### Results

The run used polynomial length \(n=256\) and 10,000 operations.

| Algorithm | Threads | Throughput (ops/s) | Speedup vs naive |
|---|---:|---:|---:|
| Naive multiplication | 1 | 8,189.53 | 1.00× |
| Serial NTT, precomputed twiddles | 1 | 51,511.28 | 6.29× |
| Batch OpenMP NTT | 2 | 67,445.10 | 8.23× |
| Batch OpenMP NTT | 4 | 97,557.43 | 11.91× |
| Batch OpenMP NTT | 8 | 127,953.46 | 15.62× |
| Stage-parallel NTT | 2 | 37,423.00 | 4.57× |
| Stage-parallel NTT | 4 | 27,955.83 | 3.41× |
| Stage-parallel NTT | 8 | 15,027.60 | 1.84× |

The eight-thread batch implementation achieved 127,953.46 operations per second, approximately **2.48× the serial NTT throughput** and **15.62× the naive multiplication throughput**.

Stage-level parallelism performed worse as the thread count increased. Each NTT stage depends on the results of the previous stage, requiring synchronisation between stages. For this workload, barrier and thread-management overhead outweighed the available parallel work.

**Conclusion:** batch-level parallelism is the more effective strategy for this experiment. The results also illustrate that adding threads does not automatically improve performance.

## 4.3 Experiment C — Prepared Key Context optimisation

**Files:**
- Implementation: `native/src/xwing.c`
- Public API: `native/include/xwing/xwing.h`
- Benchmark: `native/experiments/key_context_bench.c`
- Result: `testing/results/key-context-benchmark.csv`

### Problem addressed

In the ordinary native API, repeated encapsulation or decapsulation with the same long-term key can repeat key preparation work.

For example:
- Encapsulation repeatedly imports/prepares the recipient's ML-KEM and X25519 public-key objects.
- Decapsulation repeatedly expands the private seed and prepares the corresponding ML-KEM and X25519 key objects.

When an application reuses a long-term recipient key for many KEM operations, repeating this work adds avoidable overhead.

### Optimisation

The prepared-context API moves long-term key preparation into an explicit setup step.

- `xwing_encap_context_new(pk)` prepares and stores the recipient public-key objects.
- `xwing_decap_context_new(sk)` expands and prepares the recipient private-key objects.
- `xwing_encapsulate_prepared(...)` reuses the prepared encapsulation context.
- `xwing_decapsulate_prepared(...)` reuses the prepared decapsulation context.
- The corresponding `*_context_free(...)` functions release the stored objects and cleanse the context.

The optimisation caches the long-term key objects; it does **not** cache a session secret or reuse ephemeral randomness. Fresh per-operation cryptographic work still occurs, including fresh encapsulation randomness and the relevant KEM/DH operations.

The header specifies one context per worker thread. Contexts must not be shared concurrently between threads.

### Results

The benchmark used 2,000 iterations for each row. Repeated-operation measurements exclude context setup; the complete-handshake measurement includes key generation and per-key context setup/destruction.

| Operation | Baseline latency | Prepared latency | Speedup | Latency reduction |
|---|---:|---:|---:|---:|
| Encapsulation | 121.44 µs | 73.48 µs | 1.65× | 39.5% |
| Decapsulation | 139.94 µs | 58.44 µs | 2.39× | 58.2% |
| Repeated exchange | 249.21 µs | 133.62 µs | 1.87× | 46.4% |
| Complete handshake | 307.23 µs | 282.61 µs | 1.09× | 8.0% |

All benchmark correctness checks reported `PASS`.

The complete-handshake improvement is smaller because that measurement includes the setup cost that the repeated-operation measurements intentionally exclude.

**Conclusion:** prepared contexts substantially reduce repeated encapsulation/decapsulation latency when the same long-term key is reused. The benefit is smaller for a one-off complete handshake because context construction still has to be performed.

**Measurement caveat:** these are results from the archived benchmark run, with 2,000 iterations per row. They should be presented as preliminary measurements from this environment, not as statistically characterised performance claims across multiple machines or repeated independent trials.

## 4.4 Experiment D — Adversarial ciphertext and AES-GCM tamper tests

**Result:** `testing/results/adversarial-cases.csv` and `testing/results/secure-aead-tamper.log`

### Objective

Check how the implementation behaves when ciphertext components, recipient keys or AEAD inputs are modified.

### Results

| Test case | Observed behaviour | Result |
|---|---|---|
| Valid X-Wing ciphertext | Decapsulation succeeds; sender and receiver secrets match | PASS |
| ML-KEM ciphertext, single-bit modification | Decapsulation returns a secret that does not match the sender's; AEAD authentication fails | PASS |
| ML-KEM ciphertext, multiple-bit modification | Secret mismatch; AEAD authentication fails | PASS |
| X25519 public value bit-flip | Secret mismatch; AEAD authentication fails | PASS |
| Wrong recipient private key | Secret mismatch; AEAD authentication fails | PASS |
| Low-order X25519 input | Rejected | PASS |
| AES-GCM ciphertext bit-flip | Authentication fails; output is cleared | PASS |
| AES-GCM tag bit-flip | Authentication fails; output is cleared | PASS |
| Wrong AES key | Authentication fails; output is cleared | PASS |
| Truncated X-Wing ciphertext | Not testable through the fixed-size API alone | Caller length check required |

### Interpretation

ML-KEM uses implicit rejection for invalid ciphertexts: a modified ML-KEM ciphertext does not necessarily cause the decapsulation API to return an explicit error. It can instead produce a fallback secret. Therefore, the correct check is not simply “every modified ML-KEM ciphertext must be rejected by the KEM function.” In this end-to-end demonstration, the resulting hybrid secret does not match the sender's secret, so AES-GCM authentication fails.

The X-Wing native API accepts fixed-size ciphertext buffers. The caller must validate the received ciphertext length before passing the buffer to the API. The test records this as a caller-side requirement rather than claiming that the fixed-size API itself detects truncation.

**Conclusion:** the tested tampering cases behaved as expected in the recorded run. These tests are functional checks; they are not a formal security proof or a complete protocol audit.

## 4.5 Experiment E — Decapsulation timing comparison

**Result:** `testing/results/decapsulation-timing.csv` and `testing/results/decapsulation-timing-summary.log`

### Objective

Compare decapsulation timings for valid ciphertexts and two modified-ciphertext classes:

- valid ciphertext;
- ML-KEM component bit-flipped;
- X25519 public component bit-flipped.

The experiment collected 5,000 timing samples per class.

### Results

| Input class | Samples | Mean time | Median time |
|---|---:|---:|---:|
| Valid ciphertext | 5,000 | 141.96 µs | 136.09 µs |
| ML-KEM bit-flipped | 5,000 | 141.80 µs | 136.61 µs |
| X25519 bit-flipped | 5,000 | 142.40 µs | 136.23 µs |

Welch's t-statistics recorded by the experiment:

| Comparison | Welch t-statistic |
|---|---:|
| Valid vs ML-KEM bit-flipped | 0.2276 |
| Valid vs X25519 bit-flipped | -0.5836 |

The observed means are close, and these comparisons do not show a statistically clear timing difference in this dataset.

**Important limitation:** this is not proof that the implementation is constant-time or free of side channels. Timing measurements can be affected by system noise, scheduling, CPU frequency changes, cache state and the measurement setup. A stronger side-channel evaluation would require controlled hardware, repeated independent runs and a more rigorous statistical methodology.

## 4.6 Experiment F — Functional and malformed-input stress tests

**Results:**
- `testing/results/native-roundtrip-stress.log`
- `testing/results/native-malformed-stress.log`
- `testing/results/python-tests.log`
- `testing/results/status.txt`

### Results

| Test | Recorded result |
|---|---|
| Python unit tests | 3/3 passed |
| Native valid KEM round trips | 2,400 passed (30 key pairs × 40 operations per mode) |
| Malformed decapsulation attempts | 5,000 completed without crash |
| Malformed encapsulation attempts | 5,000 completed without crash |
| Build and dependency checks | Passed |
| Native secure communication demo | Message authenticated and recovered |
| Output validation | Passed |
| Full recorded test pipeline | PASS |

The malformed-input stress test demonstrates that the tested random malformed inputs did not crash the process. It does not prove that all malformed inputs are handled securely or correctly.

---

# 5. Consolidated results

| Experiment | Main result | What it demonstrates |
|---|---|---|
| Original-paper Python baseline | ML-KEM and X25519 component secrets and final hybrid secret matched | Correct implementation of the paper's construction for the tested valid run |
| OpenMP batch KEM | 3.23× throughput speedup at 8 threads in draft-11 mode | Parallel execution of independent KEM operations |
| NTT | Serial NTT was 6.29× faster than naive multiplication; 8-thread batch NTT was 2.48× faster than serial NTT | NTT and batch parallelism on a standalone polynomial workload |
| Prepared key contexts | 1.65× encapsulation and 2.39× decapsulation speedup | Reusing prepared long-term EVP key objects reduces repeated-operation overhead |
| Adversarial/AEAD tests | Tested tampering cases failed secret matching or AEAD authentication as expected | Functional tamper-detection behaviour |
| Timing comparison | No clear timing difference observed in the collected samples | Preliminary timing observation only; not a constant-time proof |
| Stress testing | 2,400 valid round trips and 10,000 malformed-input attempts completed as recorded | Functional robustness under the tested workload |

---

# 6. Overall conclusions

1. The Python baseline provides a transparent, correctness-focused implementation of the original X-Wing paper construction.
2. The separate native C implementation provides a draft-11 implementation suitable for native API use and performance experiments.
3. OpenMP batch processing improves aggregate throughput for independent KEM operations.
4. The standalone NTT experiment shows the advantage of transform-based polynomial multiplication and demonstrates why batch-level parallelism can outperform stage-level parallelism for this workload.
5. Prepared key contexts are the most directly integrated native optimisation: they reduce repeated key preparation overhead while preserving fresh per-operation cryptographic work.
6. The adversarial and AES-GCM tests provide functional evidence that the tested modifications are detected in the end-to-end demonstration.
7. Timing and stress-test results are useful experimental evidence, but neither establishes formal security, constant-time behaviour or complete protocol security.

## 7. Reproducibility and result files

Run commands from the project root after configuring the OpenSSL 3.5 environment and building the CMake project.

```bash
# Original-paper Python baseline
python3 run_demo.py

# Python unit tests
python3 -m unittest discover -s tests -v

# Native correctness demo
./build/xwing_native_demo

# Local KEM + HKDF + AES-256-GCM demo
./build/xwing_secure_demo

# OpenMP batch KEM benchmark
./build/xwing_native_bench 1000

# Standalone NTT experiment
./build/ntt_lab 10000

# Prepared key-context experiment
./build/xwing_key_context_bench 2000

# Validate captured outputs
python3 testing/validate_outputs.py
```

Primary archived outputs:

| Output | Contents |
|---|---|
| `testing/results/paper-demo.log` | Original-paper baseline execution trace |
| `testing/results/python-tests.log` | Python unit-test results |
| `testing/results/kem-batch.csv` | OpenMP KEM throughput |
| `testing/results/ntt.csv` | NTT and OpenMP NTT measurements |
| `testing/results/key-context-benchmark.csv` | Baseline vs prepared-context measurements |
| `testing/results/adversarial-cases.csv` | Adversarial and AEAD tamper cases |
| `testing/results/decapsulation-timing.csv` | Per-sample timing data |
| `testing/results/decapsulation-timing-summary.log` | Timing summary and Welch t-statistics |
| `testing/results/native-roundtrip-stress.log` | Valid round-trip stress results |
| `testing/results/native-malformed-stress.log` | Malformed-input stress results |
| `testing/results/status.txt` | Archived build/test pipeline status |

---

## 8. Scope and limitations

- The baseline and native implementations target different X-Wing specifications and must be described separately.
- The Python baseline uses OpenSSL command-line subprocesses; its timings are not directly comparable to native EVP timings.
- The NTT experiment is standalone and does not accelerate OpenSSL's internal ML-KEM implementation.
- The benchmark results are environment-specific and should be repeated on controlled hardware before making broad performance claims.
- The timing experiment is not a proof of constant-time execution.
- The local secure demo does not authenticate peer identity or the recipient public key.
- The fixed-size native ciphertext API requires caller-side input-length validation.
- Functional tests and stress tests do not replace a formal cryptographic security analysis.


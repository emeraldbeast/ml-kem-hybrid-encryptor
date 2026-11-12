# X-Wing Project — Final Experiments Report

**Reporting period:** 4–10 November 2026  
**Primary test environment:** Ubuntu 22.04 under WSL 2, GCC 11.4.0, CMake 3.22.1, OpenMP 4.5, OpenSSL 3.5.5  
**Scope:** Functional validation, native performance, polynomial multiplication/NTT, OpenMP scaling, key-context reuse, adversarial inputs, and an AES-GCM application demonstration.

## Executive summary

The captured integration suite passed. The project demonstrated matching X-Wing shared secrets in its Python original-paper implementation and native draft-11 implementation, but those are separate version targets and are not claimed to interoperate with each other. The educational NTT improved single-thread polynomial throughput over the naive reference, and batch-level OpenMP improved throughput further; parallelizing stages of one small transform was slower. Reusing prepared native key objects reduced repeated encapsulation and decapsulation latency in a single 2,000-iteration run. The adversarial tests confirmed ML-KEM implicit rejection behavior, X25519 low-order rejection, AES-GCM tamper rejection, and clearing of unauthenticated plaintext. The timing samples showed no obvious mean separation among the three tested ciphertext classes, which is not proof of constant-time behavior.

---

## Experiment 1 — Version-specific X-Wing correctness and integration

### 1. Experiment

Validate the project’s original-paper baseline and native draft-11 implementation independently, then run the project integration suite.

### 2. What we did in this experiment

- Ran the Python original-paper implementation, which follows the paper’s Figure 12 construction and combiner ordering.
- Ran the native C draft-11 implementation and the separately labeled research hash-CT comparator.
- Ran Python unit tests, native demos, the secure-message demo, KEM and NTT benchmarks, dashboard health checks, and captured-output validation.

### 3. What were the results

- Python tests: **3 passed**.
- Original-paper implementation: ML-KEM component, X25519 component, and final hybrid shared-secret comparisons all matched.
- Native draft-11 round trip: **passed**, with matching 32-byte secrets.
- Research hash-CT comparator round trip: **passed**.
- Full integration run: **all recorded stages passed**, including configure/build and result validation.

### 4. What are the conclusions

The two implementations each pass their own functional checks. The original-paper baseline and draft-11 implementation use different construction details and key representations; these checks do **not** establish cross-version interoperability or agreement with an independent implementation. The hash-CT comparator is research-only and is not wire-compatible X-Wing.

**Evidence:** [integration status](testing/results/status.txt), [Python test log](testing/results/python-tests.log), [paper demo output](testing/results/paper-demo.log), [native demo output](testing/results/native-demo.log), [validation log](testing/results/validate-results.log).

---

## Experiment 2 — Original-paper component timing walkthrough

### 1. Experiment

Capture an end-to-end timing breakdown for the Python/OpenSSL CLI original-paper demonstration.

### 2. What we did in this experiment

The demo timed ML-KEM and X25519 key generation, encapsulation/decapsulation, and SHA3-256 combination while checking that sender and receiver component secrets and final hybrid secrets matched.

### 3. What were the results

One captured run reported:

| Step | Time (ms) |
|---|---:|
| ML-KEM key generation | 18.474 |
| X25519 key generation | 25.003 |
| ML-KEM encapsulation | 6.802 |
| Ephemeral X25519 key generation | 20.457 |
| X25519 DH during encapsulation | 6.007 |
| ML-KEM decapsulation | 5.904 |
| X25519 DH during decapsulation | 5.651 |
| SHA3-256 combination, encapsulation | 0.031 |
| SHA3-256 combination, decapsulation | 0.015 |
| Reported total round trip | 89.717 |

All component and hybrid secret checks passed.

### 4. What are the conclusions

This run illustrates that the hash-combination work is small beside key generation and the public-key operations. The Python demo invokes OpenSSL subprocesses, so its timings include process startup and file I/O. Treat these values as an educational walkthrough, not as a primitive-only benchmark or a direct comparison to the native API measurements.

**Evidence:** [paper demo output](testing/results/paper-demo.log).

---

## Experiment 3 — OpenMP scaling for independent X-Wing encapsulations

### 1. Experiment

Measure throughput as independent native encapsulations are distributed across OpenMP worker threads.

### 2. What we did in this experiment

The benchmark performed 1,000 independent encapsulations per mode at 1, 2, 4, and 8 threads. Each operation used fresh randomness. It measured the draft-11 mode and the separate research hash-CT comparator.

### 3. What were the results

| Mode | Threads | Operations/s | Speedup vs. 1 thread | Efficiency |
|---|---:|---:|---:|---:|
| Draft-11 | 1 | 5,286.08 | 1.000× | 100.0% |
| Draft-11 | 2 | 6,730.75 | 1.273× | 63.7% |
| Draft-11 | 4 | 13,035.73 | 2.466× | 61.7% |
| Draft-11 | 8 | 17,090.50 | 3.233× | 40.4% |
| Research hash-CT | 1 | 5,225.20 | 1.000× | 100.0% |
| Research hash-CT | 2 | 7,230.70 | 1.384× | 69.2% |
| Research hash-CT | 4 | 12,787.56 | 2.447× | 61.2% |
| Research hash-CT | 8 | 19,235.21 | 3.681× | 46.0% |

The run’s benchmark log reported GCC 11.4.0, OpenSSL 3.5.5, and 12 available OpenMP processors.

### 4. What are the conclusions

Independent encapsulations scaled to 8 threads in this run, reaching 3.233× draft-11 and 3.681× hash-CT throughput. Efficiency declined as thread count increased, which is consistent with parallel overhead and resource contention. This benchmark parallelizes separate KEM operations; it does not split a single encapsulation across threads. The hash-CT result is not a performance result for interoperable draft-11 X-Wing.

**Evidence:** [KEM batch CSV](testing/results/kem-batch.csv), [benchmark log](testing/results/kem-benchmark.log).

---

## Experiment 4 — Polynomial multiplication with NTT and parallel strategies

### 1. Experiment

Compare naive cyclic convolution with an optimized serial NTT, batch-level OpenMP, and stage-level OpenMP.

### 2. What we did in this experiment

The standalone NTT lab measured 10,000 operations on size-256 polynomials over the educational ring `F_12289[X]/(X^256 - 1)`. The optimized serial method used precomputed twiddles and Barrett reduction. The lab checked 16 deterministic input pairs against the naive reference before timing.

### 3. What were the results

| Method | Threads | Operations/s | Speedup vs. serial NTT |
|---|---:|---:|---:|
| Naive cyclic convolution | 1 | 8,189.53 | — |
| Serial NTT with precomputed twiddles | 1 | 51,511.28 | 1.000× |
| Batch-parallel NTT | 1 | 40,723.27 | 0.791× |
| Batch-parallel NTT | 2 | 67,445.10 | 1.309× |
| Batch-parallel NTT | 4 | 97,557.43 | 1.893× |
| Batch-parallel NTT | 8 | 127,953.46 | 2.484× |
| Stage-parallel NTT | 2 | 37,423.00 | 0.727× |
| Stage-parallel NTT | 4 | 27,955.83 | 0.543× |
| Stage-parallel NTT | 8 | 15,027.60 | 0.292× |

The serial NTT achieved **6.290×** the naive method’s throughput. The 8-thread batch-parallel result achieved **2.484×** serial NTT throughput.

### 4. What are the conclusions

Precomputed NTT arithmetic substantially outperformed the naive reference in this lab. Parallelizing a batch of independent transforms benefited from more available work, while parallelizing the stages of one small transform was slower than the serial NTT. Thread setup and synchronization outweighed the work available within a single size-256 transform. This lab uses a different ring from ML-KEM and is not connected to OpenSSL’s ML-KEM implementation.

**Evidence:** [NTT benchmark CSV](testing/results/ntt.csv), [NTT log](testing/results/ntt-benchmark.log), [raw NTT result](results/raw/ntt-10000.csv).

---

## Experiment 5 — Native X-Wing round-trip and malformed-input stress

### 1. Experiment

Exercise native valid round trips, API error paths, zeroization, low-order X25519 input, ML-KEM implicit rejection, and random malformed inputs.

### 2. What we did in this experiment

- Performed 30 key generations and 40 round trips per mode for both native modes.
- Checked null arguments, invalid modes, output clearing, low-order X25519 input, and ML-KEM ciphertext mutation.
- Separately attempted 5,000 random malformed decapsulations and 5,000 random public-key encapsulations.

### 3. What were the results

- **2,400/2,400** valid round trips matched.
- Invalid modes and null input checks behaved as expected; output-clearing checks passed.
- A low-order all-zero X25519 value was rejected and the output secret was cleared.
- A modified ML-KEM ciphertext followed implicit rejection: decapsulation returned a different hybrid secret rather than an API error.
- **10,000** random malformed-input attempts completed without a crash.

The saved project notes say the stress harnesses were run in an AddressSanitizer/UndefinedBehaviorSanitizer-enabled build; the retained logs do not include the full sanitizer build commands. These were targeted stress cases, not coverage-guided fuzzing.

### 4. What are the conclusions

The tested native error paths completed without crashing and followed the expected failure/implicit-rejection behavior. These finite tests do not establish exhaustive input coverage, memory safety for all inputs, or cryptographic security.

**Evidence:** [round-trip stress log](testing/results/native-roundtrip-stress.log), [malformed-input stress log](testing/results/native-malformed-stress.log), [stress harnesses](testing/stress-tests/).

---

## Experiment 6 — KEM-derived AES-256-GCM message protection

### 1. Experiment

Demonstrate how an X-Wing shared secret can feed HKDF-SHA256 and AES-256-GCM, then test authentication failures.

### 2. What we did in this experiment

The secure demo generated an X-Wing key pair, encapsulated and decapsulated, derived AES keys with HKDF-SHA256, and encrypted/decrypted a local message with AES-256-GCM. It then modified the encrypted message, authentication tag, and AES key. The decryption helper clears provisional plaintext if authentication fails.

### 3. What were the results

- Correct KEM-derived key, ciphertext, and tag: message authenticated and recovered.
- One-bit ciphertext modification: rejected.
- One-bit tag modification: rejected.
- Wrong AES key: rejected.
- On each authentication failure, the output buffer was cleared.

### 4. What are the conclusions

The local demo validates the KEM-to-HKDF-to-AEAD data flow and its fail-closed handling for these tamper cases. It does not authenticate a peer identity or public key and is not a replacement for a reviewed protocol such as TLS or HPKE.

**Evidence:** [secure demo log](testing/results/secure-aead-tamper.log).

---

## Experiment 7 — Prepared native key-context reuse

### 1. Experiment

Measure whether caching OpenSSL key objects reduces repeated native X-Wing operation latency.

### 2. What we did in this experiment

We compared the baseline API, which re-expands/imports key material for each operation, with prepared contexts that cache the recipient ML-KEM/X25519 public-key objects or recipient ML-KEM/X25519 private-key objects. The benchmark ran 2,000 iterations per row. Prepared context setup is excluded from `encaps`, `decaps`, and `repeated_exchange` timings, but included in `complete_handshake,per_key_context`. Every row checked sender/receiver shared-secret agreement. Fresh ephemeral X25519 randomness remained enabled on every encapsulation.

### 3. What were the results

| Operation | Baseline latency | Prepared latency | Speedup | Latency reduction |
|---|---:|---:|---:|---:|
| Encapsulate | 121.44 µs | 73.48 µs | 1.653× | 39.5% |
| Decapsulate | 139.94 µs | 58.44 µs | 2.395× | 58.2% |
| Repeated exchange | 249.21 µs | 133.62 µs | 1.865× | 46.4% |
| Complete handshake | 307.23 µs | 282.61 µs | 1.087× | 8.0% |

The measured throughput rose from 8,234 to 13,609 encapsulations/s, from 7,146 to 17,113 decapsulations/s, and from 4,013 to 7,484 repeated exchanges/s. Complete-handshake throughput rose from 3,255 to 3,538 handshakes/s. KeyGen was measured at 60.62 µs/op (16,497 ops/s). All correctness fields in the CSV were `PASS`.

The benchmark executable reported GCC 11.4.0 and OpenSSL 3.5.5. The captured environment file also contains a separate OpenSSL CLI loader error and a fallback to system OpenSSL 3.0.2; that CLI line is not the runtime version reported by the benchmark executable. The experiment runner was subsequently corrected to record the version reported by the benchmark.

### 4. What are the conclusions

In this one-run measurement, prepared contexts substantially reduced repeated Encaps and Decaps latency. The smaller complete-handshake gain is expected because that row includes key generation and context construction for every new key pair. These are preliminary single-run results without warm-up or repeated-trial statistics; repeat trials before making a general performance claim.

**Evidence:** [key-context results](testing/results/key-context-benchmark.csv), [benchmark runtime log](testing/results/key-context-benchmark.log), [environment capture](testing/results/experiment-environment.txt).

---

## Experiment 8 — Adversarial ciphertext behavior and timing investigation

### 1. Experiment

Check KEM ciphertext tampering, wrong-key behavior, AES-GCM authentication, output clearing, and whether the tested ciphertext classes show an obvious decapsulation timing difference.

### 2. What we did in this experiment

The functional cases covered valid ciphertext, one-bit and multiple-bit ML-KEM ciphertext changes, an X25519 public-value bit change, a different recipient private key, an all-zero low-order X25519 value, and AES-GCM ciphertext/tag/key tampering. The C API has a fixed-size ciphertext pointer and no length argument, so truncation cannot safely be tested through this API. For timing, the harness randomized the order of 5,000 valid, 5,000 ML-KEM-bit-flipped, and 5,000 X25519-bit-flipped decapsulation samples.

### 3. What were the results

| Input case | Decapsulation/authentication result | Shared secret / output handling |
|---|---|---|
| Valid KEM ciphertext and AES-GCM tag | Accepted | KEM secret matched; plaintext recovered |
| ML-KEM single-bit change | Decapsulation completed | Different hybrid secret; AES-GCM rejected; plaintext buffer cleared |
| ML-KEM multiple-bit changes | Decapsulation completed | Different hybrid secret; AES-GCM rejected; plaintext buffer cleared |
| X25519 public-value bit change | Decapsulation completed | Different hybrid secret; AES-GCM rejected; plaintext buffer cleared |
| Different recipient private key | Decapsulation completed | Different hybrid secret; AES-GCM rejected; plaintext buffer cleared |
| All-zero low-order X25519 value | Decapsulation rejected | Output secret cleared |
| Truncated ciphertext | Not testable through current API | Caller must validate ciphertext length before calling |
| AES-GCM ciphertext, tag, or key tampering | Authentication rejected | Output buffer cleared |

Timing summary (5,000 samples per class):

| Class | Mean | Median | Standard deviation |
|---|---:|---:|---:|
| Valid | 141.96 µs | 136.09 µs | 34.87 µs |
| ML-KEM bit-flipped | 141.80 µs | 136.61 µs | 34.62 µs |
| X25519 bit-flipped | 142.40 µs | 136.23 µs | 41.16 µs |

Welch t statistics were **0.228** for valid vs. ML-KEM-bit-flipped and **−0.584** for valid vs. X25519-bit-flipped.

### 4. What are the conclusions

The functional cases behaved as expected: ML-KEM mutations followed implicit rejection and produced a different hybrid secret; invalid low-order X25519 input caused explicit rejection; and the application layer rejected modified messages and cleared unauthenticated plaintext. The timing sample means and t statistics show no obvious separation among these three classes in this run. This is an exploratory result only: measurement noise, limited input classes, and the test environment prevent a constant-time conclusion or exclusion of timing leakage.

**Evidence:** [adversarial case results](testing/results/adversarial-cases.csv), [raw timing samples](testing/results/decapsulation-timing.csv), [timing summary](testing/results/decapsulation-timing-summary.log), [secure demo tamper output](testing/results/secure-aead-tamper.log).

---

## Overall conclusions and limitations

1. The project has passing functional evidence for its separate original-paper and native draft-11 implementations, with no cross-implementation interoperability claim.
2. The NTT and prepared-context experiments show useful performance gains for the measured workload, while stage-level parallelism on a small transform regresses.
3. The adversarial tests support the expected implicit-rejection, explicit low-order rejection, and AES-GCM fail-closed behaviors for the cases exercised.
4. The timing run did not reveal an obvious mean difference for its selected ciphertext classes, but it does not demonstrate constant-time behavior.
5. All performance CSVs are single-run observations. They lack repeated-trial confidence intervals and should be rerun with warm-up and multiple independent trials before publication.
6. No independent known-answer vectors, cross-library interoperability, formal verification, or cryptographic audit are included. The standalone NTT ring is not ML-KEM’s ring, and none of the measured prototype results establish production security.

The full integration run was captured on 8 November 2026. The new context-reuse and adversarial/timing run was captured on 10 November 2026 at 11:27 UTC with 2,000 key-context iterations and 5,000 timing rounds per class. See the linked raw evidence for exact values and outputs.

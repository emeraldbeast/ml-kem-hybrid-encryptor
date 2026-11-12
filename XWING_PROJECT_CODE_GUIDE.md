# X-Wing Project — Code & Viva Guide

**Purpose:** a compact guide to explain the problem, algorithm, repository, important code blocks, and the evidence in `testing/` during a professor's viva.

> **Line numbers:** all line references below match the submitted `Base File/` project ZIP. If you edit a file, line numbers may shift.

---

## 1. Problem statement: what are we solving?

A Key-Encapsulation Mechanism (KEM) lets two parties establish the same secret key over a public channel. Traditional elliptic-curve Diffie–Hellman (X25519) is fast and widely studied, but a sufficiently capable quantum computer threatens its security. ML-KEM-768 is designed to resist known classical and quantum attacks, but post-quantum schemes are comparatively newer and may face future cryptanalytic discoveries.

**X-Wing combines both components.** The goal is that the hybrid construction retains its intended security if either the classical or post-quantum component remains secure, subject to the paper's assumptions and correct implementation. It is not a claim that simply hashing any two secrets is automatically safe.

A KEM has three operations:

1. **KeyGen:** recipient creates a public key and a private key.
2. **Encaps:** sender uses the public key to create a ciphertext and a shared secret.
3. **Decaps:** recipient uses the private key and ciphertext to recover the same shared secret.

### Original paper's X-Wing flow (Python path)

- Generate ML-KEM-768 key pair `(sk1, pk1)`.
- Generate recipient X25519 secret `sk2` and public key `pk2`.
- Sender uses ML-KEM to create `(c1, k1)`.
- Sender creates ephemeral X25519 key material; `c2` is its public value and `k2 = DH(ephemeral_secret, pk2)`.
- Both sides derive `K = SHA3-256(label || k1 || k2 || c2 || pk2)`.
- Recipient recovers `k1` from `(sk1, c1)` and `k2` from `(sk2, c2)`, then hashes the same ordered input.

**Why is `c1` omitted from the paper's combiner?** The paper proves a ciphertext-second-preimage-resistance property (C2PRI) for ML-KEM-768 and uses it to justify omitting the large ML-KEM ciphertext in this *specific* construction. A generic KEM combiner must not copy this omission without its own proof.

### Paper's logical sizes

| Object | Size |
|---|---:|
| ML-KEM public key / private key | 1,184 / 2,400 B |
| X25519 private key / public key | 32 / 32 B |
| X-Wing public key / private key | 1,216 / 2,464 B |
| ML-KEM ciphertext / X25519 ciphertext | 1,088 / 32 B |
| Combined ciphertext | 1,120 B |
| Each component secret / final secret | 32 / 32 B |
| Combiner input | 134 B = 6 + 32 + 32 + 32 + 32 |

The paper's six-byte label is `\.//^\`, whose bytes are `5c 2e 2f 2f 5e 5c`.

---

## 2. First explain this important version boundary

This repository deliberately contains **two related but non-interoperable X-Wing paths**:

| Path | Code | What it implements |
|---|---|---|
| Original-paper baseline | `xwing/` + Python dashboard | Figure 12 construction: paper label first, then `k1 || k2 || c2 || pk2` |
| Native implementation | `native/src/xwing.c` | X-Wing Internet-Draft revision 11: seed expansion with SHAKE256 and draft-11 combiner ordering |

Their public-key and ciphertext sizes are similar, but the private-key representation and the combiner byte order differ. **Do not say the Python and C outputs are interoperable.** The `XWING_RESEARCH_HASH_CT` C mode is a separate research comparator, not standard X-Wing.

---

## 3. Repository map: why each folder/file exists

```text
Base File/
├── README.md, USER_GUIDE.md, RUNNING_INSTRUCTIONS.md
├── PROFESSOR_DEMO_GUIDE.md
├── X-Wing_Final_Project_Report.docx / .pdf
├── CMakeLists.txt, requirements.txt, .gitignore
├── run_demo.py, run_dashboard.py
├── xwing/                    # Original-paper Python implementation
├── dashboard/                # Local web UI and HTTP server
├── tests/                    # Small Python unittest suite
├── native/
│   ├── include/xwing/        # Public C API and byte-size constants
│   ├── src/                  # Native KEM, demos, benchmark
│   └── experiments/ntt/      # Standalone NTT/parallelism lab
├── scripts/                  # Plot CSV benchmark results
├── results/raw/               # Saved experiment CSV input data
├── testing/
│   ├── stress-tests/          # Extra C stress-test source
│   └── results/               # Logs, CSVs, test/benchmark evidence
└── docs/                      # Architecture, threat model, method and limits
```

| Folder/file | What to say when asked |
|---|---|
| `xwing/` | Python implementation of the original paper. Separates the cryptographic composition from OpenSSL command execution. |
| `dashboard/` | Browser presentation layer. The browser asks the Python server to run real crypto; JavaScript does not fake the algorithm. |
| `native/include/xwing/` | Public C header: sizes, mode identifiers, and functions exposed to other C files. |
| `native/src/` | Native draft-11 KEM implementation, local AEAD demo, simple round-trip demo, and OpenMP benchmark. |
| `native/experiments/ntt/` | Isolated educational NTT/number-theory experiment. It is not linked into ML-KEM. |
| `tests/` | Three quick Python unit/integration tests for the original-paper path. |
| `testing/` | Reproducible validation script, separate stress-test sources, result validation, test logs and benchmark CSV. |
| `testing/results/` | Evidence of what ran: exit statuses, stdout/stderr logs, dashboard health JSON and performance measurements. |
| `results/raw/` | Raw CSV inputs that can be used by the plotting script. |
| `scripts/` | Optional Python chart-generation code for KEM and NTT CSV data. |
| `docs/` | Supporting explanations: paper notes, architecture, version boundaries, threats, benchmarks, results and limitations. |
| `build/`, `testing/build/` | Generated CMake outputs, object files, executables and cached build state. These are not source modules; rebuild rather than relying on prebuilt binaries. |

Root files: `README.md` is the project overview; `USER_GUIDE.md` is user-facing usage; `RUNNING_INSTRUCTIONS.md` gives environment/build/run commands; `PROFESSOR_DEMO_GUIDE.md` is the presentation script; the IEEE-style DOCX/PDF is the formal report; `CMakeLists.txt` defines native build targets; `requirements.txt` states that Python uses only its standard library; `.gitignore` excludes generated files; `run_demo.py` launches one JSON CLI run; `run_dashboard.py` starts the browser dashboard.

---

## 4. Main implementation: original paper Python path

### A. `xwing/openssl_backend.py` — primitive adapter

This module does not invent ML-KEM or X25519. It asks OpenSSL to execute those standardized primitives.

| Lines | Code purpose / viva explanation |
|---|---|
| 1–8 | Docstring states this is an auditable teaching wrapper and not a production or constant-time benchmark implementation. |
| 12–17 | Imports subprocess, timers, dataclass, paths and typing utilities. |
| 20–27 | Defines a clear exception for OpenSSL failures and a result object holding elapsed milliseconds. |
| 29–32 | Backend class and X25519 DER/SPKI prefix used to recognize the public-key serialization format. |
| 34–61 | Runs `openssl version`, parses the version, and rejects versions older than 3.5 because this implementation needs OpenSSL ML-KEM support. |
| 63–83 | `run()` builds an argument list and calls `subprocess.run` **without a shell**; checks failures/timeouts and measures wall-clock time. |
| 85–94 | `generate_mlkem_keypair()` runs `genpkey -algorithm ML-KEM-768`, then exports the public key from the private-key file. |
| 96–113 | `mlkem_encapsulate()` passes the public key to `pkeyutl -encap`; reads the resulting ciphertext and sender secret. |
| 115–133 | `mlkem_decapsulate()` writes the received ciphertext to a temporary file and runs `pkeyutl -decap` using the recipient private key. |
| 135–165 | `generate_x25519_keypair()` generates an X25519 key pair and exports public DER. It checks the expected wrapper and extracts the final 32 raw public-key bytes. |
| 167–188 | `x25519_derive()` calls OpenSSL `pkeyutl -derive`, reads the shared secret and checks that it is exactly 32 bytes. |
| 191–195 | `fingerprint()` returns a short SHA-256 prefix for display; it is an identifier, not the shared secret itself. |

**If asked why use OpenSSL CLI:** it lets us use vetted primitive implementations while keeping our own code focused on the X-Wing composition. The trade-off is subprocess/file overhead, so these timings are not primitive-only timings.

### B. `xwing/paper_baseline.py` — the paper's actual composition

| Lines | Code purpose / viva explanation |
|---|---|
| 1–10 | States exactly which construction is implemented: ML-KEM-768 + direct X25519 DH + the paper's SHA3-256 combiner. |
| 14–23 | Imports hashing, randomness, temporary-directory, timer, platform and backend utilities. |
| 25–26 | Stores the exact six-byte paper label. |
| 28–43 | Defines expected logical key/ciphertext/secret sizes and calculates the 134-byte combiner length. |
| 46–53 | `_hash_combiner()` concatenates the fields in paper order, checks input length, hashes with SHA3-256 and records hash time. |
| 56–75 | `_step()` constructs a structured event for the dashboard: name, explanation, inputs, outputs, timing and status. |
| 77–89 | Starts a full run, initializes backend/timing/trace and creates a temporary directory. Temporary files are cleaned up when the context exits. |
| 91–119 | Recipient key generation: ML-KEM key pair first, then static X25519 key pair. The X25519 public bytes are retained for the combiner. |
| 121–133 | Sender runs ML-KEM encapsulation with `pk1`, obtaining ciphertext `c1` and secret `k1`. |
| 135–152 | Sender creates an ephemeral X25519 key. Its public key is `c2`; DH with recipient public key `pk2` produces `k2`. |
| 154–166 | Sender computes `SHA3-256(label || k1 || k2 || c2 || pk2)`. Notice `c1` is **not** in this paper combiner input. |
| 168–197 | Recipient decapsulates `c1` to recover `k1'`, then computes X25519 DH using its static private key and `c2` to recover `k2'`. |
| 199–211 | Recipient applies the identical combiner with the recovered secrets and the same public values. |
| 213–230 | Compares the ML-KEM secret, X25519 secret and final hybrid secret separately. If any mismatch occurs, the run fails. |
| 232–245 | Assembles ciphertext lengths and timing metrics for keygen, encapsulation, decapsulation, combiner and full round trip. |
| 247–293 | Returns the JSON report: runtime/version, sizes, checks, fingerprints, public previews, timings and explanatory notes. Raw private keys/shared secrets are not returned. |

**Core correctness statement:** `k1_sender == k1_receiver`, `k2_sender == k2_receiver`, and `K_sender == K_receiver` must all be true.

### C. CLI entry points

- `run_demo.py` lines 1–18 calls `run_original_paper_roundtrip()`, catches expected setup/runtime errors and prints the report as formatted JSON.
- `run_dashboard.py` lines 1–7 imports `serve()` and starts the dashboard when executed directly.
- `xwing/__init__.py` exports the main round-trip function so other modules can import it simply as `from xwing import ...`.

---

## 5. Dashboard: what happens when I click “Run actual handshake”?

### Backend: `dashboard/server.py`

- Lines 11–18 locate the project root, make it importable, import the real paper-roundtrip function and locate static assets.
- Lines 21–27 define the HTTP handler and keep terminal logging minimal.
- Lines 29–41 send HTTP responses and JSON, with content type, no-cache and browser security headers.
- Lines 43–72 handle GET requests: serve the HTML/CSS/JS, and `/api/health` checks that a suitable OpenSSL is available.
- Lines 74–96 handle POST `/api/run`: validate body size, run the real Python X-Wing operation, and return the JSON trace; errors become HTTP error responses.
- Lines 98–110 start a `ThreadingHTTPServer` on `127.0.0.1:8765` and stop cleanly on Ctrl+C.

### Frontend: `dashboard/static/`

- `index.html`: page structure, cards, fields and buttons. IDs such as `run-button`, `keygen-mlkem`, `encaps-x25519`, `decaps-mlkem`, `verify`, `timing-list` are hooks used by JavaScript.
- `app.css`: visual styling only—layout, cards, status colors, bars and responsive behavior. It does not perform cryptography.
- `app.js`: lines 1–21 obtains DOM elements and defines timing labels; 39–48 checks backend health; 60–86 renders algorithm steps; 88–131 draws timing bars; 133–170 displays fingerprints, sizes and PASS/FAIL checks; 172–200 sends POST `/api/run` and renders the returned real report; 202–223 resets the display; 225–237 exports JSON; 239–265 wires up buttons, copy controls and detail toggles.

**What to say:** the browser is a visualisation layer. The cryptographic work happens on the local Python/OpenSSL backend; JavaScript only requests it and displays the returned trace. The server is bound to localhost, not intended as a public service.

---

## 6. Native C implementation and demonstrations

### A. `native/include/xwing/xwing.h`

- Lines 1–4: include guard and fixed-width integer type.
- Lines 6–11: byte-size constants for seed, public key, ciphertext and shared secret; these define the fixed-size C interface.
- Lines 13–18: mode enum. `XWING_DRAFT11` is the native target; `XWING_RESEARCH_HASH_CT` is only a research comparison mode.
- Lines 20–26: public function declarations for key generation, encapsulation and decapsulation.

### B. `native/src/xwing.c`

This file is **draft-11 native C**, not the original-paper Python baseline.

| Lines | Code purpose / viva explanation |
|---|---|
| 1–8 | Imports the public API and OpenSSL EVP, random, parameter, memory-cleaning and byte-copy facilities. |
| 10 | Stores the six-byte domain-separation label. |
| 12–19 | `shake256()` uses EVP SHAKE256 to expand input into a requested number of output bytes. |
| 21–25 | `hash256()` computes SHA3-256 and checks for a 32-byte digest. |
| 27–42 | `mlkem_from_seed()` initializes an ML-KEM-768 EVP context, supplies the 64-byte ML-KEM seed parameter and generates the key object. |
| 44–51 | `x25519_public()` constructs an X25519 private-key object and derives the corresponding raw 32-byte public key. |
| 53–65 | `x25519_dh()` creates local/peer key objects and runs EVP key derivation to produce a 32-byte DH secret. |
| 67–85 | `expand()` runs SHAKE256 on the 32-byte X-Wing seed, splits 96 bytes into ML-KEM seed (64 B) and X25519 secret (32 B), derives both public-key components, and cleans temporary seed material. |
| 88–111 | `combine()` assembles bytes then hashes them. Draft-11 order is `ss_M || ss_X || ct_X || pk_X || label`. Research hash-CT adds the 1,088-byte ML-KEM ciphertext and is deliberately nonstandard. |
| 113–128 | `xwing_keygen()` creates a random 32-byte seed, expands it, then serializes `pk_M || pk_X`; clears sensitive/temporary buffers on exit/failure. |
| 130–161 | `xwing_encapsulate()` validates arguments/mode, imports the recipient ML-KEM public key, creates ephemeral X25519 material, derives the X25519 secret, performs ML-KEM encapsulation, appends the 32-byte X25519 public value to the 1,088-byte ML-KEM ciphertext, combines secrets, and cleans temporary buffers. |
| 163–184 | `xwing_decapsulate()` re-expands the recipient seed, decapsulates the ML-KEM part, derives X25519 secret from the final 32 ciphertext bytes, runs the same combiner, clears output on failure and cleans temporary secrets. |

`OPENSSL_cleanse()` is used to overwrite selected secret buffers before they leave scope. This is good hygiene, but it is not proof that every copy is erased from all process memory.

### C. Native demos

- `native/src/demo.c`: generates one native key pair; tests both draft-11 and research hash-CT mode; uses `CRYPTO_memcmp()` to compare 32-byte secrets; prints only whether they match; cleans secret arrays.
- `native/src/secure_demo.c`: `derive_aes_key()` (lines 10–22) uses HKDF-SHA256 to derive a 32-byte AES key from the KEM secret and a context string; `encrypt_gcm()` (24–38) uses a fresh 12-byte nonce and obtains a 16-byte tag; `decrypt_gcm()` (40–54) verifies the tag during GCM finalization; `main()` (56–77) runs draft-11 keygen/encaps/decaps, checks shared-secret equality, encrypts then decrypts a fixed message, checks recovered plaintext and cleans secrets.

**Important limitation:** the secure demo shows KEM key establishment followed by authenticated encryption of a message. It does not authenticate the recipient's public key or the identity of a peer; it is a single-process demonstration, not TLS or a complete secure network protocol.

---

## 7. DSA / Parallel Computing experiment code

### A. `native/experiments/ntt/ntt_lab.c`

This is a standalone teaching lab—not code used by ML-KEM in this project.

| Lines | What it does |
|---|---|
| 7–14 | Declares the ring/workload: cyclic convolution in `F_12289[X]/(X^256−1)`, length 256, 8 radix-2 stages. The comment explicitly says this is not ML-KEM's ring. |
| 16–20 | `ntt_plan` stores forward and inverse twiddle factors and inverse transform length. |
| 22–47 | Implements modular reduction, addition, subtraction and multiplication modulo 12,289. `reduce32()` uses Barrett reduction to avoid a general division in each modular multiplication. |
| 49–58 | `powq()` performs modular exponentiation by repeated squaring. |
| 60–81 | `plan_init()` calculates a transform root and inverse root, precomputes twiddle factors for each stage, and calculates `N⁻¹ mod Q` for inverse scaling. |
| 83–92 | `bit_reverse()` permutes coefficients into the order required by the iterative radix-2 transform. |
| 94–114 | `transform()` runs butterfly stages. Each butterfly combines two values using a twiddle factor; optional OpenMP distributes independent blocks within a stage. Inverse mode applies the inverse-length factor. |
| 116–125 | `multiply_naive()` is the O(N²) reference cyclic convolution. |
| 127–138 | `multiply_ntt()` copies inputs, transforms both, multiplies pointwise, inverse-transforms and copies the product out. |
| 140–150 | Parses operation count and generates deterministic test polynomials. |
| 153–169 | Initializes the plan and compares NTT output with naive output for 16 deterministic inputs; exits before benchmarking if any output differs. |
| 177–227 | Times naive multiplication, serial NTT, batch-level OpenMP and stage-level OpenMP; computes operations/second, speedup and efficiency; checksum prevents the work from being unused. |

**Critical viva distinction:** ML-KEM uses `Z_3329[X]/(X^256+1)` (negacyclic arithmetic). This lab uses `F_12289[X]/(X^256−1)` (cyclic arithmetic). It illustrates NTT and parallelism, but it does not replace, modify or benchmark ML-KEM's internal NTT.

### B. `native/src/benchmark.c`

- Lines 8–13: validates the optional operation count.
- Lines 15–29: sets up key buffers, generates one recipient key pair, and prints compiler/OpenSSL/processor metadata.
- Lines 30–53: loops over draft-11 and hash-CT modes; sweeps thread counts; `#pragma omp parallel for schedule(static)` distributes independent encapsulations. Each iteration owns its ciphertext and secret arrays, so iterations do not share those outputs. It measures wall time, throughput, speedup and efficiency.
- Lines 54–55: cleans the private seed and exits.

This benchmark measures **batch encapsulation throughput against one fixed recipient public key**, not network handshake latency or a full TLS server.

### C. `CMakeLists.txt`

- Lines 1–6: requires CMake 3.20 and configures strict C11.
- Lines 7–8: requires OpenSSL Crypto and OpenMP for C.
- Lines 10–12: builds `xwing_native` as a static library and links OpenSSL.
- Lines 13–18: builds the two demos and the native KEM benchmark.
- Lines 19–20: builds the isolated NTT lab with OpenMP.
- Lines 22–29: enables compiler warnings for MSVC or GCC/Clang.

---

## 8. Testing: know the difference between `tests/` and `testing/`

### A. `tests/test_xwing.py` — the three Python tests

| Lines | Test | What it proves |
|---|---|---|
| 9–16 | `test_paper_label_and_sizes` | Exact six-byte label and expected paper logical lengths, including 134-byte combiner input. |
| 18–20 | `test_backend_requires_mlkem_capable_openssl` | Installed OpenSSL is at least 3.5.0. |
| 22–38 | `test_real_xwing_roundtrip` | Runs actual paper-baseline crypto, checks ciphertext/combiner lengths, checks both component secrets and final secret match, and checks that raw secret/private-key fields are absent from report. |

Recorded result: **3 tests passed** (`testing/results/python-tests.log`). These are targeted unit/integration tests, not a security proof.

### B. `testing/run_all.sh` — the top-level validation runner

- Lines 1–10: Bash setup, project/result/build paths, and environment variables for the recorded private OpenSSL installation.
- Lines 11–12: creates the status log and a helper that runs a command, writes its output to a named log and records its exit code.
- Lines 13–19: checks dependencies, configures/builds with CMake, runs Python tests, original-paper CLI demo, native demo and AEAD demo.
- Lines 20–21: runs KEM batch and NTT benchmarks, saving CSV and stderr metadata.
- Lines 22–27: starts the dashboard temporarily, polls its `/api/health` endpoint, records success/failure, then stops it.
- Line 28: runs the captured-output validator.

Note: the script assumes OpenSSL is installed under `/opt/openssl-3.5`; adjust its PATH/library/pkg-config variables if your installation differs.

### C. `testing/validate_outputs.py`

It reads `status.txt`, verifies that required stages have exit code 0, parses the paper-demo JSON and checks all component/final-secret matches, checks the native and secure-demo success markers, checks dashboard health JSON, and verifies that KEM/NTT CSV files contain rows with positive durations. It validates captured evidence; it does not rerun the algorithms.

### D. `testing/stress-tests/` — additional C stress checks

- `native_roundtrip_stress.c`: repeats key generation and valid encapsulation/decapsulation across both native modes; compares secrets with `CRYPTO_memcmp`; also checks null pointers, invalid modes, cleared outputs, an all-zero X25519 point, and the ML-KEM implicit-rejection path.
- `native_malformed_input_stress.c`: feeds random malformed private-key/ciphertext buffers to decapsulation and random public-key buffers to encapsulation, checking that the calls complete without a crash.

**Do not say `testing/run_all.sh` runs these two stress programs.** The saved stress logs are separate artifacts; `testing/README.md` and `docs/testing-strategy.md` explicitly distinguish them from the main runner. They are targeted robustness/crash checks, not a coverage-guided fuzzing campaign.

### E. `testing/results/` — what each result file means

| File | Evidence/result |
|---|---|
| `status.txt` | All listed main stages recorded exit code 0, including validation. |
| `dependency-check.log` | Python 3.10.12, OpenSSL 3.5.5, ML-KEM-768 availability, CMake 3.22.1, GCC 11.4.0 and OpenMP support. |
| `configure.log`, `build.log` | CMake configure and native targets built successfully. |
| `python-tests.log` | All 3 Python tests passed. |
| `paper-demo.log` | Original paper baseline: ML-KEM match, X25519 match and final hybrid-secret match all `true`; 134-byte combiner input; 1,120-byte combined ciphertext. Saved full-run time was 88.726 ms in that run. |
| `native-demo.log` | Draft-11 and research hash-CT native round trips both reported matching 32-byte secrets. |
| `secure-demo.log` | Draft-11 → HKDF-SHA256 → AES-256-GCM test authenticated and recovered the fixed message. It also prints the peer-authentication limitation. |
| `dashboard-health.json`, `dashboard.log` | Local health endpoint returned `ok: true`; this is a health check, not an exhaustive browser/UI test. |
| `kem-batch.csv`, `kem-batch.log` | Eight rows for 1,000 encapsulations per configuration, with timings, throughput, speedup and efficiency. |
| `ntt.csv`, `ntt.log` | Nine rows for 10,000 polynomial multiplications; NTT reference check completed before timing; checksum and compiler/processor metadata recorded. |
| `native-roundtrip-stress.log` | 2,400 valid round trips passed (30 key pairs × 40 operations × 2 modes), plus the listed edge-case checks. |
| `native-malformed-stress.log` | 5,000 malformed decapsulation and 5,000 malformed encapsulation attempts completed without a crash. |

### F. How to explain the saved performance numbers

**KEM batch benchmark (1,000 encapsulations per configuration):**

- Draft-11: throughput rose from 4,625.09 ops/s (1 thread) to 15,087.54 ops/s (8 threads), with reported 3.2621× speedup and 0.4078 efficiency at 8 threads.
- Research hash-CT comparator: 3,865.04 ops/s (1 thread) to 16,653.35 ops/s (8 threads), with reported 4.3087× speedup and 0.5386 efficiency.

Do not conclude from this single run that hash-CT is inherently faster. It is one recorded run, and the results report itself cautions that these are initial baselines affected by WSL, system load and other noise.

**NTT benchmark (10,000 length-256 multiplications):**

- Naive cyclic convolution: 8,143.72 ops/s.
- Serial NTT with precomputed twiddles: 43,449.72 ops/s (5.3354× versus naive).
- Batch OpenMP: 122,727.54 ops/s at 8 threads (2.8246× versus serial NTT).
- Stage-level OpenMP: 9,425.98 ops/s at 8 threads (0.2169× versus serial NTT).

**Interpretation:** batching independent transforms gives useful parallel work. Parallelising each small transform stage repeatedly creates parallel-region/synchronization overhead that outweighs the work at N=256. This is a good result to discuss: parallelism is not automatically faster.

All measurements are single-run baselines. Do not call them publication-grade or compare subprocess-based Python timings with the paper's CPU-cycle measurements.

---

## 9. Likely professor questions — crisp answers

**Q: Why hybridise X25519 and ML-KEM?**  
A: To combine a well-studied classical component with a post-quantum component, reducing dependence on either one alone under the construction's security assumptions.

**Q: What is the difference between a KEM and encryption?**  
A: A KEM establishes shared key material. A symmetric cipher such as AES-GCM then uses derived key material to encrypt/authenticate application messages.

**Q: Why does the paper omit the ML-KEM ciphertext from the hash?**  
A: The paper proves ML-KEM-768's ciphertext second-preimage resistance and uses that property in the proof for this concrete combiner. It is not a generic rule for all KEMs.

**Q: Why are there Python and C versions?**  
A: Python preserves the original paper's Figure 12 construction for readability and dashboard visualisation. Native C separately implements draft-11 using OpenSSL EVP and is the path used for the OpenMP benchmark. They are not byte-interoperable.

**Q: Is the NTT code part of ML-KEM?**  
A: No. It is an isolated educational experiment using a different cyclic ring. It demonstrates transform algorithms and parallel overhead, not ML-KEM's exact polynomial arithmetic.

**Q: Does a matching round trip prove the scheme secure?**  
A: No. It proves functional agreement for tested inputs. IND-CCA security comes from the paper's formal argument under stated assumptions; implementation security needs separate vectors, interoperability, fuzzing, side-channel review and audit.

**Q: Does AES-GCM authenticate the other person?**  
A: No. GCM authenticates ciphertext under the derived key. The demo does not authenticate the recipient public key or peer identity.

**Q: Why is stage-parallel NTT slower?**  
A: The transform has only 256 coefficients. Repeated OpenMP parallel regions and synchronization cost more than the small amount of butterfly work. Batch-level parallelism amortises that overhead across independent multiplications.

---

## 10. Two report/presentation cautions

1. **IEEE report vs testing record:** the IEEE-style report's implementation/results section says no tests or measurements had been run while that report was prepared. However, `testing/REPORT.md` records a successful validation run dated 5 November 2026. Before submission, reconcile that wording—update the IEEE report's results section or clearly state the report was written before the later validation run. Do not leave contradictory claims in the submitted materials.
2. **Claims to avoid:** do not call this production-ready, audited, constant-time, a TLS implementation, peer-authenticated communication, or an ML-KEM NTT optimisation. The repository documentation explicitly lists these as limitations.

**One-sentence project summary to memorise:**  
*“We implement the original X-Wing paper construction in a Python/OpenSSL baseline, maintain a separate native C implementation of draft-11, and evaluate functional correctness plus independent KEM/NTT parallel workloads with recorded tests and benchmarks—while keeping experimental arithmetic separate from the cryptographic implementation.”*

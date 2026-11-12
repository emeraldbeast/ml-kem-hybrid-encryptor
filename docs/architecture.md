# Architecture and module responsibilities

There are now two separate KEM paths. The Python modules and dashboard preserve the original paper baseline. The native C library under `native/` targets X-Wing draft-11. Do not compare their key bytes or assume they interoperate.

## Data flow

```text
ML-KEM-768 KeyGen ──> pk1, sk1
                              \
                               \
X25519 KeyGen ──────> pk2, sk2  ──> Recipient public/private key tuples

Sender:
  ML-KEM Encaps(pk1) ──> c1, k1
  Ephemeral X25519 ─────> c2, k2
  SHA3-256(label || k1 || k2 || c2 || pk2) ──> K_sender

Recipient:
  ML-KEM Decaps(c1, sk1) ──> k1'
  X25519 DH(sk2, c2) ─────> k2'
  SHA3-256(label || k1' || k2' || c2 || pk2) ──> K_receiver

Correctness check: K_sender == K_receiver
```

## Boundaries

- The OpenSSL adapter knows how to invoke primitives and parse raw X25519 public bytes from their standard SubjectPublicKeyInfo wrapper.
- The paper-baseline module knows the ordering of the X-Wing operations and combiner fields, but not the details of invoking an external cryptographic process.
- The web server does not contain cryptographic composition logic; it triggers the core operation and sends a safe, JSON-serializable report to the browser.
- The browser is a view only. It never performs a fake local simulation and does not receive private keys or raw shared-secret values.

## Why use a subprocess adapter first?

For a first teaching milestone, OpenSSL's documented ML-KEM CLI provides a low-dependency path to actually execute ML-KEM, X25519 and hashing without writing the primitives ourselves. A subprocess is slower than a direct library call, but that is acceptable for a correctness-focused baseline. Later performance experiments should use direct APIs or a dedicated benchmark harness and should be kept separate from this code path.

## Error handling

- On startup, require OpenSSL 3.5 or newer, since ML-KEM support was added in OpenSSL 3.5.
- Fail the run if a subprocess fails, a result length is unexpected, or either component/shared-secret comparison fails.
- The HTTP server listens on localhost, does not accept user-controlled command arguments, and does not return raw secrets.

## Native and experiment paths

- `native/src/xwing.c` uses OpenSSL EVP for ML-KEM-768 and X25519, SHAKE256 key expansion, and SHA3-256 combination.
- `native/src/secure_demo.c` demonstrates the KEM followed by HKDF-SHA256 and AES-256-GCM. It remains a single-process demo with no peer authentication.
- `native/src/benchmark.c` measures batches of independent encapsulations with OpenMP.
- `native/experiments/ntt/ntt_lab.c` owns the teaching polynomial operations, NTT plan/twiddles, reduction method, and NTT parallel experiments. None of this code is linked into the KEM library.

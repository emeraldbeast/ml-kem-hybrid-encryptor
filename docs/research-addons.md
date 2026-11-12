# Research add-ons: papers and deployment practice

This shortlist extends the current paper-baseline + parallel-computing project without presenting deployment engineering as a new cryptographic construction. The original paper and the current X-Wing draft are separate targets. Keep the OS-metrics phase out of scope unless it is explicitly reintroduced.

## Recommended order

### 1. Interoperability and known-answer validation

Add deterministic key-generation and encapsulation vectors for each version, then compare the project with an independent implementation. Include malformed encodings, invalid ML-KEM public keys, low-order X25519 inputs, and error handling. Keep original-paper vectors separate from draft-11 vectors.

A dashboard round trip only shows that both sides of this implementation agree with each other. It does not establish interoperability or that the bytes match the specification.

References: [X-Wing draft 11, construction and vectors](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11), [Cloudflare CIRCL X-Wing implementation](https://github.com/cloudflare/circl/tree/main/kem/xwing), [BoringSSL X-Wing API](https://github.com/google/boringssl/blob/main/include/openssl/xwing.h).

### 2. Compare implementation backends

Add the same vector corpus for OpenSSL, Cloudflare CIRCL, and BoringSSL. Compare output compatibility, API shape, error behavior, and performance. This is a strong systems project because the libraries expose different interfaces and key object models.

Do not compare raw timings until you pin compiler, library revision, provider, CPU, thread configuration, and the exact operation boundaries.

### 3. TLS hybrid key-exchange compatibility study

Build a separate TLS experiment around standardized X25519MLKEM768 key shares. Measure ClientHello/ServerHello sizes, handshake latency, negotiation success, and fallback behavior through proxies and middleboxes. Do not place the standalone X-Wing KEM directly into a custom TLS handshake; follow the TLS hybrid group specification.

Deployment precedent: Chrome's earlier hybrid-KEM rollout found that some network middleboxes mishandled larger TLS messages. Cloudflare now describes probing origin support/preferences and selecting the post-quantum hybrid where available.

References: [IETF TLS ECDHE-MLKEM draft](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/), [Chrome hybrid Kyber deployment note](https://blog.chromium.org/2023/08/protecting-chrome-traffic-with-hybrid.html), [Cloudflare Automatic Key Exchange](https://blog.cloudflare.com/automatic-key-exchange-for-origins/).

### 4. Separate encryption from authentication

Extend the local KEM → HKDF → AES-GCM demo into a two-party client/server prototype using a pinned recipient public key, explicit message framing, nonce handling, and authenticated transcript/context. Demonstrate that changing the recipient key enables a man-in-the-middle attack unless the key is authenticated. Keep it a teaching demo, not a substitute for TLS/HPKE.

For a standards-oriented follow-up, compare the X-Wing KEM interface with HPKE and the TLS hybrid key schedule.

### 5. Implement ML-KEM's actual polynomial arithmetic as a separate lab

The current teaching NTT uses a convenient cyclic ring. A deeper follow-up is to study FIPS 203's degree-256 polynomial ring modulo 3329, including the specified NTT representation, modular reduction, and vectorized implementation. Validate each arithmetic layer against the specification before considering any optimized implementation; never replace the library's ML-KEM path with student code for real use.

Possible comparisons: schoolbook multiplication, the reference NTT, precomputed/fused twiddles, Barrett or Montgomery reduction, SIMD, batch OpenMP, and stage-level OpenMP.

Reference: [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

### 6. Add an implementation/deployment measurement report

Collect operation latency distributions, ciphertext/public-key sizes, TLS handshake success rates, and throughput under multiple worker counts. Record exact versions and hardware/toolchain. The X-Wing paper's cycle measurements are one baseline; production deployment also has packet-size, compatibility, and negotiation costs.

Reference: [Original X-Wing paper](https://eprint.iacr.org/2024/039).

### 7. Study post-quantum authentication separately

X-Wing protects key establishment; it does not make the server's certificate/signature post-quantum. A separate research section can map the certificate and signature migration problem, including larger signatures, certificate-chain size, and trust infrastructure. Keep this distinct from the KEM implementation.

Reference: [Chromium post-quantum HTTPS authentication roadmap](https://www.chromium.org/Home/chromium-security/post-quantum-auth-roadmap/).

## Best project-sized next milestone

The highest-value next deliverable is draft-specific known-answer and cross-library interoperability checks, followed by a TLS compatibility experiment. That first establishes bytes-on-the-wire correctness; the second demonstrates the engineering constraints browser/CDN deployments encounter.

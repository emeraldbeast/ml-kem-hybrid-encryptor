# Versioning and experiment boundaries

## Original paper baseline

The Python dashboard and `xwing/paper_baseline.py` follow Figure 12 of Barbosa et al.: separately generated ML-KEM and X25519 keys, the paper combiner ordering `label || ss_M || ss_X || ct_X || pk_X`, and 134-byte combiner input.

## Native X-Wing draft target

`native/src/xwing.c` targets [draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/11/), dated 23 September 2026. Its draft-defined combiner is `ss_M || ss_X || ct_X || pk_X || label`. The private seed/public key/ciphertext/shared-secret sizes are 32/1,216/1,120/32 bytes. The draft is not a finalized RFC and may change.

The native backend uses the OpenSSL 3.5+ ML-KEM EVP API documented in [OpenSSL's ML-KEM key-management manual](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/) and [ML-KEM KEM manual](https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/).

## Research hash-CT comparator

`XWING_RESEARCH_HASH_CT` puts the paper-era label-first fields in the hash and appends the ML-KEM ciphertext. This yields 1,222 bytes of combiner input for the performance comparison. It is a research variant, not draft-11 X-Wing and not wire-compatible with the Python paper baseline's private-key representation. Keep its results separately labeled.

## NTT experiments

The standalone NTT lab compares naive cyclic convolution with an iterative radix-2 NTT over `F_12289[X]/(X^256-1)`. It precomputes twiddles, uses Barrett modular reduction, and measures both batch-level and transform-stage OpenMP. The NTT code is not linked into either KEM and does not implement ML-KEM's `Z_3329[X]/(X^256+1)` arithmetic.

This project includes the previous proposed ideas: version pinning, original-paper and current-draft separation, ciphertext-hash comparison, KEM batch scaling, naive-versus-NTT experiments, OpenMP efficiency measurements, threat-model notes, and reproducibility guidance. The OS scheduling/counter layer remains outside the current scope.

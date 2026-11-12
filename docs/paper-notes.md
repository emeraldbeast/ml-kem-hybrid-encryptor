# Paper notes: original X-Wing construction

## Target

The implementation target is Figure 12 / Definition 8 in *X-Wing: The Hybrid KEM You've Been Looking For* (Barbosa et al.). It is intentionally not silently upgraded to another X-Wing draft revision.

## Algorithms in the paper

### KeyGen

1. Generate `(sk1, pk1)` with `ML-KEM-768.KeyGen`.
2. Generate a 32-byte X25519 private value `sk2`.
3. Derive `pk2 = X25519.DH(sk2, basepoint)`, the X25519 public key.
4. Return public key `(pk1, pk2)` and private tuple `(sk1, sk2, pk2)`.

### Encaps

1. Using `pk1`, obtain ML-KEM component secret `k1` and ciphertext `c1`.
2. Generate ephemeral X25519 private value `ske`.
3. Compute ephemeral public value `c2 = X25519.DH(ske, basepoint)`.
4. Compute `k2 = X25519.DH(ske, pk2)`.
5. Compute `K = SHA3-256(label || k1 || k2 || c2 || pk2)`.
6. Return hybrid secret `K` and ciphertext `(c1, c2)`.

### Decaps

1. Parse ciphertext `(c1, c2)`.
2. Compute `k1 = ML-KEM-768.Dec(c1, sk1)`.
3. Compute `k2 = X25519.DH(sk2, c2)`.
4. Compute `K = SHA3-256(label || k1 || k2 || c2 || pk2)`.
5. Return `K`.

The six-byte ASCII label is `\\.//^\\` as a Python bytes literal (actual bytes: `5c 2e 2f 2f 5e 5c`).

## Why the paper's combiner input is 134 bytes

`6-byte label + 32-byte ML-KEM secret + 32-byte X25519 secret + 32-byte X25519 ciphertext + 32-byte recipient X25519 public key = 134 bytes`.

The 1,088-byte ML-KEM ciphertext is deliberately not in this input in the original construction. The paper proves the relevant ciphertext-second-preimage property for ML-KEM and uses it to justify this specific design.

## What this repository proves experimentally

A successful run provides functional evidence that the installed primitives work together as expected for a generated valid ciphertext: both component secrets match, both combiner inputs are 134 bytes, and the final 32-byte secrets match. This does not constitute a proof of IND-CCA security and does not independently validate the cryptographic library.

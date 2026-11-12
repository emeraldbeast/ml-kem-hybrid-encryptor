# Threat model and limitations

X-Wing is a key-encapsulation mechanism, not an authenticated protocol or message-encryption scheme. These implementations do not authenticate the recipient's public key, prevent key substitution, provide replay protection, or define application key derivation and nonce management. A real application needs an authenticated protocol and authenticated encryption.

The Python dashboard binds only to localhost and returns secret fingerprints rather than raw secrets. Temporary files and subprocesses are not a formal secure-erasure guarantee. The native C API uses fixed-size pointer arguments without explicit buffer lengths and returns a generic failure status. Neither path has independent security review, side-channel review, fuzzing, or interoperability validation in this delivery. Do not use this educational project to protect real data.

The NTT experiment is isolated from ML-KEM. It demonstrates arithmetic and parallel-performance tradeoffs; it is not a security implementation of ML-KEM polynomial arithmetic.

# Benchmark methodology

`xwing_native_bench` executes independent encapsulations against one recipient public key. Each operation uses fresh randomness and separate output buffers. It reports wall time, throughput, speedup `S_p = T_1 / T_p`, and efficiency `E_p = S_p / p` over power-of-two OpenMP worker counts.

The hash-CT mode adds the 1,088-byte ML-KEM ciphertext to the SHA3-256 input. This measures hash-input work in this prototype; it is a research comparator, not interoperable X-Wing and not evidence about the security proof.

`ntt_lab` compares naive cyclic convolution with an iterative NTT and includes precomputed twiddles, Barrett reduction, batch parallelism, and stage parallelism. It checks 16 deterministic input pairs against the naive reference before timing. Stage synchronization can outweigh useful work on a short transform. Its ring is educational and is not ML-KEM's arithmetic ring.

Captured single-run values are in `../testing/results/kem-batch.csv` and `../testing/results/ntt.csv`, with environment details and interpretation in `../testing/REPORT.md`. These are initial observations from one WSL environment, not publication-quality statistics. For stronger claims, repeat after warm-up, preserve raw CSV, record CPU/compiler/flags/OpenSSL/OpenMP versions and thread settings, and report medians and spread.
# Results and limitations

The captured integration run and targeted stress checks are summarized in [`../testing/REPORT.md`](../testing/REPORT.md). They provide functional evidence for the tested operations and basic failure handling; they do not establish cryptographic security or interoperability.

The Python dashboard implements the original paper construction. The native C implementation targets X-Wing draft-11. The hash-CT mode is a research-only comparator and is not interoperable X-Wing. The NTT lab uses an educational ring distinct from ML-KEM and is not connected to OpenSSL's ML-KEM implementation.

The available KEM and NTT benchmark CSVs are single-run observations from Ubuntu 22.04 under WSL 2. They are not publication-quality statistics. The dashboard invokes OpenSSL subprocesses, so its displayed durations include process startup and file I/O. The OpenMP KEM workload parallelizes independent encapsulations rather than splitting one KEM operation across workers.

The current runner has been updated for unique build output and accurate failure status, but that updated runner has not yet been run. No independent known-answer vector comparison, cross-implementation interoperability test, cryptographic audit, formal verification, or constant-time analysis is included. The project is an educational/research prototype and should not be used as production cryptography.
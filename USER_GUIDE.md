# X-Wing Project User Guide

## What this project demonstrates

There are two separate paths. The Python dashboard and CLI show the original X-Wing paper construction using OpenSSL command-line tools. Native C targets X-Wing draft-11 through OpenSSL EVP. They have similar sizes but different encoding/key derivation and are not interoperable. The research hash-CT mode is a comparator only.

## Start the interactive dashboard

From Ubuntu WSL:

    cd "/mnt/c/Users/Dhananjay/OneDrive/Attachments/Desktop/Cryptography SOP/Base File"
    export PATH=/opt/openssl-3.5/bin:$PATH
    export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:/opt/openssl-3.5/lib
    python3 run_dashboard.py

Open http://127.0.0.1:8765 and select Run actual handshake. Stop the server with Ctrl+C. It listens on localhost only.

## What changes during a dashboard run

1. The backend creates recipient ML-KEM-768 and X25519 keys.
2. The sender creates the ML-KEM ciphertext and secret, then a fresh ephemeral X25519 public key and DH secret.
3. The paper path combines both secrets and the paper transcript fields with SHA3-256.
4. The recipient decapsulates both components and independently derives its combined secret.
5. The backend checks equality of the two 32-byte secrets.

Watch the step status, component sizes, elapsed times, public ciphertext previews, and secret fingerprints. The UI never displays private keys or raw shared secrets. Python timings include OpenSSL process startup and file I/O.

## Command-line experiences

From the project root, with the OpenSSL environment above:

- python3 run_demo.py prints a JSON trace of the original-paper path, checks, sizes, and timings.
- testing/run_all.sh builds and runs the test suite; artifacts go under testing/results/.
- The testing runner prints the unique build directory; run its xwing_native_demo for draft-11 and the research comparator.
- Run xwing_secure_demo to see draft-11 followed by HKDF-SHA256 and AES-256-GCM.
- Run xwing_native_bench 1000 for KEM encapsulation throughput and OpenMP scaling.
- Run ntt_lab 10000 for the teaching NTT reference check and parallel experiments.

The detailed test plan and run report are testing/README.md and testing/REPORT.md.

## How to read what changes

- testing/results/status.txt lists run stages and exit codes.
- testing/results/*.log contains build, test, demo, and environment output.
- testing/results/kem-batch.csv records KEM throughput, speedup, and efficiency.
- testing/results/ntt.csv compares naive convolution, serial NTT, batch OpenMP, and stage OpenMP.
- Secret values are not printed. Demo success messages say when sender and receiver secrets match.
- Compare one-thread and multi-thread rows from the same run. Repeat runs and compare medians and spread before drawing performance conclusions.

## Limits

The hash-CT mode is not interoperable standard X-Wing. The NTT lab uses a teaching ring, not ML-KEM arithmetic. The secure demo does not authenticate a peer or recipient key. This is educational research software, not production cryptography.
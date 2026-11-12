# Running instructions

This guide covers the Python original-paper dashboard/CLI and the native C/OpenMP programs. The project is an educational research prototype, not production cryptography.

## Dependencies

- Python 3.10 or newer.
- OpenSSL 3.5 or newer with ML-KEM-768 in the default provider.
- CMake 3.20 or newer.
- GCC 11+ with OpenMP on Ubuntu/WSL, or another C11 compiler and OpenMP runtime supported by CMake.
- OpenSSL development headers and `libcrypto` for the native programs.
- A browser for the local dashboard.

The recorded environment was Ubuntu 22.04 in WSL 2, Python 3.10.12, OpenSSL 3.5.5, CMake 3.22.1, GCC 11.4.0, and OpenMP 4.5. If using a private OpenSSL installation, use the same prefix at configure and runtime.

## Configure OpenSSL on Ubuntu/WSL

For an OpenSSL 3.5 installation at `/opt/openssl-3.5`:

```bash
export OPENSSL_PREFIX=/opt/openssl-3.5
export PATH="$OPENSSL_PREFIX/bin:$PATH"
export LD_LIBRARY_PATH="$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PKG_CONFIG_PATH="$OPENSSL_PREFIX/lib64/pkgconfig:$OPENSSL_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
```

Check versions and the ML-KEM provider:

```bash
python3 --version
openssl version
openssl list -kem-algorithms | grep -i ML-KEM-768
cmake --version | head -1
gcc --version | head -1
pkg-config --modversion openssl
```

The `openssl` command and the libraries found by CMake/runtime must refer to the same OpenSSL 3.5 installation. Do not replace Ubuntu's system OpenSSL to configure a private prefix.

## Run the Python paper-baseline dashboard

From the project root (the directory containing `CMakeLists.txt` and `run_dashboard.py`):

```bash
python3 run_dashboard.py
```

Open <http://127.0.0.1:8765> and choose **Run actual handshake**. This executes the original paper construction locally through OpenSSL CLI processes; the dashboard is bound to localhost. Stop the server with Ctrl+C. Displayed timings include process startup and file I/O.

For a one-shot JSON run:

```bash
python3 run_demo.py
```

## Build and run native programs

Configure and build from source:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX"
cmake --build build --parallel
```

Run the native draft-11 and research comparator round trips, then the local derived-key demo:

```bash
./build/xwing_native_demo
./build/xwing_secure_demo
```

The second demo uses HKDF-SHA256 and AES-256-GCM after draft-11 key establishment. It is single-process and does not authenticate peer identity or implement a network protocol.

## Run benchmarks

KEM batch encapsulation benchmark (optional argument: operations per configuration):

```bash
./build/xwing_native_bench 1000
```

NTT workload (optional argument: multiplications per configuration):

```bash
./build/ntt_lab 10000
```

The KEM benchmark distributes independent encapsulations across OpenMP workers. The NTT lab verifies against its naive reference before reporting timings. Its educational ring is different from ML-KEM's ring and is not linked into the KEM implementation. Both programs emit CSV to standard output. Results from a single run are exploratory; preserve raw output and repeat runs before making performance claims.

## Run the automated project checks

From the project root:

```bash
bash testing/run_all.sh
```

The runner checks dependencies, configures/builds in a unique directory below `testing/results/`, runs the Python and native demos, captures KEM and NTT benchmark CSVs, checks dashboard health, and validates outputs. It writes or overwrites the standard logs and CSVs under `testing/results/`. Back them up first if you want to preserve the currently included measurements. By default it uses `/opt/openssl-3.5`; to use another private prefix:

```bash
export OPENSSL_PREFIX=/path/to/openssl-3.5
bash testing/run_all.sh
```

The command exits nonzero if a stage or output validation fails. The runner does not regenerate the saved sanitizer stress logs. See [`testing/REPORT.md`](testing/REPORT.md) for dates, results, and limitations.

## Tests independently

Python unit tests:

```bash
python3 -m unittest discover -s tests -v
```

The native executable checks its round trips when run. `ntt_lab` compares its output with the naive reference before timing. The separate stress harness sources and captured logs are under `testing/stress-tests/` and `testing/results/`.

## Troubleshooting

- If the wrong OpenSSL version is used, reapply the environment exports and confirm `which openssl`, `openssl version`, and `pkg-config --modversion openssl`.
- If an executable cannot find `libcrypto.so.3`, set `LD_LIBRARY_PATH` to the matching OpenSSL 3.5 `lib`/`lib64` directory.
- If OpenMP is unavailable, install/use a compiler toolchain with OpenMP support and confirm CMake reports OpenMP found. The Python dashboard does not require OpenMP.
- If dashboard port 8765 is occupied, stop the earlier local dashboard process and restart it.

For a timed presentation runbook with expected outputs and fallback steps, see [`PROFESSOR_DEMO_GUIDE.md`](PROFESSOR_DEMO_GUIDE.md).
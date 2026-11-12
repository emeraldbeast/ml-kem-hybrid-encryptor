"""Small, auditable wrappers around OpenSSL 3.5+ command-line operations.

The 
cryptographic operations themselves are performed by OpenSSL. This module
uses temporary PEM/binary files because the OpenSSL CLI offers a convenient,
inspectable ML-KEM KEM interface. It is intended for a local teaching prototype,
not a production service or a constant-time benchmark harness.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class OpenSSLCommandError(RuntimeError):
    """Raised when an OpenSSL subprocess fails."""


@dataclass(frozen=True)
class CommandResult:
    elapsed_ms: float


class OpenSSLBackend:
    """Invoke the installed OpenSSL command safely without a shell."""

    X25519_SPKI_PREFIX = bytes.fromhex("302a300506032b656e032100")

    def __init__(self, executable: str = "openssl") -> None:
        self.executable = executable
        try:
            completed = subprocess.run(
                [self.executable, "version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OpenSSLCommandError(
                "OpenSSL was not found. Install OpenSSL 3.5 or newer and ensure "
                "the 'openssl' command is on PATH."
            ) from exc

        self.version_text = completed.stdout.strip()
        match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", self.version_text)
        if not match:
            raise OpenSSLCommandError(
                f"Could not parse OpenSSL version: {self.version_text!r}"
            )
        self.version = tuple(int(part) for part in match.groups())
        if self.version < (3, 5, 0):
            raise OpenSSLCommandError(
                f"OpenSSL 3.5.0 or newer is required for ML-KEM-768; found "
                f"{self.version_text}."
            )

    def run(self, args: Sequence[str], *, timeout: int = 30) -> CommandResult:
        command = [self.executable, *args]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                check=True,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.decode("utf-8", errors="replace").strip()
            safe_command = " ".join(command[:4])
            raise OpenSSLCommandError(
                f"OpenSSL command failed ({safe_command} ...). "
                f"OpenSSL reported: {detail or 'no diagnostic'}"
            ) from exc
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OpenSSLCommandError(f"Could not run OpenSSL command: {exc}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return CommandResult(elapsed_ms=elapsed_ms)

    def generate_mlkem_keypair(self, directory: Path) -> tuple[Path, Path, float]:
        secret_key = directory / "mlkem768-secret.pem"
        public_key = directory / "mlkem768-public.pem"
        started = time.perf_counter()
        self.run(["genpkey", "-algorithm", "ML-KEM-768", "-out", str(secret_key)])
        self.run(
            ["pkey", "-in", str(secret_key), "-pubout", "-out", str(public_key)]
        )
        elapsed = (time.perf_counter() - started) * 1000.0
        return secret_key, public_key, elapsed

    def mlkem_encapsulate(
        self, public_key: Path, directory: Path
    ) -> tuple[bytes, bytes, float]:
        ciphertext = directory / "mlkem768-ciphertext.bin"
        shared_secret = directory / "mlkem768-sender-secret.bin"
        result = self.run(
            [
                "pkeyutl",
                "-encap",
                "-inkey",
                str(public_key),
                "-out",
                str(ciphertext),
                "-secret",
                str(shared_secret),
            ]
        )
        return ciphertext.read_bytes(), shared_secret.read_bytes(), result.elapsed_ms

    def mlkem_decapsulate(
        self, secret_key: Path, ciphertext_bytes: bytes, directory: Path
    ) -> tuple[bytes, float]:
        ciphertext = directory / "mlkem768-ciphertext-for-decapsulation.bin"
        shared_secret = directory / "mlkem768-recipient-secret.bin"
        ciphertext.write_bytes(ciphertext_bytes)
        result = self.run(
            [
                "pkeyutl",
                "-decap",
                "-inkey",
                str(secret_key),
                "-in",
                str(ciphertext),
                "-secret",
                str(shared_secret),
            ]
        )
        return shared_secret.read_bytes(), result.elapsed_ms

    def generate_x25519_keypair(
        self, name: str, directory: Path
    ) -> tuple[Path, Path, bytes, float]:
        secret_key = directory / f"{name}-secret.pem"
        public_key = directory / f"{name}-public.pem"
        public_der = directory / f"{name}-public.der"
        started = time.perf_counter()
        self.run(["genpkey", "-algorithm", "X25519", "-out", str(secret_key)])
        self.run(
            ["pkey", "-in", str(secret_key), "-pubout", "-out", str(public_key)]
        )
        self.run(
            [
                "pkey",
                "-in",
                str(secret_key),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(public_der),
            ]
        )
        der = public_der.read_bytes()
        if len(der) != 44 or not der.startswith(self.X25519_SPKI_PREFIX):
            raise OpenSSLCommandError(
                "Unexpected X25519 SubjectPublicKeyInfo encoding from OpenSSL."
            )
        raw_public = der[-32:]
        elapsed = (time.perf_counter() - started) * 1000.0
        return secret_key, public_key, raw_public, elapsed

    def x25519_derive(
        self, private_key: Path, peer_public_key: Path, directory: Path, name: str
    ) -> tuple[bytes, float]:
        shared_secret = directory / f"{name}-shared-secret.bin"
        result = self.run(
            [
                "pkeyutl",
                "-derive",
                "-inkey",
                str(private_key),
                "-peerkey",
                str(peer_public_key),
                "-out",
                str(shared_secret),
            ]
        )
        secret = shared_secret.read_bytes()
        if len(secret) != 32:
            raise OpenSSLCommandError(
                f"X25519 produced {len(secret)} bytes; expected 32."
            )
        return secret, result.elapsed_ms


def fingerprint(data: bytes, length: int = 16) -> str:
    """Return a short, non-secret identifier for displaying in the dashboard."""
    import hashlib

    return hashlib.sha256(data).hexdigest()[:length]

"""The original paper's X-Wing construction (Figure 12).

Construction:
  * ML-KEM-768 for the post-quantum component
  * X25519 directly as a Diffie-Hellman component
  * SHA3-256(label || k1 || k2 || c2 || pk2) as the combiner

This is deliberately the paper baseline, not a generic combiner and not a
claim of interoperability with a later X-Wing Internet-Draft revision.
"""

from __future__ import annotations

import hashlib
import platform
import secrets
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .openssl_backend import OpenSSLBackend, fingerprint

# Six ASCII bytes exactly as specified in the original paper.
XWING_LABEL = b"\\.//^\\"

# Logical raw sizes for the paper's selected parameter set.
SIZES = {
    "mlkem_public_key": 1184,
    "mlkem_private_key": 2400,
    "x25519_private_key": 32,
    "x25519_public_key": 32,
    "xwing_public_key": 1216,
    "xwing_private_key": 2464,
    "mlkem_ciphertext": 1088,
    "x25519_ciphertext": 32,
    "xwing_ciphertext": 1120,
    "component_shared_secret": 32,
    "hybrid_shared_secret": 32,
    "combiner_label": len(XWING_LABEL),
    "combiner_input": 6 + 32 + 32 + 32 + 32,
}


def _hash_combiner(k1: bytes, k2: bytes, c2: bytes, pk2: bytes) -> tuple[bytes, bytes, float]:
    material = XWING_LABEL + k1 + k2 + c2 + pk2
    if len(material) != SIZES["combiner_input"]:
        raise ValueError(f"Unexpected X-Wing combiner input length: {len(material)}")
    hash_started = time.perf_counter()
    digest = hashlib.sha3_256(material).digest()
    elapsed_ms = (time.perf_counter() - hash_started) * 1000.0
    return digest, material, elapsed_ms


def _step(
    step_id: str,
    title: str,
    short: str,
    elapsed_ms: float,
    inputs: list[str],
    outputs: list[str],
    explanation: str,
) -> dict[str, Any]:
    return {
        "id": step_id,
        "title": title,
        "short": short,
        "elapsed_ms": round(elapsed_ms, 3),
        "inputs": inputs,
        "outputs": outputs,
        "explanation": explanation,
        "status": "complete",
    }


def run_original_paper_roundtrip() -> dict[str, Any]:
    """Perform a real ephemeral X-Wing keygen/encaps/decaps round trip.

    The output deliberately omits private keys and raw shared secrets. Only
    short SHA-256 fingerprints are returned to the dashboard for comparison.
    Temporary files are deleted by TemporaryDirectory when this function exits.
    """
    backend = OpenSSLBackend()
    total_started = time.perf_counter()
    steps: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="xwing-paper-baseline-") as temp_name:
        directory = Path(temp_name)

        # KeyGen: ML-KEM-768 key pair.
        mlkem_sk, mlkem_pk, keygen_mlkem_ms = backend.generate_mlkem_keypair(directory)
        steps.append(
            _step(
                "keygen-mlkem",
                "Generate ML-KEM-768 keys",
                "POST-QUANTUM KEYGEN",
                keygen_mlkem_ms,
                ["OpenSSL RNG"],
                ["pk₁: 1,184 B", "sk₁: 2,400 B"],
                "Generate the lattice-based KEM key pair used by the post-quantum branch.",
            )
        )

        # KeyGen: X25519 recipient key pair.
        x_sk, x_pk, pk2, keygen_x25519_ms = backend.generate_x25519_keypair(
            "recipient-x25519", directory
        )
        steps.append(
            _step(
                "keygen-x25519",
                "Generate recipient X25519 keys",
                "CLASSICAL KEYGEN",
                keygen_x25519_ms,
                ["OpenSSL RNG", "X25519 base point"],
                ["sk₂: 32 B", "pk₂: 32 B"],
                "Generate the classical static X25519 key pair. The public key pk₂ is included in the combiner input.",
            )
        )

        # Enc: ML-KEM encapsulation.
        ml_ct, k1_sender, encaps_mlkem_ms = backend.mlkem_encapsulate(mlkem_pk, directory)
        steps.append(
            _step(
                "encaps-mlkem",
                "Encapsulate with ML-KEM-768",
                "POST-QUANTUM ENCAPSULATION",
                encaps_mlkem_ms,
                ["pk₁"],
                ["c₁: 1,088 B", "k₁: 32 B"],
                "The ML-KEM sender creates the first ciphertext component and its 32-byte shared secret.",
            )
        )

        # Enc: ephemeral X25519 and DH with the recipient's static public key.
        eph_sk, eph_pk, c2, eph_keygen_ms = backend.generate_x25519_keypair(
            "ephemeral-x25519", directory
        )
        k2_sender, encaps_dh_ms = backend.x25519_derive(
            eph_sk, x_pk, directory, "sender-x25519"
        )
        steps.append(
            _step(
                "encaps-x25519",
                "Create the X25519 ciphertext and secret",
                "CLASSICAL ENCAPSULATION",
                eph_keygen_ms + encaps_dh_ms,
                ["pk₂", "ephemeral randomness"],
                ["c₂: 32 B", "k₂: 32 B"],
                "The ephemeral public key is c₂. X25519 Diffie–Hellman gives k₂ = DH(ske, pk₂).",
            )
        )

        # Enc: original paper's combiner; intentionally excludes c1.
        k_sender, sender_material, sender_hash_ms = _hash_combiner(k1_sender, k2_sender, c2, pk2)
        steps.append(
            _step(
                "encaps-combine",
                "Combine the component secrets",
                "SHA3-256 COMBINER",
                sender_hash_ms,
                ["label: 6 B", "k₁: 32 B", "k₂: 32 B", "c₂: 32 B", "pk₂: 32 B"],
                ["K_sender: 32 B", f"input: {len(sender_material)} B"],
                "Compute SHA3-256(label || k₁ || k₂ || c₂ || pk₂). The original construction does not include the 1,088-byte ML-KEM ciphertext c₁ here.",
            )
        )

        # Dec: recover each component secret.
        k1_receiver, decap_mlkem_ms = backend.mlkem_decapsulate(
            mlkem_sk, ml_ct, directory
        )
        steps.append(
            _step(
                "decaps-mlkem",
                "Decapsulate ML-KEM-768",
                "POST-QUANTUM DECAPSULATION",
                decap_mlkem_ms,
                ["sk₁", "c₁: 1,088 B"],
                ["k₁′: 32 B"],
                "The recipient recovers the ML-KEM component secret from its private key and c₁.",
            )
        )

        k2_receiver, decap_dh_ms = backend.x25519_derive(
            x_sk, eph_pk, directory, "recipient-x25519"
        )
        steps.append(
            _step(
                "decaps-x25519",
                "Recover the X25519 shared secret",
                "CLASSICAL DECAPSULATION",
                decap_dh_ms,
                ["sk₂", "c₂: 32 B"],
                ["k₂′: 32 B"],
                "The recipient computes k₂′ = DH(sk₂, c₂). This should equal the sender's k₂.",
            )
        )

        # Dec: same combiner inputs in the same order.
        k_receiver, receiver_material, receiver_hash_ms = _hash_combiner(k1_receiver, k2_receiver, c2, pk2)
        steps.append(
            _step(
                "decaps-combine",
                "Derive the recipient's hybrid secret",
                "SHA3-256 COMBINER",
                receiver_hash_ms,
                ["label: 6 B", "k₁′: 32 B", "k₂′: 32 B", "c₂: 32 B", "pk₂: 32 B"],
                ["K_receiver: 32 B", f"input: {len(receiver_material)} B"],
                "The recipient hashes the same ordered fields to derive K_receiver.",
            )
        )

        mlkem_match = k1_sender == k1_receiver
        x25519_match = k2_sender == k2_receiver
        hybrid_match = k_sender == k_receiver
        steps.append(
            {
                "id": "verify",
                "title": "Verify shared-secret agreement",
                "short": "CORRECTNESS CHECK",
                "elapsed_ms": 0.0,
                "inputs": ["K_sender", "K_receiver"],
                "outputs": ["32-byte equality check"],
                "explanation": "The server compares secrets internally; raw shared secrets are not returned to the browser.",
                "status": "passed" if hybrid_match and mlkem_match and x25519_match else "failed",
            }
        )

        if not (mlkem_match and x25519_match and hybrid_match):
            raise RuntimeError("X-Wing correctness check failed: component secrets did not match.")

        # Ciphertext is c = (c1, c2). Only public material is previewed.
        elapsed_total_ms = (time.perf_counter() - total_started) * 1000.0
        timings = {
            "keygen_mlkem_ms": round(keygen_mlkem_ms, 3),
            "keygen_x25519_ms": round(keygen_x25519_ms, 3),
            "encaps_mlkem_ms": round(encaps_mlkem_ms, 3),
            "encaps_x25519_keygen_ms": round(eph_keygen_ms, 3),
            "encaps_x25519_dh_ms": round(encaps_dh_ms, 3),
            "decaps_mlkem_ms": round(decap_mlkem_ms, 3),
            "decaps_x25519_dh_ms": round(decap_dh_ms, 3),
            "encaps_combiner_ms": round(sender_hash_ms, 3),
            "decaps_combiner_ms": round(receiver_hash_ms, 3),
            "total_roundtrip_ms": round(elapsed_total_ms, 3),
        }

        return {
            "ok": True,
            "algorithm": "X-Wing original-paper baseline",
            "paper_reference": "Barbosa et al., 'X-Wing: The Hybrid KEM You've Been Looking For', Figure 12",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "runtime": {
                "openssl": backend.version_text,
                "python": platform.python_version(),
                "implementation": "OpenSSL CLI + Python hashlib.sha3_256",
            },
            "label_ascii": XWING_LABEL.decode("ascii"),
            "label_hex": XWING_LABEL.hex(),
            "sizes_bytes": dict(SIZES),
            "actual_lengths_bytes": {
                "mlkem_ciphertext": len(ml_ct),
                "x25519_ciphertext": len(c2),
                "xwing_ciphertext": len(ml_ct) + len(c2),
                "mlkem_sender_secret": len(k1_sender),
                "x25519_sender_secret": len(k2_sender),
                "hybrid_sender_secret": len(k_sender),
                "combiner_input": len(sender_material),
            },
            "checks": {
                "mlkem_component_match": mlkem_match,
                "x25519_component_match": x25519_match,
                "hybrid_shared_secret_match": hybrid_match,
            },
            "fingerprints": {
                "sender_hybrid_secret_sha256_prefix": fingerprint(k_sender),
                "receiver_hybrid_secret_sha256_prefix": fingerprint(k_receiver),
                "mlkem_component_secret_sha256_prefix": fingerprint(k1_sender),
                "x25519_component_secret_sha256_prefix": fingerprint(k2_sender),
            },
            "public_previews": {
                "recipient_x25519_public_hex_prefix": pk2[:12].hex(),
                "ephemeral_x25519_public_hex_prefix": c2[:12].hex(),
                "mlkem_ciphertext_hex_prefix": ml_ct[:16].hex(),
            },
            "timings_ms": timings,
            "steps": steps,
            "notes": [
                "This run executes the original paper construction, not a later X-Wing Internet-Draft revision.",
                "OpenSSL subprocess timings include process startup and file I/O; they are not primitive-only benchmarks.",
                "This local educational prototype has not been security-audited and is not for production use.",
                "The browser receives secret fingerprints, not private keys or raw shared secrets.",
            ],
        }

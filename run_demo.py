"""Run one real original-paper X-Wing round trip and print a JSON report."""

from __future__ import annotations

import json
import sys

from xwing import run_original_paper_roundtrip
from xwing.openssl_backend import OpenSSLCommandError


if __name__ == "__main__":
    try:
        report = run_original_paper_roundtrip()
    except (OpenSSLCommandError, RuntimeError, ValueError) as exc:
        print(f"X-Wing demo failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(report, indent=2))

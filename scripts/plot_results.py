#!/usr/bin/env python3
"""Create throughput and speedup charts from native benchmark CSV output."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def make_kem_plots(path: Path, output: Path, plt) -> None:
    rows = read_rows(path)
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row and row.get("mode"):
            groups[row["mode"]].append(row)
    if not groups:
        raise ValueError(f"No KEM benchmark rows found in {path}")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for mode, values in sorted(groups.items()):
        values.sort(key=lambda row: int(row["threads"]))
        threads = [int(row["threads"]) for row in values]
        axes[0].plot(threads, [float(row["operations_per_second"]) for row in values], marker="o", label=mode)
        axes[1].plot(threads, [float(row["speedup"]) for row in values], marker="o", label=mode)
    axes[0].set(title="X-Wing batch throughput", xlabel="OpenMP threads", ylabel="Encapsulations / second")
    axes[1].set(title="Parallel speedup", xlabel="OpenMP threads", ylabel="Speedup")
    for axis in axes:
        axis.grid(True, alpha=0.25)
        axis.legend()
    fig.tight_layout()
    fig.savefig(output / "kem-throughput-speedup.png", dpi=160)
    plt.close(fig)


def make_ntt_plots(path: Path, output: Path, plt) -> None:
    rows = read_rows(path)
    if not rows:
        raise ValueError(f"No NTT benchmark rows found in {path}")
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    serial_rows = [row for row in rows if row.get("algorithm") in {"naive", "ntt_precomputed_twiddles"}]
    labels = [row["algorithm"] for row in serial_rows]
    rates = [float(row["operations_per_second"]) for row in serial_rows]
    axes[0].bar(labels, rates, color=["#6574cd", "#22a699"][: len(labels)])
    parallel_rows = [row for row in rows if row.get("algorithm") in {"ntt_openmp_batch", "ntt_stage_parallel"}]
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in parallel_rows:
        groups[row["algorithm"]].append(row)
    for algorithm, values in sorted(groups.items()):
        values.sort(key=lambda row: int(row["threads"]))
        axes[1].plot([int(row["threads"]) for row in values],
                     [float(row["speedup"]) for row in values], marker="o", label=algorithm)
    axes[0].set(title="Polynomial multiplication throughput", ylabel="Multiplications / second")
    axes[0].tick_params(axis="x", rotation=15)
    axes[1].set(title="NTT parallel speedup", xlabel="OpenMP threads", ylabel="Speedup vs serial NTT")
    for axis in axes:
        axis.grid(True, alpha=0.25)
    if groups:
        axes[1].legend()
    fig.tight_layout()
    fig.savefig(output / "ntt-throughput-speedup.png", dpi=160)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kem", type=Path, help="CSV from xwing_native_bench")
    parser.add_argument("--ntt", type=Path, help="CSV from ntt_lab (redirect stdout to a file)")
    parser.add_argument("--out", type=Path, default=Path("results/figures"))
    args = parser.parse_args()
    if not args.kem and not args.ntt:
        parser.error("provide --kem and/or --ntt CSV input")
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise SystemExit("Plotting needs matplotlib; install it with python3 -m pip install matplotlib") from exc

    args.out.mkdir(parents=True, exist_ok=True)
    if args.kem:
        make_kem_plots(args.kem, args.out, plt)
    if args.ntt:
        make_ntt_plots(args.ntt, args.out, plt)
    print(f"Figures written to {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

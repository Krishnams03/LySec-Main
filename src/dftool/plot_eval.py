"""
DFTool - Evaluation Plotter
Generate paper-ready figures from `dftool-eval` outputs.

Usage examples:
    dftool-eval-plot --input-json /tmp/dftool_eval.json --output-dir /tmp/plots
    dftool-eval-plot --input-csv /tmp/dftool_eval_incidents.csv --output-dir /tmp/plots
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
from typing import Any


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _load_from_json(path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)

    baseline = payload.get("baseline_incidents", []) or []
    faces = payload.get("faces_incidents", []) or []
    return baseline, faces


def _load_from_csv(path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    baseline: list[dict[str, Any]] = []
    faces: list[dict[str, Any]] = []

    with open(path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            model = str(row.get("model", "")).strip().lower()
            item = {
                "model": model,
                "score": _to_float(row.get("score"), 0.0),
                "event_count": int(_to_float(row.get("event_count"), 0.0)),
                "monitor_count": int(_to_float(row.get("monitor_count"), 0.0)),
                "indicator": row.get("indicator", ""),
                "campaign_key": row.get("campaign_key", ""),
            }

            if model == "baseline":
                baseline.append(item)
            elif model == "faces":
                faces.append(item)

    return baseline, faces


def _to_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _score_series(incidents: list[dict[str, Any]]) -> list[float]:
    return [float(inc.get("score", 0.0)) for inc in incidents]


def _monitor_series(incidents: list[dict[str, Any]]) -> list[float]:
    return [float(inc.get("monitor_count", 0.0)) for inc in incidents]


def _threshold_counts(scores: list[float], thresholds: list[int]) -> list[int]:
    return [sum(1 for s in scores if s >= t) for t in thresholds]


def _write_threshold_table(
    out_path: str,
    thresholds: list[int],
    baseline_counts: list[int],
    faces_counts: list[int],
):
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["threshold", "baseline_incidents_ge_threshold", "faces_incidents_ge_threshold"])
        for t, b, f in zip(thresholds, baseline_counts, faces_counts):
            writer.writerow([t, b, f])


def _write_model_comparison_table(
    out_path: str,
    baseline_incidents: list[dict[str, Any]],
    faces_incidents: list[dict[str, Any]],
):
    baseline_scores = _score_series(baseline_incidents)
    faces_scores = _score_series(faces_incidents)
    baseline_monitors = _monitor_series(baseline_incidents)
    faces_monitors = _monitor_series(faces_incidents)

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["metric", "baseline", "faces_v1"])
        writer.writerow(["incident_count", len(baseline_incidents), len(faces_incidents)])
        writer.writerow(["avg_score", round(_mean(baseline_scores), 2), round(_mean(faces_scores), 2)])
        writer.writerow(
            [
                "avg_monitor_diversity",
                round(_mean(baseline_monitors), 2),
                round(_mean(faces_monitors), 2),
            ]
        )


def _chain_frequency(incidents: list[dict[str, Any]]) -> Counter:
    counter: Counter = Counter()
    for incident in incidents:
        chains = incident.get("matched_chains", []) or []
        for chain in chains:
            chain_name = str(chain).strip()
            if chain_name:
                counter[chain_name] += 1
    return counter


def _write_chain_frequency_table(out_path: str, counter: Counter):
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["chain_pattern", "count"])
        for name, count in counter.most_common():
            writer.writerow([name, count])


def _plot_threshold_sweep(
    out_path: str,
    thresholds: list[int],
    baseline_counts: list[int],
    faces_counts: list[int],
):
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(thresholds, baseline_counts, marker="o", linewidth=2, label="Baseline")
    ax.plot(thresholds, faces_counts, marker="o", linewidth=2, label="FACES-v1")
    ax.set_title("Incident Threshold Sweep")
    ax.set_xlabel("Score Threshold")
    ax.set_ylabel("Incident Count (score ≥ threshold)")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def _plot_score_distribution(
    out_path: str,
    baseline_scores: list[float],
    faces_scores: list[float],
):
    import matplotlib.pyplot as plt

    bins = list(range(0, 101, 5))
    fig, ax = plt.subplots(figsize=(8, 5))
    if baseline_scores:
        ax.hist(baseline_scores, bins=bins, alpha=0.55, label="Baseline")
    if faces_scores:
        ax.hist(faces_scores, bins=bins, alpha=0.55, label="FACES-v1")

    ax.set_title("Incident Score Distribution")
    ax.set_xlabel("Score")
    ax.set_ylabel("Incident Count")
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def _plot_model_comparison(
    out_path: str,
    baseline_incidents: list[dict[str, Any]],
    faces_incidents: list[dict[str, Any]],
):
    import matplotlib.pyplot as plt

    metrics = ["Incident Count", "Avg Score", "Avg Monitor Diversity"]
    baseline_values = [
        float(len(baseline_incidents)),
        _mean(_score_series(baseline_incidents)),
        _mean(_monitor_series(baseline_incidents)),
    ]
    faces_values = [
        float(len(faces_incidents)),
        _mean(_score_series(faces_incidents)),
        _mean(_monitor_series(faces_incidents)),
    ]

    x = list(range(len(metrics)))
    width = 0.36

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([i - width / 2 for i in x], baseline_values, width=width, label="Baseline")
    ax.bar([i + width / 2 for i in x], faces_values, width=width, label="FACES-v1")

    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.set_title("Model Comparison")
    ax.set_ylabel("Value")
    ax.grid(True, axis="y", alpha=0.3)
    ax.legend()

    for i, val in enumerate(baseline_values):
        ax.text(i - width / 2, val, f"{val:.2f}", ha="center", va="bottom", fontsize=9)
    for i, val in enumerate(faces_values):
        ax.text(i + width / 2, val, f"{val:.2f}", ha="center", va="bottom", fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def _plot_chain_pattern_frequency(out_path: str, counter: Counter):
    import matplotlib.pyplot as plt

    if not counter:
        return

    names = [name for name, _ in counter.most_common()]
    counts = [count for _, count in counter.most_common()]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(names, counts)
    ax.set_title("FACES-v1 Matched Chain Pattern Frequency")
    ax.set_xlabel("Chain Pattern")
    ax.set_ylabel("Matched Incident Count")
    ax.grid(True, axis="y", alpha=0.3)
    ax.tick_params(axis="x", rotation=20)

    for i, val in enumerate(counts):
        ax.text(i, val, str(val), ha="center", va="bottom", fontsize=9)

    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(
        description="Generate threshold sweep and score distribution plots from dftool-eval outputs"
    )
    parser.add_argument("--input-json", help="Path to dftool-eval JSON report")
    parser.add_argument("--input-csv", help="Path to dftool-eval CSV incidents report")
    parser.add_argument("--output-dir", default="./eval_plots", help="Directory for plot artifacts")
    args = parser.parse_args()

    if not args.input_json and not args.input_csv:
        raise SystemExit("Provide at least one input source: --input-json or --input-csv")

    try:
        import matplotlib

        matplotlib.use("Agg")
    except ImportError as exc:
        raise SystemExit(
            "matplotlib is required for plotting. Install with: pip install matplotlib"
        ) from exc

    baseline_incidents: list[dict[str, Any]] = []
    faces_incidents: list[dict[str, Any]] = []

    if args.input_json:
        baseline_incidents, faces_incidents = _load_from_json(args.input_json)
    elif args.input_csv:
        baseline_incidents, faces_incidents = _load_from_csv(args.input_csv)

    baseline_scores = _score_series(baseline_incidents)
    faces_scores = _score_series(faces_incidents)

    if not baseline_scores and not faces_scores:
        raise SystemExit("No incidents found in input data.")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    thresholds = list(range(0, 101, 5))
    baseline_counts = _threshold_counts(baseline_scores, thresholds)
    faces_counts = _threshold_counts(faces_scores, thresholds)

    threshold_plot = str(output_dir / "threshold_sweep.png")
    score_plot = str(output_dir / "score_distribution.png")
    model_plot = str(output_dir / "model_comparison.png")
    chain_plot = str(output_dir / "chain_pattern_frequency.png")
    threshold_csv = str(output_dir / "threshold_sweep.csv")
    model_csv = str(output_dir / "model_comparison.csv")
    chain_csv = str(output_dir / "chain_pattern_frequency.csv")

    _plot_threshold_sweep(threshold_plot, thresholds, baseline_counts, faces_counts)
    _plot_score_distribution(score_plot, baseline_scores, faces_scores)
    _plot_model_comparison(model_plot, baseline_incidents, faces_incidents)
    _write_threshold_table(threshold_csv, thresholds, baseline_counts, faces_counts)
    _write_model_comparison_table(model_csv, baseline_incidents, faces_incidents)

    chain_counter = _chain_frequency(faces_incidents)
    _write_chain_frequency_table(chain_csv, chain_counter)
    _plot_chain_pattern_frequency(chain_plot, chain_counter)

    print("Evaluation plots generated:")
    print(f"- {threshold_plot}")
    print(f"- {score_plot}")
    print(f"- {model_plot}")
    if chain_counter:
        print(f"- {chain_plot}")
    print(f"- {threshold_csv}")
    print(f"- {model_csv}")
    print(f"- {chain_csv}")


if __name__ == "__main__":
    main()

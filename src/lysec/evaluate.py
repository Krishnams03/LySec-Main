"""
LySec - Correlation Evaluator
Replay alert logs and compare baseline correlation scoring against FACES-v1.

Usage examples:
    lysec-eval --alerts-file /var/log/lysec/alerts.log
    lysec-eval --alerts-file ./alerts.jsonl --window-sec 300 --top 10
    lysec-eval --alerts-file ./alerts.jsonl --ml-anomaly --ml-top 10
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any
import math


SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


SEVERITY_WEIGHTS = {
    SEVERITY_INFO: 1,
    SEVERITY_LOW: 2,
    SEVERITY_MEDIUM: 3,
    SEVERITY_HIGH: 5,
    SEVERITY_CRITICAL: 8,
}


class ReplayCorrelator:
    def __init__(
        self,
        model: str,
        window_sec: int,
        min_unique_monitors: int,
        min_score: float,
        emit_suppress_sec: int,
    ):
        self.model = model
        self.window_sec = window_sec
        self.min_unique_monitors = min_unique_monitors
        self.min_score = min_score
        self.emit_suppress_sec = emit_suppress_sec
        self.recent_alerts: list[dict[str, Any]] = []
        self.last_emitted: dict[str, float] = {}
        self.incidents: list[dict[str, Any]] = []

        self.score_weights = {
            "severity": 4.0,
            "diversity": 7.0,
            "burst": 20.0,
            "rarity": 25.0,
            "chain": 1.0,
        }
        self.chain_patterns = [
            {
                "name": "credential_to_execution",
                "events": ["LOGIN_FAILED", "BRUTE_FORCE_DETECTED", "SUSPICIOUS_PROCESS"],
                "bonus": 14,
            },
            {
                "name": "lateral_to_privilege",
                "events": ["LOGIN_SUCCESS", "UID_CHANGE", "PRIVILEGE_ESCALATION"],
                "bonus": 16,
            },
            {
                "name": "network_recon_chain",
                "events": ["NEW_INTERFACE", "PROMISCUOUS_MODE", "NEW_LISTENER"],
                "bonus": 12,
            },
        ]

    def process_alert(self, alert: dict[str, Any]):
        event_type = str(alert.get("event_type", ""))
        if event_type == "CORRELATED_INCIDENT":
            return

        now = float(alert.get("epoch", 0.0))
        window_start = now - self.window_sec
        self.recent_alerts.append(alert)
        self.recent_alerts = [a for a in self.recent_alerts if float(a.get("epoch", 0.0)) >= window_start]

        trigger_indicators = self._extract_indicators(alert.get("details", {}))
        if not trigger_indicators:
            return

        related = []
        for candidate in self.recent_alerts:
            if trigger_indicators.intersection(self._extract_indicators(candidate.get("details", {}))):
                related.append(candidate)

        if len(related) < 2:
            return

        monitors = {a.get("monitor", "unknown") for a in related}
        if len(monitors) < self.min_unique_monitors:
            return

        indicator_key, indicator_freq = self._select_primary_indicator(related, trigger_indicators)

        if self.model == "baseline":
            score = float(sum(SEVERITY_WEIGHTS.get(a.get("severity", SEVERITY_MEDIUM), 3) for a in related))
            components = {"severity_sum": round(score, 2)}
            matched_chains: list[str] = []
        else:
            score, components, matched_chains = self._score_faces(related, indicator_freq)

        if score < self.min_score:
            return

        campaign_key = f"{indicator_key}|{'|'.join(sorted(monitors))}"
        last_emit = self.last_emitted.get(campaign_key, 0)
        if now - last_emit < self.emit_suppress_sec:
            return
        self.last_emitted[campaign_key] = now

        incident = {
            "model": self.model,
            "epoch": now,
            "indicator": indicator_key,
            "campaign_key": campaign_key,
            "score": round(float(score), 2),
            "event_count": len(related),
            "monitor_count": len(monitors),
            "monitors": sorted(monitors),
            "trigger_event": alert.get("event_type"),
            "components": components,
            "matched_chains": matched_chains,
        }
        self.incidents.append(incident)

    @staticmethod
    def _extract_indicators(details: dict[str, Any]) -> set[str]:
        indicators: set[str] = set()
        if not isinstance(details, dict):
            return indicators
        for key in ("ip", "user", "pid", "interface", "path", "serial", "host", "listener"):
            value = details.get(key)
            if value is None:
                continue
            txt = str(value).strip()
            if txt:
                indicators.add(f"{key}:{txt}")
        return indicators

    def _score_faces(
        self,
        related: list[dict[str, Any]],
        indicator_freq: int,
    ) -> tuple[float, dict[str, float], list[str]]:
        monitor_count = len({a.get("monitor", "unknown") for a in related})
        severity_sum = sum(SEVERITY_WEIGHTS.get(a.get("severity", SEVERITY_MEDIUM), 3) for a in related)

        severity_component = severity_sum * float(self.score_weights["severity"])
        diversity_component = max(0, monitor_count - 1) * float(self.score_weights["diversity"])

        epochs = [float(a.get("epoch", 0.0)) for a in related]
        span = max(0.0, max(epochs) - min(epochs)) if epochs else float(self.window_sec)
        burst_tightness = max(0.0, 1.0 - min(span, float(self.window_sec)) / float(self.window_sec))
        burst_event_factor = min(1.0, len(related) / 6.0)
        burst_component = burst_tightness * burst_event_factor * float(self.score_weights["burst"])

        rarity_component = (1.0 / max(1, indicator_freq)) * float(self.score_weights["rarity"])

        chain_bonus, matched_chains = self._chain_bonus(related)
        chain_component = chain_bonus * float(self.score_weights["chain"])

        total = severity_component + diversity_component + burst_component + rarity_component + chain_component
        score = min(100.0, total)
        components = {
            "severity": round(min(100.0, severity_component), 2),
            "diversity": round(min(100.0, diversity_component), 2),
            "burst": round(min(100.0, burst_component), 2),
            "rarity": round(min(100.0, rarity_component), 2),
            "chain": round(min(100.0, chain_component), 2),
        }
        return round(score, 2), components, matched_chains

    def _chain_bonus(self, related: list[dict[str, Any]]) -> tuple[float, list[str]]:
        ordered = sorted(related, key=lambda a: float(a.get("epoch", 0.0)))
        sequence = [str(a.get("event_type", "")) for a in ordered]
        total_bonus = 0.0
        matched: list[str] = []
        for pattern in self.chain_patterns:
            target = [str(x) for x in pattern.get("events", [])]
            if self._is_ordered_subsequence(sequence, target):
                total_bonus += float(pattern.get("bonus", 0))
                matched.append(str(pattern.get("name", "unnamed")))
        return total_bonus, matched

    @staticmethod
    def _is_ordered_subsequence(sequence: list[str], target: list[str]) -> bool:
        if not target:
            return False
        idx = 0
        for item in sequence:
            if item == target[idx]:
                idx += 1
                if idx == len(target):
                    return True
        return False

    def _select_primary_indicator(
        self,
        related: list[dict[str, Any]],
        trigger_indicators: set[str],
    ) -> tuple[str, int]:
        indicator_counts: dict[str, int] = {ind: 0 for ind in trigger_indicators}
        for candidate in self.recent_alerts:
            c_inds = self._extract_indicators(candidate.get("details", {}))
            for ind in indicator_counts:
                if ind in c_inds:
                    indicator_counts[ind] += 1
        if not indicator_counts:
            return "unknown", 1
        indicator, freq = min(indicator_counts.items(), key=lambda item: item[1])
        return indicator, max(1, int(freq))


def _parse_epoch(entry: dict[str, Any]) -> float | None:
    if "epoch" in entry:
        try:
            return float(entry["epoch"])
        except (TypeError, ValueError):
            pass
    ts = entry.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def load_alerts(path: str) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            epoch = _parse_epoch(item)
            if epoch is None:
                continue
            item["epoch"] = epoch
            item.setdefault("details", {})
            alerts.append(item)
    alerts.sort(key=lambda a: float(a.get("epoch", 0.0)))
    return alerts


def print_summary(
    baseline: ReplayCorrelator,
    faces: ReplayCorrelator,
    source_alert_count: int,
    top: int,
):
    base_inc = baseline.incidents
    face_inc = faces.incidents

    base_keys = {i["campaign_key"] for i in base_inc}
    face_keys = {i["campaign_key"] for i in face_inc}

    baseline_only = sorted(base_keys - face_keys)
    faces_only = sorted(face_keys - base_keys)
    overlap = sorted(base_keys & face_keys)

    print("=== LySec Correlation Evaluation ===")
    print(f"Source alerts replayed: {source_alert_count}")
    print()
    print("Models")
    print(f"- baseline incidents: {len(base_inc)}")
    print(f"- FACES-v1 incidents: {len(face_inc)}")
    print(f"- overlap campaign keys: {len(overlap)}")
    print(f"- baseline-only keys: {len(baseline_only)}")
    print(f"- FACES-only keys: {len(faces_only)}")

    if base_inc:
        print(
            f"- baseline avg score/events/monitors: "
            f"{mean(i['score'] for i in base_inc):.2f} / "
            f"{mean(i['event_count'] for i in base_inc):.2f} / "
            f"{mean(i['monitor_count'] for i in base_inc):.2f}"
        )
    if face_inc:
        print(
            f"- FACES-v1 avg score/events/monitors: "
            f"{mean(i['score'] for i in face_inc):.2f} / "
            f"{mean(i['event_count'] for i in face_inc):.2f} / "
            f"{mean(i['monitor_count'] for i in face_inc):.2f}"
        )

    print()
    print("Top FACES-v1 incidents")
    for incident in sorted(face_inc, key=lambda i: i["score"], reverse=True)[:top]:
        chains = ",".join(incident.get("matched_chains", [])) or "none"
        print(
            f"- score={incident['score']:.2f} indicator={incident['indicator']} "
            f"events={incident['event_count']} monitors={incident['monitor_count']} chains={chains}"
        )

    if face_inc:
        all_chains = Counter(c for i in face_inc for c in i.get("matched_chains", []))
        if all_chains:
            print()
            print("Matched chain patterns")
            for name, count in all_chains.most_common():
                print(f"- {name}: {count}")


def _summary_dict(
    baseline: ReplayCorrelator,
    faces: ReplayCorrelator,
    source_alert_count: int,
    anomaly_incidents: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    base_inc = baseline.incidents
    face_inc = faces.incidents

    base_keys = {i["campaign_key"] for i in base_inc}
    face_keys = {i["campaign_key"] for i in face_inc}

    summary: dict[str, Any] = {
        "source_alert_count": source_alert_count,
        "baseline_incident_count": len(base_inc),
        "faces_incident_count": len(face_inc),
        "overlap_campaign_keys": len(base_keys & face_keys),
        "baseline_only_keys": len(base_keys - face_keys),
        "faces_only_keys": len(face_keys - base_keys),
    }

    if base_inc:
        summary["baseline_avg_score"] = round(mean(i["score"] for i in base_inc), 2)
        summary["baseline_avg_event_count"] = round(mean(i["event_count"] for i in base_inc), 2)
        summary["baseline_avg_monitor_count"] = round(mean(i["monitor_count"] for i in base_inc), 2)

    if face_inc:
        summary["faces_avg_score"] = round(mean(i["score"] for i in face_inc), 2)
        summary["faces_avg_event_count"] = round(mean(i["event_count"] for i in face_inc), 2)
        summary["faces_avg_monitor_count"] = round(mean(i["monitor_count"] for i in face_inc), 2)

    anomaly_incidents = anomaly_incidents or []
    if anomaly_incidents:
        summary["anomaly_incident_count"] = len(anomaly_incidents)
        summary["anomaly_avg_score"] = round(
            mean(float(i.get("anomaly_score", 0.0)) for i in anomaly_incidents), 2
        )

    return summary


def _safe_stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 1.0
    m = mean(values)
    var = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return max(1e-9, math.sqrt(var))


def _z(v: float, mu: float, sigma: float) -> float:
    return (v - mu) / max(1e-9, sigma)


def _build_anomaly_incidents(
    faces_incidents: list[dict[str, Any]],
    top: int,
) -> list[dict[str, Any]]:
    """
    Lightweight local ML-style ranking using z-score anomaly features.
    Learns feature distribution from the replayed incident population.
    """
    if not faces_incidents:
        return []

    event_vals = [float(i.get("event_count", 0.0)) for i in faces_incidents]
    monitor_vals = [float(i.get("monitor_count", 0.0)) for i in faces_incidents]
    score_vals = [float(i.get("score", 0.0)) for i in faces_incidents]
    chain_vals = [float(len(i.get("matched_chains", []) or [])) for i in faces_incidents]

    indicator_counts = Counter(str(i.get("indicator", "unknown")) for i in faces_incidents)
    rarity_vals = [1.0 / max(1.0, float(indicator_counts[str(i.get("indicator", "unknown"))])) for i in faces_incidents]

    mu_event, sd_event = mean(event_vals), _safe_stdev(event_vals)
    mu_monitor, sd_monitor = mean(monitor_vals), _safe_stdev(monitor_vals)
    mu_score, sd_score = mean(score_vals), _safe_stdev(score_vals)
    mu_chain, sd_chain = mean(chain_vals), _safe_stdev(chain_vals)
    mu_rarity, sd_rarity = mean(rarity_vals), _safe_stdev(rarity_vals)

    ranked: list[dict[str, Any]] = []
    for idx, incident in enumerate(faces_incidents):
        ev = float(incident.get("event_count", 0.0))
        mon = float(incident.get("monitor_count", 0.0))
        sc = float(incident.get("score", 0.0))
        ch = float(len(incident.get("matched_chains", []) or []))
        rar = rarity_vals[idx]

        z_event = max(0.0, _z(ev, mu_event, sd_event))
        z_monitor = max(0.0, _z(mon, mu_monitor, sd_monitor))
        z_score = max(0.0, _z(sc, mu_score, sd_score))
        z_chain = max(0.0, _z(ch, mu_chain, sd_chain))
        z_rarity = max(0.0, _z(rar, mu_rarity, sd_rarity))

        # Weighted anomaly confidence in [0, 100]
        raw = (
            (2.4 * z_score)
            + (1.8 * z_monitor)
            + (1.6 * z_event)
            + (1.0 * z_chain)
            + (1.4 * z_rarity)
        )
        anomaly_score = round(min(100.0, raw * 18.0), 2)

        item = dict(incident)
        item["model"] = "anomaly"
        item["anomaly_score"] = anomaly_score
        item["anomaly_features"] = {
            "z_score": round(z_score, 3),
            "z_monitor": round(z_monitor, 3),
            "z_event": round(z_event, 3),
            "z_chain": round(z_chain, 3),
            "z_rarity": round(z_rarity, 3),
        }
        ranked.append(item)

    ranked.sort(key=lambda i: float(i.get("anomaly_score", 0.0)), reverse=True)
    return ranked[: max(1, int(top))]


def _write_json_output(
    output_path: str,
    baseline: ReplayCorrelator,
    faces: ReplayCorrelator,
    source_alert_count: int,
    anomaly_incidents: list[dict[str, Any]] | None = None,
):
    anomaly_incidents = anomaly_incidents or []
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": _summary_dict(baseline, faces, source_alert_count, anomaly_incidents),
        "baseline_incidents": baseline.incidents,
        "faces_incidents": faces.incidents,
        "anomaly_incidents": anomaly_incidents,
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def _write_csv_output(
    output_path: str,
    baseline: ReplayCorrelator,
    faces: ReplayCorrelator,
    anomaly_incidents: list[dict[str, Any]] | None = None,
):
    anomaly_incidents = anomaly_incidents or []
    rows: list[dict[str, Any]] = []
    for incident in baseline.incidents:
        rows.append(
            {
                "model": "baseline",
                "epoch": incident.get("epoch"),
                "indicator": incident.get("indicator"),
                "campaign_key": incident.get("campaign_key"),
                "score": incident.get("score"),
                "event_count": incident.get("event_count"),
                "monitor_count": incident.get("monitor_count"),
                "monitors": ";".join(incident.get("monitors", [])),
                "trigger_event": incident.get("trigger_event"),
                "matched_chains": ";".join(incident.get("matched_chains", [])),
                "components": json.dumps(incident.get("components", {}), sort_keys=True),
            }
        )

    for incident in faces.incidents:
        rows.append(
            {
                "model": "faces",
                "epoch": incident.get("epoch"),
                "indicator": incident.get("indicator"),
                "campaign_key": incident.get("campaign_key"),
                "score": incident.get("score"),
                "event_count": incident.get("event_count"),
                "monitor_count": incident.get("monitor_count"),
                "monitors": ";".join(incident.get("monitors", [])),
                "trigger_event": incident.get("trigger_event"),
                "matched_chains": ";".join(incident.get("matched_chains", [])),
                "components": json.dumps(incident.get("components", {}), sort_keys=True),
                "anomaly_score": "",
            }
        )

    for incident in anomaly_incidents:
        rows.append(
            {
                "model": "anomaly",
                "epoch": incident.get("epoch"),
                "indicator": incident.get("indicator"),
                "campaign_key": incident.get("campaign_key"),
                "score": incident.get("score"),
                "event_count": incident.get("event_count"),
                "monitor_count": incident.get("monitor_count"),
                "monitors": ";".join(incident.get("monitors", [])),
                "trigger_event": incident.get("trigger_event"),
                "matched_chains": ";".join(incident.get("matched_chains", [])),
                "components": json.dumps(incident.get("anomaly_features", {}), sort_keys=True),
                "anomaly_score": incident.get("anomaly_score"),
            }
        )

    fieldnames = [
        "model",
        "epoch",
        "indicator",
        "campaign_key",
        "score",
        "event_count",
        "monitor_count",
        "monitors",
        "trigger_event",
        "matched_chains",
        "components",
        "anomaly_score",
    ]

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="Replay alerts and compare baseline correlation to FACES-v1"
    )
    parser.add_argument("--alerts-file", required=True, help="Path to JSONL alerts log")
    parser.add_argument("--window-sec", type=int, default=300)
    parser.add_argument("--min-unique-monitors", type=int, default=2)
    parser.add_argument("--baseline-min-score", type=float, default=8.0)
    parser.add_argument("--faces-min-score", type=float, default=45.0)
    parser.add_argument("--emit-suppress-sec", type=int, default=180)
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument(
        "--ml-anomaly",
        action="store_true",
        help="Enable lightweight local anomaly ranking over FACES incidents",
    )
    parser.add_argument(
        "--ml-top",
        type=int,
        default=10,
        help="Number of top anomaly-ranked incidents to include",
    )
    parser.add_argument("--output-json", help="Write full evaluation report to JSON file")
    parser.add_argument("--output-csv", help="Write incident-level results to CSV file")
    args = parser.parse_args()

    alerts = load_alerts(args.alerts_file)
    if not alerts:
        print("No valid alert entries found in file.")
        return

    baseline = ReplayCorrelator(
        model="baseline",
        window_sec=args.window_sec,
        min_unique_monitors=args.min_unique_monitors,
        min_score=args.baseline_min_score,
        emit_suppress_sec=args.emit_suppress_sec,
    )
    faces = ReplayCorrelator(
        model="faces",
        window_sec=args.window_sec,
        min_unique_monitors=args.min_unique_monitors,
        min_score=args.faces_min_score,
        emit_suppress_sec=args.emit_suppress_sec,
    )

    for alert in alerts:
        baseline.process_alert(alert)
        faces.process_alert(alert)

    print_summary(baseline, faces, len(alerts), args.top)

    anomaly_incidents: list[dict[str, Any]] = []
    if args.ml_anomaly:
        anomaly_incidents = _build_anomaly_incidents(faces.incidents, args.ml_top)
        print()
        print("Top ML-style anomaly incidents")
        for incident in anomaly_incidents:
            print(
                f"- anomaly={incident.get('anomaly_score', 0):.2f} "
                f"score={incident.get('score', 0):.2f} "
                f"indicator={incident.get('indicator')} "
                f"events={incident.get('event_count')} monitors={incident.get('monitor_count')}"
            )

    if args.output_json:
        _write_json_output(
            args.output_json,
            baseline,
            faces,
            len(alerts),
            anomaly_incidents=anomaly_incidents,
        )
        print(f"JSON report written: {args.output_json}")

    if args.output_csv:
        _write_csv_output(
            args.output_csv,
            baseline,
            faces,
            anomaly_incidents=anomaly_incidents,
        )
        print(f"CSV report written: {args.output_csv}")


if __name__ == "__main__":
    main()


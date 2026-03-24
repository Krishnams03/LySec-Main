"""
LySec - Alert Engine
Centralized alert dispatcher.  Monitors push events here; the engine
formats, deduplicates, and fans out to configured channels (log, syslog,
email, webhook).

Design: DETECT & LOG only — alerts are informational, never preventive.
"""

import json
import logging
import os
import smtplib
import time
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

try:
    import urllib.request
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

logger = logging.getLogger("lysec.alerts")

# ──────────────────────────────────────────────
# Severity levels (VERIS-inspired)
# ──────────────────────────────────────────────
SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


class AlertEngine:
    """
    Singleton-style alert dispatcher.
    """

    def __init__(self, config: dict):
        self._config = config.get("alerts", {})
        self._alert_log_path = self._config.get(
            "alert_log", "/var/log/lysec/alerts.log"
        )
        Path(os.path.dirname(self._alert_log_path)).mkdir(
            parents=True, exist_ok=True
        )
        # Simple dedup: hash(monitor+event_type+key_detail) -> last_ts
        self._seen: dict[str, float] = {}
        self._dedup_window = 60  # seconds

        # Cross-monitor correlation settings
        corr_cfg = self._config.get("correlation", {})
        self._corr_enabled = corr_cfg.get("enabled", True)
        self._corr_window_sec = corr_cfg.get("window_sec", 300)
        self._corr_min_unique_monitors = corr_cfg.get("min_unique_monitors", 2)
        self._corr_min_score = corr_cfg.get("min_score", 45)
        self._corr_emit_suppress_sec = corr_cfg.get("emit_suppress_sec", 180)
        self._corr_model_name = corr_cfg.get("model_name", "FACES-v1")
        self._corr_recent_alerts: list[dict[str, Any]] = []
        self._corr_last_emitted: dict[str, float] = {}
        self._severity_weights = {
            SEVERITY_INFO: 1,
            SEVERITY_LOW: 2,
            SEVERITY_MEDIUM: 3,
            SEVERITY_HIGH: 5,
            SEVERITY_CRITICAL: 8,
        }
        self._score_weights = corr_cfg.get(
            "score_weights",
            {
                "severity": 4.0,
                "diversity": 7.0,
                "burst": 20.0,
                "rarity": 25.0,
                "chain": 1.0,
            },
        )
        self._chain_patterns = corr_cfg.get(
            "chain_patterns",
            [
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
            ],
        )

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────
    def fire(
        self,
        monitor: str,
        event_type: str,
        message: str,
        severity: str = SEVERITY_MEDIUM,
        details: dict[str, Any] | None = None,
    ):
        """
        Create and dispatch an alert.
        """
        alert_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)

        alert = {
            "alert_id": alert_id,
            "timestamp": now_utc.isoformat(),
            "epoch": time.time(),
            "monitor": monitor,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "details": details or {},
        }

        # Deduplication
        dedup_key = f"{monitor}:{event_type}:{json.dumps(details, sort_keys=True, default=str)}"
        last = self._seen.get(dedup_key, 0)
        if time.time() - last < self._dedup_window:
            return  # suppress duplicate
        self._seen[dedup_key] = time.time()

        # ── Dispatch ──
        self._dispatch(alert)

        # ── Correlation ──
        if self._corr_enabled and event_type != "CORRELATED_INCIDENT":
            self._maybe_emit_correlation(alert)

    # ──────────────────────────────────────────
    # Correlation logic
    # ──────────────────────────────────────────
    def _maybe_emit_correlation(self, alert: dict[str, Any]):
        now = time.time()
        window_start = now - self._corr_window_sec

        self._corr_recent_alerts.append(alert)
        self._corr_recent_alerts = [
            a for a in self._corr_recent_alerts if a.get("epoch", 0) >= window_start
        ]

        trigger_indicators = self._extract_indicators(alert.get("details", {}))
        if not trigger_indicators:
            return

        related: list[dict[str, Any]] = []
        for candidate in self._corr_recent_alerts:
            candidate_indicators = self._extract_indicators(candidate.get("details", {}))
            if trigger_indicators.intersection(candidate_indicators):
                related.append(candidate)

        if len(related) < 2:
            return

        monitors = {a.get("monitor", "unknown") for a in related}
        if len(monitors) < self._corr_min_unique_monitors:
            return

        indicator_key, indicator_freq = self._select_primary_indicator(
            related, trigger_indicators
        )
        score, components, matched_chains = self._score_correlated_incident(
            related, indicator_freq
        )
        if score < self._corr_min_score:
            return

        campaign_key = f"{indicator_key}|{'|'.join(sorted(monitors))}"
        last_emit = self._corr_last_emitted.get(campaign_key, 0)
        if now - last_emit < self._corr_emit_suppress_sec:
            return
        self._corr_last_emitted[campaign_key] = now

        corr_severity = self._score_to_severity(score)

        corr_alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "epoch": now,
            "monitor": "correlation",
            "event_type": "CORRELATED_INCIDENT",
            "severity": corr_severity,
            "message": (
                "Cross-monitor correlated incident detected "
                f"for indicator '{indicator_key}'"
            ),
            "details": {
                "model": self._corr_model_name,
                "indicator": indicator_key,
                "score": score,
                "score_components": components,
                "window_sec": self._corr_window_sec,
                "event_count": len(related),
                "monitors": sorted(monitors),
                "trigger_event": alert.get("event_type"),
                "matched_chains": matched_chains,
                "contributing_alert_ids": [a.get("alert_id") for a in related],
            },
        }
        self._dispatch(corr_alert)

    def _score_correlated_incident(
        self, related: list[dict[str, Any]], indicator_freq: int
    ) -> tuple[float, dict[str, float], list[str]]:
        monitor_count = len({a.get("monitor", "unknown") for a in related})
        severity_sum = sum(
            self._severity_weights.get(a.get("severity", SEVERITY_MEDIUM), 3)
            for a in related
        )

        severity_component = severity_sum * float(self._score_weights.get("severity", 4.0))
        diversity_component = max(0, monitor_count - 1) * float(
            self._score_weights.get("diversity", 7.0)
        )

        epochs = [float(a.get("epoch", 0.0)) for a in related if a.get("epoch") is not None]
        if epochs:
            span = max(0.0, max(epochs) - min(epochs))
        else:
            span = float(self._corr_window_sec)
        burst_tightness = max(0.0, 1.0 - min(span, float(self._corr_window_sec)) / float(self._corr_window_sec))
        burst_event_factor = min(1.0, len(related) / 6.0)
        burst_component = (
            burst_tightness
            * burst_event_factor
            * float(self._score_weights.get("burst", 20.0))
        )

        rarity_component = (
            (1.0 / max(1, indicator_freq))
            * float(self._score_weights.get("rarity", 25.0))
        )

        chain_bonus, matched_chains = self._chain_bonus(related)
        chain_component = chain_bonus * float(self._score_weights.get("chain", 1.0))

        raw_score = (
            severity_component
            + diversity_component
            + burst_component
            + rarity_component
            + chain_component
        )
        score = round(min(100.0, raw_score), 2)

        components = {
            "severity": round(min(100.0, severity_component), 2),
            "diversity": round(min(100.0, diversity_component), 2),
            "burst": round(min(100.0, burst_component), 2),
            "rarity": round(min(100.0, rarity_component), 2),
            "chain": round(min(100.0, chain_component), 2),
        }
        return score, components, matched_chains

    def _chain_bonus(self, related: list[dict[str, Any]]) -> tuple[float, list[str]]:
        ordered = sorted(related, key=lambda a: a.get("epoch", 0))
        event_sequence = [str(a.get("event_type", "")) for a in ordered]

        total_bonus = 0.0
        matched: list[str] = []
        for pattern in self._chain_patterns:
            events = pattern.get("events", [])
            if not events:
                continue
            if self._is_ordered_subsequence(event_sequence, events):
                total_bonus += float(pattern.get("bonus", 0))
                matched.append(str(pattern.get("name", "unnamed_pattern")))
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
        self, related: list[dict[str, Any]], trigger_indicators: set[str]
    ) -> tuple[str, int]:
        indicator_counts: dict[str, int] = {ind: 0 for ind in trigger_indicators}

        for candidate in self._corr_recent_alerts:
            c_inds = self._extract_indicators(candidate.get("details", {}))
            for ind in indicator_counts:
                if ind in c_inds:
                    indicator_counts[ind] += 1

        if not indicator_counts:
            return "unknown", 1

        primary = min(indicator_counts.items(), key=lambda item: item[1])
        return primary[0], max(1, primary[1])

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 80:
            return SEVERITY_CRITICAL
        if score >= 60:
            return SEVERITY_HIGH
        if score >= 40:
            return SEVERITY_MEDIUM
        return SEVERITY_LOW

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

    # ──────────────────────────────────────────
    # Dispatch backends
    # ──────────────────────────────────────────
    def _dispatch(self, alert: dict[str, Any]):
        self._write_alert_log(alert)
        self._log_alert(alert)

        if self._config.get("syslog", False):
            self._send_syslog(alert)

        email_cfg = self._config.get("email", {})
        if email_cfg.get("enabled", False):
            self._send_email(alert, email_cfg)

        webhook_cfg = self._config.get("webhook", {})
        if webhook_cfg.get("enabled", False):
            self._send_webhook(alert, webhook_cfg)

    def _write_alert_log(self, alert: dict):
        """Append JSON alert to dedicated alert log file."""
        try:
            with open(self._alert_log_path, "a") as f:
                f.write(json.dumps(alert, default=str) + "\n")
        except Exception as exc:
            logger.error("Failed to write alert log: %s", exc)

    def _log_alert(self, alert: dict):
        """Forward alert to the main forensic logger."""
        level = {
            SEVERITY_INFO: logging.INFO,
            SEVERITY_LOW: logging.INFO,
            SEVERITY_MEDIUM: logging.WARNING,
            SEVERITY_HIGH: logging.ERROR,
            SEVERITY_CRITICAL: logging.CRITICAL,
        }.get(alert["severity"], logging.WARNING)

        logger.log(
            level,
            "[ALERT %s] [%s] %s",
            alert["severity"],
            alert["monitor"],
            alert["message"],
            extra={
                "event_type": alert["event_type"],
                "monitor": alert["monitor"],
                "details": alert["details"],
                "severity": alert["severity"],
                "alert_id": alert["alert_id"],
            },
        )

    def _send_syslog(self, alert: dict):
        """Already handled by forensic_logger syslog handler."""
        pass

    def _send_email(self, alert: dict, cfg: dict):
        """Send alert via SMTP."""
        try:
            subject = f"[LySec {alert['severity']}] {alert['event_type']} on {alert['monitor']}"
            body = json.dumps(alert, indent=2, default=str)
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = cfg["from_addr"]
            msg["To"] = cfg["to_addr"]

            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
                server.starttls()
                server.login(cfg["username"], cfg["password"])
                server.sendmail(cfg["from_addr"], [cfg["to_addr"]], msg.as_string())
        except Exception as exc:
            logger.error("Email alert failed: %s", exc)

    def _send_webhook(self, alert: dict, cfg: dict):
        """POST JSON alert to a webhook URL."""
        if not HAS_URLLIB:
            return
        try:
            data = json.dumps(alert, default=str).encode("utf-8")
            req = urllib.request.Request(
                cfg["url"],
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            logger.error("Webhook alert failed: %s", exc)

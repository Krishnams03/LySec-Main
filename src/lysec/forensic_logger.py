"""
LySec - Forensic Logger
Provides tamper-evident, timestamped, JSON-structured logging with SHA-256
integrity hashing.  Every log line is a self-contained JSON record so it can
be ingested by SIEM / timeline tools (e.g. Plaso, Timesketch).

Design philosophy:
    * DETECT & LOG — never block, never prevent.
    * UTC timestamps everywhere (ISO-8601).
    * Each rotated log file gets a SHA-256 manifest entry.
"""

import hashlib
import json
import logging
import logging.handlers
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class ForensicFormatter(logging.Formatter):
    """
    Emit every log record as a single JSON line with forensic metadata.
    """

    def __init__(self, hostname: str = None):
        super().__init__()
        self._hostname = hostname or _get_hostname()
        self._session_id = str(uuid.uuid4())       # unique per daemon run

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "epoch": time.time(),
            "hostname": self._hostname,
            "session_id": self._session_id,
            "level": record.levelname,
            "source": record.name,
            "module": record.module,
            "message": record.getMessage(),
        }

        # Attach extra forensic fields if present
        for attr in ("event_type", "monitor", "details", "severity",
                      "alert_id", "evidence_hash", "raw_data"):
            val = getattr(record, attr, None)
            if val is not None:
                log_entry[attr] = val

        return json.dumps(log_entry, default=str)


class IntegrityRotatingHandler(logging.handlers.RotatingFileHandler):
    """
    RotatingFileHandler that writes a SHA-256 hash of every rotated file
    into a companion .sha256 manifest.
    """

    def doRollover(self):
        # Hash the current file before rotation
        if os.path.isfile(self.baseFilename):
            digest = _hash_file(self.baseFilename)
            manifest = self.baseFilename + ".sha256"
            with open(manifest, "a") as mf:
                ts = datetime.now(timezone.utc).isoformat()
                mf.write(f"{ts}  {digest}  {self.baseFilename}\n")

        super().doRollover()


def setup_logging(config: dict) -> logging.Logger:
    """
    Configure and return the root forensic logger based on config dict.
    """
    log_cfg = config["logging"]
    log_dir = log_cfg["log_dir"]
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("lysec")
    logger.setLevel(logging.DEBUG)

    # ── Main forensic log (JSON) ──
    main_log = os.path.join(log_dir, "lysec.log")
    max_bytes = log_cfg.get("max_log_size_mb", 100) * 1024 * 1024
    backup_count = log_cfg.get("log_rotation_count", 10)

    file_handler = IntegrityRotatingHandler(
        main_log, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setFormatter(ForensicFormatter())
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    # ── Syslog (optional) ──
    if config.get("alerts", {}).get("syslog", False):
        try:
            syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
            syslog_handler.setFormatter(ForensicFormatter())
            syslog_handler.setLevel(logging.WARNING)
            logger.addHandler(syslog_handler)
        except Exception:
            pass  # syslog may not be available

    # ── Console (for debug / foreground mode) ──
    console = logging.StreamHandler()
    console.setFormatter(ForensicFormatter())
    console.setLevel(logging.INFO)
    logger.addHandler(console)

    return logger


def log_event(logger: logging.Logger, level: int, message: str, **kwargs):
    """
    Convenience wrapper to emit a forensic event.
    Extra kwargs become fields in the JSON record.
    """
    extra = {}
    for key in ("event_type", "monitor", "details", "severity",
                "alert_id", "evidence_hash", "raw_data"):
        if key in kwargs:
            extra[key] = kwargs[key]

    logger.log(level, message, extra=extra)


def _hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Return hex digest of a file."""
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_data(data: str | bytes, algorithm: str = "sha256") -> str:
    """Return hex digest of arbitrary data."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.new(algorithm, data).hexdigest()


def _get_hostname() -> str:
    """Return best-effort hostname across Linux/Windows runtimes."""
    try:
        return os.uname().nodename
    except Exception:
        return os.environ.get("HOSTNAME") or os.environ.get("COMPUTERNAME") or "unknown-host"


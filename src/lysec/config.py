"""
DFTool Configuration
Default configuration and YAML config loader.
"""

import os
import yaml
from pathlib import Path

# ──────────────────────────────────────────────
# Default paths
# ──────────────────────────────────────────────
DEFAULT_CONFIG_PATH = "/etc/lysec/lysec.yaml"
LEGACY_CONFIG_PATH = "/etc/dftool/dftool.yaml"
DEFAULT_LOG_DIR = "/var/log/lysec"
DEFAULT_EVIDENCE_DIR = "/var/lib/lysec/evidence"
DEFAULT_PID_FILE = "/var/run/lysec/lysecd.pid"
DEFAULT_ALERT_LOG = "/var/log/lysec/alerts.log"

# ──────────────────────────────────────────────
# Default configuration dictionary
# ──────────────────────────────────────────────
DEFAULT_CONFIG = {
    "daemon": {
        "pid_file": DEFAULT_PID_FILE,
        "user": "root",
        "group": "root",
        "watchdog": {
            "enabled": True,
            "pid_file": "/var/run/lysec/lysec-watchdog.pid",
            "heartbeat_socket": "/var/run/lysec/lysec-heartbeat.sock",
            "heartbeat_interval_sec": 2,
            "heartbeat_timeout_sec": 8,
            "restart_cooldown_sec": 20,
            "service_name": "lysec.service",
        },
    },
    "logging": {
        "log_dir": DEFAULT_LOG_DIR,
        "evidence_dir": DEFAULT_EVIDENCE_DIR,
        "max_log_size_mb": 100,
        "log_rotation_count": 10,
        "hash_algorithm": "sha256",            # hash every log file for integrity
        "log_format": "json",                   # json | plain
        "utc_timestamps": True,                 # forensic best-practice
    },
    "monitors": {
        "usb": {
            "enabled": True,
            "poll_interval": 1,                 # seconds
            "alert_on_new_device": True,
            "unknown_device_severity": "MEDIUM",
            "storage_device_severity": "MEDIUM",
            "emit_mount_event": True,
            "mount_enrich_timeout_sec": 15,
            "whitelist": [],                    # list of known vendor:product ids
        },
        "ports": {
            "enabled": True,
            "poll_interval": 1,
            "subsystems": [
                "usb",
                "thunderbolt",
                "net",
                "block",
                "sound",
                "drm",
                "pci",
            ],
            "alert_on_change": False,
        },
        "login": {
            "enabled": True,
            "watch_files": [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/wtmp",
                "/var/log/btmp",
            ],
            "alert_on_root_login": True,
            "alert_on_failed_login": True,
            "failed_login_threshold": 5,        # within window
            "failed_login_window_sec": 300,
        },
        "network": {
            "enabled": True,
            "poll_interval": 5,
            "alert_on_new_listener": True,
            "alert_on_promiscuous": True,       # NIC in promisc mode
            "alert_on_new_interface": True,
            "alert_on_new_connection": True,
            "monitored_ports": [],              # empty = all
            "baseline_listeners": [],           # auto-populated at first run
        },
        "process": {
            "enabled": True,
            "poll_interval": 1,
            "alert_on_new_process": True,
            "alert_on_privilege_escalation": True,
            "suspicious_names": [
                "nc", "ncat", "nmap", "socat", "tcpdump",
                "wireshark", "ettercap", "hydra", "john",
                "hashcat", "mimikatz", "msfconsole",
                "reverse_shell", "bind_shell",
            ],
        },
        "filesystem": {
            "enabled": True,
            "watch_paths": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/ssh/sshd_config",
                "/etc/crontab",
                "/etc/cron.d",
                "/etc/systemd/system",
                "/root/.ssh",
                "/tmp",
                "/var/tmp",
                "/media",
                "/run/media",
                "/mnt",
            ],
            "recursive": True,
            "watch_removable_media": True,
            "mount_watch_roots": ["/media", "/run/media", "/mnt"],
            "enable_actor_attribution": True,
            "alert_on_modify": True,
            "alert_on_create": True,
            "alert_on_delete": True,
            "fuzzy_hashing": {
                "enabled": True,
                "algorithms": ["ssdeep", "tlsh"],
            },
        },
    },
    "alerts": {
        "alert_log": DEFAULT_ALERT_LOG,
        "console": True,
        "syslog": True,
        "integrity_chain": {
            "enabled": True,
            "seed": "",
        },
        "correlation": {
            "enabled": True,
            "model_name": "FACES-v1",
            "window_sec": 300,
            "min_unique_monitors": 2,
            "min_score": 45,
            "emit_suppress_sec": 180,
            "score_weights": {
                "severity": 4.0,
                "diversity": 7.0,
                "burst": 20.0,
                "rarity": 25.0,
                "chain": 1.0,
            },
            "chain_patterns": [
                {
                    "name": "credential_to_execution",
                    "events": [
                        "LOGIN_FAILED",
                        "BRUTE_FORCE_DETECTED",
                        "SUSPICIOUS_PROCESS",
                    ],
                    "bonus": 14,
                },
                {
                    "name": "lateral_to_privilege",
                    "events": [
                        "LOGIN_SUCCESS",
                        "UID_CHANGE",
                        "PRIVILEGE_ESCALATION",
                    ],
                    "bonus": 16,
                },
                {
                    "name": "network_recon_chain",
                    "events": [
                        "NEW_INTERFACE",
                        "PROMISCUOUS_MODE",
                        "NEW_LISTENER",
                    ],
                    "bonus": 12,
                },
            ],
        },
        "mitre": {
            "enabled": True,
            "default_confidence": 0.7,
            "overrides": {},
        },
        "ml_anomaly": {
            "enabled": True,
            "model_name": "OnlineZ-v1",
            "window_sec": 300,
            "min_related_events": 3,
            "min_unique_monitors": 2,
            "min_score": 60.0,
            "emit_suppress_sec": 180,
            "warmup_samples": 20,
            "feature_history_limit": 1000,
            "feature_weights": {
                "corr_score": 2.4,
                "monitor_count": 1.8,
                "event_count": 1.6,
                "chain_count": 1.0,
                "rarity": 1.4,
            },
        },
        "email": {
            "enabled": False,
            "smtp_server": "",
            "smtp_port": 587,
            "from_addr": "",
            "to_addr": "",
            "username": "",
            "password": "",
        },
        "webhook": {
            "enabled": False,
            "url": "",
        },
    },
}


def load_config(path: str = None) -> dict:
    """
    Load configuration from YAML file, falling back to defaults.
    User config values are merged on top of DEFAULT_CONFIG.
    """
    config = _deep_copy_dict(DEFAULT_CONFIG)
    if path:
        config_path = path
    else:
        config_path = DEFAULT_CONFIG_PATH if os.path.isfile(DEFAULT_CONFIG_PATH) else LEGACY_CONFIG_PATH

    if os.path.isfile(config_path):
        with open(config_path, "r") as fh:
            user_config = yaml.safe_load(fh) or {}
        config = _deep_merge(config, user_config)

    # Ensure directories exist
    for d in [
        config["logging"]["log_dir"],
        config["logging"]["evidence_dir"],
        os.path.dirname(config["daemon"]["pid_file"]),
    ]:
        Path(d).mkdir(parents=True, exist_ok=True)

    return config


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _deep_copy_dict(d: dict) -> dict:
    """Simple deep copy for nested dicts/lists."""
    import copy
    return copy.deepcopy(d)


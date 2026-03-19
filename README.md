# DFTool — Digital Forensics Monitoring Daemon

> **Detect · Log · Alert — Never Prevent**

A Linux daemon that continuously monitors system activity and produces forensic-grade,
tamper-evident logs for post-incident digital forensics and timeline reconstruction.

**DFTool is a passive forensic tool. It observes and records — it does NOT prevent,
block, or modify any system behaviour.** This is by design: preserving an untainted
evidence trail is more valuable than inline prevention for forensic investigations.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  dftoold (daemon)                                                │
│                                                                  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────┐  │
│  │ USB Monitor│ │Login Monitor│ │Net Monitor │ │Process Monitor│  │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └──────┬───────┘  │
│        │              │              │               │           │
│  ┌─────┴──────────────┴──────────────┴───────────────┴───────┐  │
│  │                    Alert Engine                             │  │
│  │  (deduplicate, correlate, score incidents, dispatch, fan-out)│  │
│  └─────┬──────────┬──────────┬──────────┬────────────────────┘  │
│        │          │          │          │                        │
│  ┌─────┴──┐ ┌────┴───┐ ┌───┴────┐ ┌───┴─────┐                  │
│  │JSON Log│ │ Syslog │ │ Email  │ │ Webhook │                   │
│  └────────┘ └────────┘ └────────┘ └─────────┘                   │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │         Forensic Logger (SHA-256 integrity hashing)        │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────┐                                                │
│  │  FS Monitor   │  (inotify via watchdog)                       │
│  └──────────────┘                                                │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  dftool (CLI)                                                    │
│  status | alerts | timeline | search | export | verify           │
└──────────────────────────────────────────────────────────────────┘
```

## What It Monitors

| Monitor      | What it watches                                      | Key alerts                                         |
|-------------|------------------------------------------------------|---------------------------------------------------|
| **USB**      | USB device attach/detach via udev or sysfs           | Unknown device, mass storage, BadUSB              |
| **Login**    | auth.log, secure, wtmp, btmp                         | Root login, brute-force, failed auth, sudo, su    |
| **Network**  | Listening sockets, interfaces, promiscuous mode      | New listener, rogue NIC, sniffing detected        |
| **Process**  | Process table via psutil                              | Suspicious tools (nmap, nc…), privilege escalation|
| **Filesystem**| Critical paths via inotify (watchdog)               | /etc/passwd, shadow, sudoers, cron, SSH keys      |

## Stronger Novel Capability: Cross-Monitor Incident Correlation

DFTool now includes a correlation layer that promotes isolated alerts into a
single high-confidence incident when multiple monitors report related activity
within a time window.

- Correlates by shared forensic indicators (`ip`, `user`, `pid`, `interface`, `path`, `serial`, `host`, `listener`)
- Uses a named composite score model (`FACES-v1`) across contributing events
- Emits a `CORRELATED_INCIDENT` alert with linked contributing alert IDs
- Suppresses duplicate incident emissions for the same campaign key

`FACES-v1` combines five components:
- Severity evidence from contributing alert severities
- Monitor diversity bonus (more independent monitors = stronger confidence)
- Burst bonus (tighter event clustering in time = stronger confidence)
- Indicator rarity bonus (rarer indicator in window = stronger confidence)
- Attack-chain bonus from ordered event patterns (e.g., login abuse → suspicious execution)

This makes the output stronger for investigations because analysts get
campaign-level evidence, not only individual point alerts.

## Why Detection-Only (Not Prevention)?

This is a **forensic** tool, not an IDS/IPS. Here's why:

1. **Evidence integrity** — Inline prevention modifies system state, potentially destroying forensic evidence
2. **Non-interference** — A monitoring tool that blocks activity can itself become a point of failure
3. **Timeline accuracy** — Clean, unaltered logs are admissible as evidence; modified state is not
4. **Complementary** — Use DFTool alongside prevention tools (iptables, SELinux, fail2ban) — it provides the forensic layer they lack
5. **False positive safety** — Blocking on false positives causes outages; logging on false positives is harmless

## Installation

```bash
# Clone the repository
git clone <repo-url> && cd DF_Tool

# Run installer (as root)
sudo ./install.sh
```

The installer will:
- Install Python dependencies
- Copy config to `/etc/dftool/dftool.yaml`
- Install systemd service
- Create log/evidence directories with proper permissions

## Quick Start

```bash
# Start the daemon
sudo systemctl start dftool

# Check status
sudo systemctl status dftool
sudo dftool status

# View real-time alerts
sudo dftool alerts --last 1h

# Run in foreground (debug mode)
sudo dftoold start --foreground
```

## CLI Usage

```bash
# View recent alerts filtered by severity
sudo dftool alerts --severity HIGH --last 2h

# Generate forensic timeline
sudo dftool timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59

# Filter timeline by monitor
sudo dftool timeline --monitor usb

# Full-text search across all logs
sudo dftool search --query "nmap"

# Export evidence to JSON or CSV
sudo dftool export --format json --output /tmp/evidence.json
sudo dftool export --format csv --output /tmp/timeline.csv

# Verify log integrity (SHA-256 manifests)
sudo dftool verify

# Evaluate correlation models on replayed alerts
sudo dftool-eval --alerts-file /var/log/dftool/alerts.log --top 10
```

## Correlation Evaluation

Use the evaluator to benchmark baseline correlation (severity sum) versus
`FACES-v1` on historical JSONL alerts.

```bash
sudo dftool-eval \
  --alerts-file /var/log/dftool/alerts.log \
  --window-sec 300 \
  --baseline-min-score 8 \
  --faces-min-score 45 \
  --output-json /tmp/dftool_eval.json \
  --output-csv /tmp/dftool_eval_incidents.csv \
  --top 10
```

The report includes incident counts, overlap, average score/event richness,
top-scoring FACES incidents, and matched chain-pattern frequencies.
Use export flags to produce paper-ready artifacts:
- `--output-json` writes full summary + both model incident sets.
- `--output-csv` writes incident-level rows for tables/plots.

Generate publication-ready plots from evaluator outputs:

```bash
sudo dftool-eval-plot \
  --input-json /tmp/dftool_eval.json \
  --output-dir /tmp/dftool_eval_plots
```

Plot artifacts generated:
- `threshold_sweep.png` (incident count vs score threshold)
- `score_distribution.png` (baseline vs FACES score histogram)
- `model_comparison.png` (incident count, avg score, avg monitor diversity)
- `chain_pattern_frequency.png` (FACES matched chain-pattern frequency)
- `threshold_sweep.csv` (table backing the threshold sweep figure)
- `model_comparison.csv` (table backing the model comparison figure)
- `chain_pattern_frequency.csv` (table backing chain frequency figure)

## Configuration

Edit `/etc/dftool/dftool.yaml` to customise:

```yaml
monitors:
  usb:
    enabled: true
    whitelist: ["8087:0024"]          # Known USB devices

  login:
    failed_login_threshold: 5         # Brute-force detection
    failed_login_window_sec: 300

  network:
    alert_on_promiscuous: true        # Detect sniffing

  process:
    suspicious_names:                 # Add your own
      - nc
      - nmap
      - tcpdump

  filesystem:
    watch_paths:                      # Add paths to monitor
      - /etc/passwd
      - /etc/shadow
      - /root/.ssh

alerts:
  syslog: true
  correlation:
    enabled: true
    model_name: FACES-v1
    window_sec: 300
    min_unique_monitors: 2
    min_score: 45
    score_weights:
      severity: 4.0
      diversity: 7.0
      burst: 20.0
      rarity: 25.0
      chain: 1.0
  email:
    enabled: true
    smtp_server: smtp.example.com
    to_addr: soc@example.com
  webhook:
    enabled: true
    url: https://hooks.slack.com/...
```

Reload config without restart:
```bash
sudo systemctl reload dftool   # sends SIGHUP
```

## Log Format

Every log entry is a self-contained JSON record (one per line), compatible with
SIEM tools, Plaso, Timesketch, and Splunk:

```json
{
  "timestamp": "2026-02-21T14:30:00.123456+00:00",
  "epoch": 1771595400.123,
  "hostname": "forensic-ws",
  "session_id": "a1b2c3d4-...",
  "level": "WARNING",
  "source": "dftool.monitor.usb",
  "message": "USB ATTACHED: SanDisk Ultra [0781:5583] serial=ABC123",
  "event_type": "USB_DEVICE_ATTACHED",
  "monitor": "usb",
  "severity": "HIGH",
  "details": {
    "vendor_id": "0781",
    "product_id": "5583",
    "vendor": "SanDisk",
    "serial": "ABC123"
  }
}
```

## Log Integrity

- Every rotated log file is SHA-256 hashed and recorded in a `.sha256` manifest
- Use `dftool verify` to check all logs against their manifests
- Tampered files are flagged immediately

## File Locations

| Path                          | Purpose                     |
|-------------------------------|-----------------------------|
| `/etc/dftool/dftool.yaml`     | Configuration               |
| `/var/log/dftool/dftool.log`  | Main forensic event log     |
| `/var/log/dftool/alerts.log`  | Alert-specific log          |
| `/var/log/dftool/*.sha256`    | Integrity manifests         |
| `/var/lib/dftool/evidence/`   | Evidence artifacts          |
| `/var/run/dftool/dftoold.pid` | Daemon PID file             |

## Dependencies

- Python 3.8+
- `pyudev` — USB monitoring via udev
- `psutil` — Process and network monitoring
- `watchdog` — Filesystem monitoring via inotify
- `pyyaml` — Configuration parsing
- `rich` — CLI table formatting (optional but recommended)

## Uninstall

```bash
sudo ./uninstall.sh
```

Forensic data (logs, evidence, config) is preserved by default.

## License

MIT

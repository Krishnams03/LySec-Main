# LySec - Linux Forensics Monitoring Daemon

> Detect - Log - Alert - Correlate (No Prevention)

LySec is a Linux daemon that continuously monitors host activity and writes
forensic-grade, tamper-evident logs for post-incident investigation and
timeline reconstruction.

LySec is intentionally passive: it detects and records events, but does not block,
kill, or prevent activity.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  lysecd (daemon)                                                 │
│                                                                  │
│  USB | Ports | Login | Network | Process | Filesystem monitors   │
│                            │                                     │
│                        Alert Engine                              │
│                            │                                     │
│               JSON logs | syslog | email | webhook               │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  lysec (CLI) and lysec-gui (desktop dashboard)                  │
└──────────────────────────────────────────────────────────────────┘
```

## What LySec Monitors

| Monitor | Coverage | Example alerts |
|---|---|---|
| USB | Device attach/detach via udev/sysfs | Unknown device, removable media |
| Ports | Dynamic udev hotplug across usb/thunderbolt/net/block/sound/drm/pci | Port device add/remove/change |
| Login | auth.log/secure/wtmp/btmp | Root login, brute-force, sudo/su |
| Network | Listeners, interfaces, promisc mode | New listener, rogue NIC, sniffing |
| Process | Process table and UID changes | Suspicious binary, privilege escalation |
| Filesystem | Critical paths via inotify/watchdog | passwd/shadow/ssh/cron tampering |

### Dynamic Handling After Startup

LySec continuously handles runtime changes after the daemon is already running:

1. Ports hotplug: `ports` monitor captures realtime add/remove/change for configured subsystems.
2. Filesystem changes: `filesystem` monitor watches configured paths and dynamically mounted removable media.
3. Process activity: `process` monitor continuously diffs live process table for new processes and UID changes.

Quick checks:

```bash
sudo lysec alerts --last 15m
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59 --monitor ports
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59 --monitor filesystem
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59 --monitor process
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59 --monitor ml
```

## Why Detect-Only

1. Preserves evidence integrity.
2. Avoids interference with production systems.
3. Improves timeline reliability.
4. Complements prevention controls (iptables, SELinux, fail2ban).
5. Reduces outage risk from false positives.

## Detection Modes

LySec uses hybrid detection:

1. Rule-based monitor alerts (deterministic events from usb/ports/login/network/process/filesystem).
2. Heuristic cross-monitor correlation (`CORRELATED_INCIDENT`, FACES-v1 scoring).
3. Live ML-style anomaly ranking (`ML_ANOMALY_INCIDENT`, OnlineZ-v1).

This keeps runtime explainable while still prioritizing unusual multi-signal activity.

## MITRE ATT&CK Enrichment

LySec supports MITRE ATT&CK-aligned enrichment for alerts.

1. Each matching alert includes `details.mitre` metadata.
2. Fields include `tactic`, `technique_id`, `technique_name`, and `confidence`.
3. This is enrichment only; it does not change detect-only behavior.

Configure under `alerts.mitre` in `/etc/lysec/lysec.yaml`:

```yaml
alerts:
  mitre:
    enabled: true
    default_confidence: 0.7
    overrides: {}
```

After changing config:

```bash
sudo systemctl restart lysec
sudo lysec alerts --last 15m
```

## Fuzzy Hashing (ssdeep / TLSH)

LySec now supports fuzzy hashing for filesystem events so near-similar file versions can be compared.

Why this helps:

1. SHA-256 changes fully even for a 1-byte modification.
2. Fuzzy hashes provide similarity context across versions.
3. Alerts can include `fuzzy_similarity` values (`ssdeep_score` and `tlsh_distance`).

Config (`monitors.filesystem.fuzzy_hashing`):

```yaml
monitors:
  filesystem:
    fuzzy_hashing:
      enabled: true
      algorithms: [ssdeep, tlsh]
```

Linux dependency note:

```bash
sudo apt install -y libfuzzy-dev
pip install -e .
```

## Installation

```bash
git clone <repo-url> && cd DF_Tool
python3 -m venv .venv
source .venv/bin/activate
chmod +x install.sh uninstall.sh scripts/*.sh
sudo ./install.sh
```

Step-by-step:

1. Create and activate virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Grant execute permission for install/uninstall/demo scripts.

```bash
chmod +x install.sh uninstall.sh scripts/*.sh
```

3. Install LySec system-wide service and command links.

```bash
sudo ./install.sh
```

4. Optional dev-mode install in your current venv.

```bash
pip install -e .
```

5. Start and verify service.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lysec
sudo systemctl status lysec
```

## Watchdog (Double-Daemon Pattern)

LySec includes a transparent watchdog daemon pattern:

1. Primary daemon: `lysecd` handles forensic monitoring.
2. Watchdog daemon: `lysec-watchdog` monitors primary liveness.
3. Heartbeat channel: Unix domain socket (`/var/run/lysec/lysec-heartbeat.sock`).
4. On missed heartbeat or dead PID, watchdog emits critical alert and attempts controlled restart of `lysec.service`.

Start and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lysec lysec-watchdog
sudo systemctl status lysec
sudo systemctl status lysec-watchdog
sudo lysec alerts --last 15m
```

Watchdog configuration is under `daemon.watchdog` in `/etc/lysec/lysec.yaml`.

## Changes Done So Far

High-level implementation status of this project:

1. Rebrand and packaging migration from DFTool to LySec.
2. Venv-based installer flow to avoid externally-managed environment issues.
3. Core monitors implemented: USB, Ports, Login, Network, Process, Filesystem.
4. Dynamic removable-media filesystem watch after daemon startup.
5. CLI enhancements:
  - `alerts`, `timeline`, `search`, `export`, `verify`
  - `anomalies` (ML-ranked incidents)
  - `split` (per-monitor outputs)
  - `correlate` (scenario/custom event-chain matching)
6. Correlation improvements:
  - sequence alias handling
  - filesystem event name normalization (`FS_*` compatibility)
7. Live ML-style anomaly scoring integrated into alert pipeline.
8. MITRE ATT&CK enrichment integrated into alert details.
9. Fuzzy hashing support for filesystem events:
  - `ssdeep`
  - `TLSH`
  - similarity fields in alert details
10. Systemd hardening profile and auditd rule pack for tamper visibility.
11. Boot ordering tuned for pre-login startup behavior.
12. New watchdog double-daemon with Unix-socket heartbeat and restart response.
13. GUI enhancements for filtering, time handling, diagnostics, and analyst decision support.
14. Demo and runbook assets for coordinator walkthroughs.

## Kali PASS/FAIL Validation Checklist

Use this checklist for complete end-to-end validation on Linux/Kali.

### Pre-check

```bash
pip install -e .
sudo systemctl daemon-reload
sudo systemctl enable --now lysec lysec-watchdog
sudo systemctl status lysec
sudo systemctl status lysec-watchdog
```

Pass criteria:

1. `lysec` service is `active (running)`.
2. `lysec-watchdog` service is `active (running)`.

### Test Matrix

1. USB attach/detach detection
  - Action: plug USB, wait 5s, unplug.
  - Check: `sudo lysec alerts --last 15m`.
  - PASS if both `USB_DEVICE_ATTACHED` and `USB_DEVICE_REMOVED` appear.

2. Port activity detection
  - Action: plug/unplug any external port device.
  - Check: `sudo lysec timeline --start 2026-03-23T00:00:00 --end 2026-03-23T23:59:59 --monitor ports`.
  - PASS if `PORT_DEVICE_ADDED` or `PORT_DEVICE_REMOVED` appears.

3. Filesystem create/modify/delete detection
  - Action:
    ```bash
    echo a > /tmp/lysec_test.txt
    echo b >> /tmp/lysec_test.txt
    rm -f /tmp/lysec_test.txt
    ```
  - Check: `sudo lysec timeline --start 2026-03-23T00:00:00 --end 2026-03-23T23:59:59 --monitor filesystem`.
  - PASS if `FS_FILE_CREATED`, `FS_FILE_MODIFIED`, and `FS_FILE_DELETED` appear.

4. Process suspicious command detection
  - Action: run `nmap -sn 127.0.0.1/24` (or any configured suspicious binary).
  - Check: `sudo lysec timeline --start 2026-03-23T00:00:00 --end 2026-03-23T23:59:59 --monitor process`.
  - PASS if `PROCESS_STARTED` and `SUSPICIOUS_PROCESS` appear.

5. Network connection correlation signal
  - Action: run a command that creates an outbound connection (for example `nmap -sn 127.0.0.1/24`).
  - Check: `sudo lysec timeline --start 2026-03-23T00:00:00 --end 2026-03-23T23:59:59 --monitor network`.
  - PASS if `NEW_CONNECTION` appears with `pid` and `ip` details.

6. Correlation sequence detection
  - Action: perform USB attach, suspicious process run, and filesystem modify in same window.
  - Check:
    ```bash
    sudo lysec correlate --sequence USB_DEVICE_ATTACHED,SUSPICIOUS_PROCESS,FS_FILE_MODIFIED --last 6h --window 30m
    ```
  - PASS if at least one correlated chain is returned.

7. MITRE enrichment
  - Check: `sudo lysec export --format json --output /tmp/lysec_alerts.json --source alerts`.
  - PASS if alert `details` include a `mitre` object with tactic/technique fields.

8. Fuzzy hashing fields
  - Action: modify same file multiple times in a watched path.
  - Check exported alerts JSON.
  - PASS if filesystem details include `fuzzy_hash` and `fuzzy_similarity` on modifications.

9. Watchdog recovery
  - Action: stop primary service `sudo systemctl stop lysec`.
  - Check within timeout:
    ```bash
    sudo systemctl status lysec
    sudo lysec alerts --last 15m
    ```
  - PASS if watchdog restarts primary and emits watchdog critical/restart events.

### Final Evidence Bundle

```bash
sudo lysec split --last 2h --output-dir /tmp/lysec_split
sudo lysec export --format json --output /tmp/lysec_evidence.json --source all
sudo lysec export --format csv --output /tmp/lysec_timeline.csv --source all
sudo lysec verify
```

Overall readiness rule:

1. Mark each test as PASS/FAIL.
2. Require 9/9 PASS for full acceptance.
3. Any FAIL must include root-cause note and re-test result.
Installer actions:
1. Creates isolated venv at `/opt/lysec/.venv`.
2. Installs package and dependencies.
3. Installs config at `/etc/lysec/lysec.yaml`.
4. Installs systemd unit `lysec.service`.
5. Creates command links in `/usr/local/bin`.

### PEP 668 note

On modern Debian/Ubuntu/Kali, system pip is externally managed. LySec avoids this by using
its own virtual environment.

If required:

```bash
sudo apt update
sudo apt install -y python3-venv
sudo ./install.sh
```

## Quick Start

```bash
sudo systemctl start lysec
sudo systemctl status lysec
sudo lysec status
sudo lysec alerts --last 1h
```

Run foreground debug mode:

```bash
sudo lysecd start --foreground
```

Launch GUI:

```bash
lysec-gui
```

### Boot Startup Behavior

LySec runs as a systemd service and starts during boot (before interactive user login) when enabled.

Verify:

```bash
sudo systemctl is-enabled lysec
sudo systemctl status lysec
sudo journalctl -u lysec --since "today"
```

If you changed unit files, reload and re-enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lysec
```

## Day-1 Forensic Checklist (Copy/Paste)

Use this single block on a fresh Linux host.

```bash
# 1) clone + venv + permissions
git clone <repo-url> && cd DF_Tool
python3 -m venv .venv
source .venv/bin/activate
chmod +x install.sh uninstall.sh scripts/*.sh

# 2) install + start service
sudo ./install.sh
sudo systemctl daemon-reload
sudo systemctl enable --now lysec

# 3) health checks
sudo systemctl status lysec
sudo lysec status
sudo lysec alerts --last 30m

# 4) per-monitor separation (ports/process/login/filesystem/etc)
sudo lysec split --last 2h --output-dir /tmp/lysec_split

# 5) attack-chain correlation (example: usb -> login -> file modify)
sudo lysec correlate --scenario usb_login_modify --last 6h --window 30m --top 20 --output /tmp/lysec_chain_report.json

# 6) ml anomaly triage
sudo lysec anomalies --last 2h --top 20 --min-score 60

# 7) timeline + export + integrity
sudo lysec timeline --start 2026-03-23T00:00:00 --end 2026-03-23T23:59:59
sudo lysec export --format json --output /tmp/lysec_evidence.json --source all
sudo lysec export --format csv --output /tmp/lysec_timeline.csv --source all
sudo lysec verify
```

Expected artifacts:

1. `/tmp/lysec_split/*.json` per-monitor alert files.
2. `/tmp/lysec_chain_report.json` chain-correlation report.
3. `/tmp/lysec_evidence.json` and `/tmp/lysec_timeline.csv` exported evidence.

## Operational Timeline Runbook

Use the following sequence in order during operations and investigations.

1. Load latest unit definitions.

```bash
sudo systemctl daemon-reload
```

Purpose: reloads systemd unit files after install/changes.
Analysis: continue only if no unit parse errors are shown.

2. Enable autostart.

```bash
sudo systemctl enable lysec
```

Purpose: starts LySec on every boot.
Analysis: confirm output contains created symlink and enabled state.

3. Start the daemon.

```bash
sudo systemctl start lysec
```

Purpose: launches LySec in background.
Analysis: if start fails, inspect service logs in step 5.

4. Verify service state.

```bash
sudo systemctl status lysec
```

Purpose: confirms active/running status and PID.
Analysis: good state is `active (running)`.

5. Live service event stream.

```bash
sudo journalctl -u lysec -f
```

Purpose: tails daemon/service logs in real time.
Analysis: look for monitor start lines and warnings/errors.

6. CLI health snapshot.

```bash
sudo lysec status
```

Purpose: LySec-level health and log directory visibility.
Analysis: confirms daemon detection and current log files.

7. Recent alerts (triage view).

```bash
sudo lysec alerts --last 30m
```

Purpose: fetches latest alert timeline.
Analysis: review by severity first: CRITICAL, HIGH, MEDIUM.

8. Full time-bounded timeline.

```bash
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59
```

Purpose: reconstructs host activity chronology for a fixed window.
Analysis: identify event chains across monitors.

9. Indicator pivots.

```bash
sudo lysec search --query "root"
sudo lysec search --query "192.168."
sudo lysec search --query "sudo"
```

Purpose: pivots investigation by user/IP/privilege indicators.
Analysis: repeated indicator across multiple event types increases confidence.

10. Export evidence artifacts.

```bash
sudo lysec export --format json --output /tmp/lysec_evidence.json --source all
sudo lysec export --format csv --output /tmp/lysec_timeline.csv --source all
```

Purpose: creates portable evidence for reporting and external analysis.
Analysis: prefer JSON for fidelity, CSV for quick spreadsheet review.

11. Validate evidence integrity.

```bash
sudo lysec verify
```

Purpose: checks log files against SHA-256 manifests.
Analysis: any tampered/missing result must be treated as an integrity incident.

12. Correlation analysis.

```bash
sudo lysec-eval --alerts-file /var/log/lysec/alerts.log --window-sec 300 --top 10 --output-json /tmp/lysec_eval.json --output-csv /tmp/lysec_eval_incidents.csv
sudo lysec-eval-plot --input-json /tmp/lysec_eval.json --output-dir /tmp/lysec_eval_plots
```

Purpose: groups related low-level alerts into higher-confidence incidents.
Analysis: prioritize highest scores and multi-monitor incidents.

13. End-of-session shutdown.

```bash
sudo systemctl stop lysec
sudo systemctl status lysec
```

Purpose: cleanly stops monitors and confirms state.
Analysis: expected final state is inactive/dead.

### Analysis Workflow

1. Define exact time window first.
2. Review alerts in that window.
3. Pivot by indicator (`ip`, `user`, `pid`, `path`, `serial`).
4. Confirm sequence in `timeline` output.
5. Export JSON/CSV evidence.
6. Run `lysec verify` before sharing evidence.
7. Run `lysec-eval` for campaign-level incident correlation.

## Coordinator Demo (USB + Process + Filesystem)

Use this exact sequence tomorrow to demonstrate monitor coverage end-to-end.

### Terminal A - start and show service health

```bash
sudo systemctl start lysec
sudo systemctl status lysec
sudo lysec status
```

What this proves:
1. Daemon is active.
2. LySec CLI can read runtime state.
3. Log paths are available.

### Terminal B - live filtered event feed

```bash
sudo python3 scripts/live_demo_view.py
```

What this shows:
1. Real-time alert stream.
2. Only `usb`, `process`, and `filesystem` events are displayed.

### Terminal C - trigger demo events

```bash
chmod +x scripts/demo_triggers.sh
sudo bash scripts/demo_triggers.sh
```

What this triggers:
1. Filesystem create/modify/delete in `/tmp`.
2. Process suspicious-command event (best effort, depends on installed tools).
3. USB prompt for manual plug/unplug.

### Manual USB step (during Terminal C)

1. Plug in a USB flash drive.
2. Wait 3-5 seconds.
3. Unplug the USB drive.

Expected live output in Terminal B:
1. `USB_DEVICE_ATTACHED`
2. `USB_DEVICE_REMOVED`

### Post-demo verification commands

```bash
sudo lysec alerts --last 15m
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59 --monitor filesystem
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59 --monitor process
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59 --monitor usb
```

### One-command showcase demo (USB + process + filesystem + fuzzy + watchdog)

Use this when presenting to faculty and you need a full proof sequence quickly.

```bash
chmod +x scripts/demo_showcase.sh
sudo python3 scripts/live_demo_view.py --show-fuzzy
sudo bash scripts/demo_showcase.sh
```

What this one-shot demo covers:

1. Filesystem create/modify/delete events.
2. Fuzzy hash and fuzzy similarity fields on file modifications.
3. Suspicious process event (best effort based on installed tools).
4. USB attach/mount/remove events (manual plug/unplug step).
5. Watchdog restart proof after primary daemon stop.

### How to explain analysis to coordinator

1. Time-order proof: events are timestamped in UTC and sortable.
2. Multi-source proof: USB, process, and filesystem are independently monitored.
3. Forensic integrity proof: run `sudo lysec verify` to validate log manifests.
4. Design intent proof: LySec is detect-and-log only, preserving evidence state.

## CLI Commands

Use these commands as a practical forensic workflow reference.

### Service and Health

```bash
sudo lysec status
sudo systemctl status lysec
sudo journalctl -u lysec -f
```

### Alert Triage

```bash
sudo lysec alerts --severity HIGH --last 2h
sudo lysec anomalies --last 2h --top 20 --min-score 60
sudo lysec alerts --last 15m
```

### Per-Monitor Separation

```bash
sudo lysec split --last 2h --output-dir /tmp/lysec_split
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59 --monitor usb
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59 --monitor ports
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59 --monitor login
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59 --monitor process
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59 --monitor filesystem
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59 --monitor network
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59 --monitor ml
```

### Correlation and Attack Chains

```bash
sudo lysec correlate --scenario usb_login_modify --last 6h --window 30m --top 20 --output /tmp/lysec_chain_report.json
sudo lysec correlate --scenario usb_login_delete --last 6h --window 30m
sudo lysec correlate --scenario usb_to_priv_esc --last 12h --window 1h
sudo lysec correlate --sequence USB_DEVICE_ATTACHED,LOGIN_SUCCESS,FS_FILE_MODIFIED --last 6h --window 45m
```

### Timeline and Search

```bash
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59
sudo lysec search --query "nmap"
sudo lysec search --query "root"
sudo lysec search --query "192.168."
```

### Evidence Export and Integrity

```bash
sudo lysec export --format json --output /tmp/evidence.json
sudo lysec export --format csv --output /tmp/timeline.csv
sudo lysec verify
```

Use `lysec anomalies` to rank only live ML anomaly incidents by anomaly score for fast triage.

Use `lysec split` to get separate per-monitor outputs (ports, process, login, filesystem, usb, network, ml, correlation).

Use `lysec correlate` to detect attack chains such as USB insertion followed by login then file modification.

## Correlation Evaluation

Replay historical alerts and compare baseline vs FACES-v1 scoring.
Optional local ML-style anomaly ranking can be enabled to prioritize unusual incidents.

```bash
sudo lysec-eval \
  --alerts-file /var/log/lysec/alerts.log \
  --window-sec 300 \
  --baseline-min-score 8 \
  --faces-min-score 45 \
  --ml-anomaly \
  --ml-top 10 \
  --output-json /tmp/lysec_eval.json \
  --output-csv /tmp/lysec_eval_incidents.csv \
  --top 10
```

Generate plots:

```bash
sudo lysec-eval-plot \
  --input-json /tmp/lysec_eval.json \
  --output-dir /tmp/lysec_eval_plots
```

## Configuration

Primary config file:

```bash
/etc/lysec/lysec.yaml
```

Key live anomaly toggles (under `alerts.ml_anomaly`):

1. `enabled`: turn live anomaly scoring on/off.
2. `min_score`: anomaly threshold for emitting `ML_ANOMALY_INCIDENT`.
3. `warmup_samples`: number of feature samples before scoring starts.
4. `emit_suppress_sec`: suppression window to prevent duplicate incident floods.

Reload config without full restart:

```bash
sudo systemctl reload lysec
```

## Log Format

Each line is JSON and SIEM-friendly:

```json
{
  "timestamp": "2026-02-21T14:30:00.123456+00:00",
  "epoch": 1771595400.123,
  "hostname": "forensic-ws",
  "level": "WARNING",
  "source": "lysec.monitor.usb",
  "message": "USB ATTACHED: SanDisk Ultra [0781:5583] serial=ABC123",
  "event_type": "USB_DEVICE_ATTACHED",
  "monitor": "usb",
  "severity": "HIGH"
}
```

## Integrity Verification

1. Rotated logs are hashed into `.sha256` manifests.
2. Run `lysec verify` to validate integrity.
3. Modified or missing files are flagged.

## Runtime Paths

| Path | Purpose |
|---|---|
| `/etc/lysec/lysec.yaml` | Main configuration |
| `/var/log/lysec/lysec.log` | Main event log |
| `/var/log/lysec/alerts.log` | Alert log |
| `/var/log/lysec/*.sha256` | Integrity manifests |
| `/var/lib/lysec/evidence/` | Evidence artifacts |
| `/var/run/lysec/lysecd.pid` | PID file |

## Tamper Resistance (Production)

If an attacker gains privileged shell access, they may try to stop local monitoring.
The goal is to make stop/tamper actions noisy and detectable, not silent.

### Hardened systemd profile

A stricter unit template is included at:

- `systemd/lysec-hardened.service`

Apply it:

```bash
sudo cp systemd/lysec-hardened.service /etc/systemd/system/lysec.service
sudo systemctl daemon-reload
sudo systemctl restart lysec
sudo systemctl status lysec
```

### auditd tamper rules

Audit rules are included at:

- `security/auditd/lysec.rules`

Apply them:

```bash
sudo apt install -y auditd audispd-plugins
sudo cp security/auditd/lysec.rules /etc/audit/rules.d/lysec.rules
sudo augenrules --load
sudo systemctl restart auditd
```

Validate rules:

```bash
sudo auditctl -l | grep lysec
```

Query possible tamper events:

```bash
sudo ausearch -k lysec_tamper
sudo ausearch -k lysec_systemctl
sudo ausearch -k lysec_kill
```

Recommended architecture in enterprise:

1. Keep local logs for endpoint timeline.
2. Stream alerts/logs to a remote collector (SIEM/syslog) in near real time.
3. Treat service stop/restart and log tamper as high-severity incidents.

## GUI Notes

The GUI (`lysec-gui`) provides:
1. Service controls (start, stop, restart).
2. Alerts table view.
3. Timeline viewer.
4. Decision Support panel with risk hints.
5. Local/UTC time toggle.

If logs/alerts appear empty in GUI:
1. Confirm service is running: `sudo systemctl status lysec`.
2. Confirm log files exist: `sudo ls -l /var/log/lysec/`.
3. Run GUI with read permissions to logs (often root): `sudo lysec-gui`.
4. Use CLI to verify data exists: `sudo lysec alerts --last 30m`.

Time interpretation:
1. LySec records timestamps in UTC for forensic consistency.
2. GUI can display either UTC or local time (Time selector).
3. For reports, explicitly mention timezone used.

Decision-making guidance:
1. Start with severity trend (CRITICAL/HIGH first).
2. Check monitor diversity (same indicator across multiple monitors increases confidence).
3. Build sequence from timeline: access -> execution -> persistence/network.
4. Export evidence and run `lysec verify` before sharing.

Filesystem events on USB not visible troubleshooting:
1. Ensure filesystem monitor is enabled in `/etc/lysec/lysec.yaml`.
2. Ensure watch paths include mount roots (`/media`, `/run/media`, `/mnt`).
3. Ensure `alert_on_create`, `alert_on_modify`, and `alert_on_delete` are set to `true` under `monitors.filesystem`.
3. Restart service after config change: `sudo systemctl restart lysec`.
4. Confirm live events: `sudo lysec alerts --last 10m | grep filesystem`.
5. Delete/create file on mounted USB and re-check timeline window.

Process suspicious command (`nmap`) not visible troubleshooting:
1. Ensure process monitor is enabled and poll interval is low (`monitors.process.poll_interval: 1`).
2. Run a command that lasts a few seconds (for example, `nmap -sn 127.0.0.1/24`) so polling can observe it.
3. Confirm with `sudo lysec alerts --last 10m` and `sudo lysec timeline --start 2026-03-23T00:00:00 --end 2026-03-23T23:59:59 --monitor process`.

Quick validation commands:

```bash
sudo systemctl restart lysec
sudo lysec alerts --last 10m
sudo lysec timeline --start 2026-03-23T00:00:00 --end 2026-03-23T23:59:59 --monitor filesystem
```

If GUI launch fails on minimal servers:

```bash
sudo apt install -y python3-tk
```

## Backward Compatibility

Legacy command aliases remain available:
1. `dftool`
2. `dftoold`
3. `dftool-eval`
4. `dftool-eval-plot`

## Uninstall

```bash
sudo ./uninstall.sh
```

Logs/evidence/config are intentionally preserved unless manually removed.

## License

MIT

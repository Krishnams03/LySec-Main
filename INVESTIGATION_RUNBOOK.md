# LySec Forensic Investigation Runbook

This guide provides a structured, end-to-end command workflow for conducting a complete forensic investigation using the LySec daemon. 

## Phase 1: Health & State Verification
Before starting the investigation, ensure the daemon is running properly and collecting data.

```bash
# Check systemd service health
sudo systemctl status lysec
sudo systemctl status lysec-prelogin
sudo systemctl status lysec-watchdog

# Check LySec process state and log directory sizes
sudo lysec status

# Tail the live event feed for any immediate errors or active events
sudo journalctl -u lysec -f
```

## Phase 2: Initial Triage
Get a high-level overview of recent suspicious activity.

```bash
# View all recent alerts in the last 2 hours
sudo lysec alerts --last 2h

# Filter exclusively for HIGH and CRITICAL severity events
sudo lysec alerts --severity HIGH --last 2h

# Rank and review only Live ML anomaly incidents
sudo lysec anomalies --last 2h --top 20 --min-score 60
```

## Phase 3: Timeline Reconstruction & Deep Dive
Reconstruct chronological activity for a specific analysis window.
*(Replace timestamps with your specific incident window)*

```bash
# Generate a full chronological timeline for all events
sudo lysec timeline --start 2026-04-18T00:00:00 --end 2026-04-18T23:59:59

# Focus on specific subsystems (Monitors: usb, ports, login, process, filesystem, network)
sudo lysec timeline --start 2026-04-18T00:00:00 --end 2026-04-18T23:59:59 --monitor process
sudo lysec timeline --start 2026-04-18T00:00:00 --end 2026-04-18T23:59:59 --monitor filesystem

# Search for specific indicators of compromise (IoCs)
sudo lysec search --query "192.168."
sudo lysec search --query "nmap"
sudo lysec search --query "root"
```

## Phase 4: Attack Chain & Correlation Analysis
Look for complex multi-stage attack scenarios across different subsystems.

```bash
# Detect standard attack scenarios (e.g., USB attach -> Login -> File Modification)
sudo lysec correlate --scenario usb_login_modify --last 6h --window 30m --top 20 --output /tmp/lysec_chain_report.json

# Detect privilege escalation vectors
sudo lysec correlate --scenario usb_to_priv_esc --last 12h --window 1h

# Manually track a custom malicious sequence
sudo lysec correlate --sequence USB_DEVICE_ATTACHED,SUSPICIOUS_PROCESS,FS_FILE_MODIFIED --last 6h --window 45m
```

## Phase 5: Artifact Export & Separation
Isolate events into distinct files and prepare your evidence for reporting.

```bash
# Split the last few hours of events into separate files per monitor
sudo lysec split --last 4h --output-dir /tmp/lysec_split

# Export ALL evidence into high-fidelity JSON (for SIEM/Log parsing)
sudo lysec export --format json --output /tmp/lysec_evidence.json --source all

# Export timeline into CSV (useful for spreadsheet/Excel review)
sudo lysec export --format csv --output /tmp/lysec_timeline.csv --source all
```

## Phase 6: Integrity Validation
Before sharing any evidence, prove that the log files have not been tampered with.

```bash
# Validate SHA-256 manifests of rotated logs
sudo lysec verify
```

## Phase 7: Post-Incident Campaign Evaluation
For after-action reporting, replay the incidents to compare baseline heuristics vs FACES-v1 machine-learning scoring.

```bash
# Generate campaign-level correlation evaluations
sudo lysec-eval \
  --alerts-file /var/log/lysec/alerts.log \
  --window-sec 300 \
  --ml-anomaly \
  --output-json /tmp/lysec_eval.json \
  --output-csv /tmp/lysec_eval_incidents.csv \
  --top 10

# Plot the evaluation statistics for reports
sudo lysec-eval-plot \
  --input-json /tmp/lysec_eval.json \
  --output-dir /tmp/lysec_eval_plots
```
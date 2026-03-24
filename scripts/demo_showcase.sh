#!/usr/bin/env bash
set -euo pipefail

echo "[LySec Demo] Pre-check services"
sudo systemctl daemon-reload
sudo systemctl enable --now lysec lysec-watchdog
sudo systemctl is-active lysec >/dev/null
sudo systemctl is-active lysec-watchdog >/dev/null
echo "[ok] lysec and lysec-watchdog are active"

echo "[LySec Demo] Trigger filesystem + fuzzy hash events"
DEMO_DIR="/tmp/lysec_fuzzy_demo"
DEMO_FILE="$DEMO_DIR/sample.txt"
mkdir -p "$DEMO_DIR"
echo "alpha alpha alpha" > "$DEMO_FILE"
sleep 1
echo "alpha alpha beta" > "$DEMO_FILE"
sleep 1
echo "alpha beta gamma" > "$DEMO_FILE"
sleep 1
rm -f "$DEMO_FILE"
rmdir "$DEMO_DIR" 2>/dev/null || true
echo "[ok] filesystem create/modify/delete sequence generated"

echo "[LySec Demo] Trigger suspicious process event"
if command -v nc >/dev/null 2>&1; then
  (nc -h >/dev/null 2>&1 || true)
  echo "[ok] ran nc -h"
elif command -v ncat >/dev/null 2>&1; then
  (ncat -h >/dev/null 2>&1 || true)
  echo "[ok] ran ncat -h"
elif command -v nmap >/dev/null 2>&1; then
  (nmap --help >/dev/null 2>&1 || true)
  echo "[ok] ran nmap --help"
elif command -v tcpdump >/dev/null 2>&1; then
  (tcpdump --version >/dev/null 2>&1 || true)
  echo "[ok] ran tcpdump --version"
else
  echo "[warn] no suspicious binary found (nc/ncat/nmap/tcpdump)"
  echo "[hint] temporary demo: add sleep in monitors.process.suspicious_names then run sleep 2"
fi

echo "[LySec Demo] USB action required"
echo "[action] plug in USB storage, wait 5 seconds, then unplug"
sleep 8

echo "[LySec Demo] Watchdog recovery test"
echo "[action] stopping lysec once; watchdog should restart it"
sudo systemctl stop lysec
sleep 10
sudo systemctl is-active lysec >/dev/null
echo "[ok] lysec restarted by watchdog"

echo "[LySec Demo] Evidence checks"
echo "--------------------------------------------------------"
echo "sudo lysec alerts --last 20m"
echo "sudo lysec timeline --monitor usb --start 2026-03-24T00:00:00 --end 2026-03-24T23:59:59"
echo "sudo lysec timeline --monitor process --start 2026-03-24T00:00:00 --end 2026-03-24T23:59:59"
echo "sudo lysec timeline --monitor filesystem --start 2026-03-24T00:00:00 --end 2026-03-24T23:59:59"
echo "sudo lysec timeline --monitor watchdog --start 2026-03-24T00:00:00 --end 2026-03-24T23:59:59"
echo "sudo lysec export --format json --output /tmp/lysec_demo_alerts.json --source alerts"
echo "sudo lysec verify"
echo "--------------------------------------------------------"
echo "[done] demo events generated"
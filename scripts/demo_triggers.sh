#!/usr/bin/env bash
set -euo pipefail

# LySec demo trigger script
# - Generates filesystem events in /tmp
# - Attempts to generate a suspicious process event using common tools
# - USB event is manual (plug/unplug a USB device)

echo "[1/3] Triggering filesystem create/modify/delete events ..."
DEMO_FILE="/tmp/lysec_demo_$(date +%s).txt"
echo "lysec demo" > "$DEMO_FILE"
sleep 1
echo "modified" >> "$DEMO_FILE"
sleep 1
rm -f "$DEMO_FILE"
echo "[ok] filesystem events triggered"

echo "[2/3] Triggering process event (best-effort) ..."
if command -v nc >/dev/null 2>&1; then
  (nc -h >/dev/null 2>&1 || true)
  echo "[ok] ran: nc -h"
elif command -v ncat >/dev/null 2>&1; then
  (ncat -h >/dev/null 2>&1 || true)
  echo "[ok] ran: ncat -h"
elif command -v nmap >/dev/null 2>&1; then
  (nmap --help >/dev/null 2>&1 || true)
  echo "[ok] ran: nmap --help"
elif command -v tcpdump >/dev/null 2>&1; then
  (tcpdump --version >/dev/null 2>&1 || true)
  echo "[ok] ran: tcpdump --version"
else
  echo "[warn] no default suspicious binaries found (nc/ncat/nmap/tcpdump)."
  echo "[hint] temporary demo option: add 'sleep' to monitors.process.suspicious_names"
  echo "[hint] then run: sleep 3"
fi

echo "[3/3] USB event is manual ..."
echo "[action] plug in a USB drive now, wait 3-5 seconds, then unplug it."

echo "[done] Triggers sent. Keep the live viewer terminal open to show events."

#!/usr/bin/env bash
set -euo pipefail

PASS_COUNT=0
WARN_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] $*"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $*"
}

step() {
  echo
  echo "[LySec Demo] $*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[FAIL] missing required command: $1"
    exit 1
  fi
}

readiness_prompt() {
  local label="$1"
  echo "[action] $label"
  read -r -p "Press Enter once completed..." _
  sleep 3
}

require_cmd python3
require_cmd sudo

DEMO_START_EPOCH="$(date +%s)"
ALERT_LOG="/var/log/lysec/alerts.log"
EXPORT_JSON="/tmp/lysec_demo_alerts.json"
VERIFY_LOG="/tmp/lysec_verify_output.txt"

step "Pre-check services"
sudo systemctl daemon-reload
sudo systemctl enable --now lysec lysec-watchdog
if sudo systemctl is-active lysec >/dev/null && sudo systemctl is-active lysec-watchdog >/dev/null; then
  pass "lysec and lysec-watchdog are active"
else
  echo "[FAIL] required services are not active"
  exit 1
fi

step "Trigger filesystem sequence for fuzzy hashing"
# Using /media instead of /tmp since /tmp is no longer monitored in your config
DEMO_DIR="/media/lysec_fuzzy_demo"
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
pass "filesystem create/modify/delete sequence generated"

step "Trigger process activity"
if command -v nmap >/dev/null 2>&1; then
  (nmap -sn 127.0.0.1/32 >/dev/null 2>&1 || true)
  pass "ran nmap process trigger"
elif command -v nc >/dev/null 2>&1; then
  (nc -h >/dev/null 2>&1 || true)
  pass "ran nc process trigger"
elif command -v ncat >/dev/null 2>&1; then
  (ncat -h >/dev/null 2>&1 || true)
  pass "ran ncat process trigger"
elif command -v tcpdump >/dev/null 2>&1; then
  (tcpdump --version >/dev/null 2>&1 || true)
  pass "ran tcpdump process trigger"
else
  warn "no suspicious demo binary found (nmap/nc/ncat/tcpdump)"
fi

step "Trigger remote/network activity"
if command -v ip >/dev/null 2>&1; then
  (sudo ip link set dev lo promisc on && sleep 1 && sudo ip link set dev lo promisc off || true)
  pass "ran network promiscuous mode trigger"
else
  warn "could not trigger network promiscuous mode (missing ip command)"
fi

step "Trigger failed login activity"
if command -v su >/dev/null 2>&1; then
  echo "wrongpassword" | su - fakeuser -c "echo hack" >/dev/null 2>&1 || true
  pass "ran failed login trigger"
else
  warn "could not trigger failed login"
fi

step "USB scenario tests (manual)"
readiness_prompt "USB disk: plug in mass-storage device, wait 5s, then unplug"
readiness_prompt "USB keyboard/HID: plug in keyboard (or HID), wait 5s, then unplug"
readiness_prompt "USB other type: plug in non-storage non-HID USB (for example phone tether, network dongle, serial adapter), wait 5s, then unplug"
pass "manual USB scenarios completed"

step "Watchdog recovery test"
echo "[action] stopping lysec once; watchdog should restart it"
sudo systemctl stop lysec
# The watchdog has an 8-second timeout + 20-second cooldown before it restarts the monitored service
sleep 32
if sudo systemctl is-active lysec-prelogin >/dev/null; then
  pass "lysec-prelogin restarted by watchdog"
elif sudo systemctl is-active lysec >/dev/null; then
  pass "lysec restarted by watchdog"
else
  warn "watchdog did not restart lysec within expected time"
fi

step "Export and integrity verification"
sudo lysec export --format json --output "$EXPORT_JSON" --source alerts >/dev/null
if sudo lysec verify >"$VERIFY_LOG" 2>&1; then
  pass "integrity chain verification command succeeded"
else
  warn "integrity verification command reported issues (see $VERIFY_LOG)"
fi

step "Automated evidence assertions"
python3 - "$DEMO_START_EPOCH" "$ALERT_LOG" <<'PY'
import json
import sys
from pathlib import Path

start_epoch = float(sys.argv[1])
alert_path = Path(sys.argv[2])

if not alert_path.exists():
    print("[WARN] alerts log not found")
    sys.exit(0)

recent = []
for line in alert_path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        evt = json.loads(line)
    except Exception:
        continue
    try:
        epoch = float(evt.get("epoch", 0.0))
    except Exception:
        epoch = 0.0
    if epoch >= start_epoch:
        recent.append(evt)

def has_event(event_type: str) -> bool:
    return any(str(e.get("event_type", "")) == event_type for e in recent)

def usb_has_type(usb_type: str) -> bool:
    want = usb_type.lower()
    for e in recent:
        if str(e.get("event_type", "")) != "USB_DEVICE_ATTACHED":
            continue
        details = e.get("details", {})
        if isinstance(details, dict) and str(details.get("usb_type", "")).lower() == want:
            return True
    return False

def has_fuzzy_filesystem() -> bool:
    for e in recent:
        if str(e.get("monitor", "")) != "filesystem":
            continue
        d = e.get("details", {})
        if not isinstance(d, dict):
            continue
        if "fuzzy_hash" in d or "fuzzy_similarity" in d:
            return True
    return False

def has_global_alert_fuzzy() -> bool:
    for e in recent:
        d = e.get("details", {})
        if isinstance(d, dict) and "alert_fuzzy" in d:
            return True
    return False

checks = [
    ("USB attached present", has_event("USB_DEVICE_ATTACHED")),
    ("USB removed present", has_event("USB_DEVICE_REMOVED")),
    ("USB mass storage seen", usb_has_type("mass_storage")),
    ("USB HID seen", usb_has_type("hid")),
    ("USB other type seen", any(
        str(e.get("event_type", "")) == "USB_DEVICE_ATTACHED"
        and isinstance(e.get("details", {}), dict)
        and str(e.get("details", {}).get("usb_type", "")).lower() not in {"", "mass_storage", "hid"}
        for e in recent
    )),
    ("Process started signal", has_event("PROCESS_STARTED")),
    ("Filesystem fuzzy fields present", has_fuzzy_filesystem()),
    ("Global alert fuzzy present", has_global_alert_fuzzy()),
]

for name, ok in checks:
    print(f"[{'PASS' if ok else 'WARN'}] {name}")

print(f"[info] recent alerts inspected: {len(recent)}")
PY

step "Useful follow-up commands"
echo "sudo lysec alerts --last 30m"
echo "sudo lysec timeline --monitor usb"
echo "sudo lysec timeline --monitor process"
echo "sudo lysec timeline --monitor filesystem"
echo "sudo lysec timeline --monitor network"
echo "sudo lysec timeline --monitor login"
echo "sudo cat $VERIFY_LOG"

echo
echo "[done] demo completed | PASS=${PASS_COUNT} WARN=${WARN_COUNT}"
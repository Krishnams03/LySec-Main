#!/usr/bin/env bash
# LySec Uninstaller
set -euo pipefail

echo "Stopping LySec daemon …"
systemctl stop lysec.service 2>/dev/null || true
systemctl disable lysec.service 2>/dev/null || true
systemctl stop lysec-prelogin.service 2>/dev/null || true
systemctl disable lysec-prelogin.service 2>/dev/null || true
systemctl stop lysec-watchdog.service 2>/dev/null || true
systemctl disable lysec-watchdog.service 2>/dev/null || true
systemctl stop dftool.service 2>/dev/null || true
systemctl disable dftool.service 2>/dev/null || true

echo "Removing systemd service …"
rm -f /etc/systemd/system/lysec.service
rm -f /etc/systemd/system/lysec-prelogin.service
rm -f /etc/systemd/system/lysec-watchdog.service
rm -f /etc/systemd/system/dftool.service
systemctl daemon-reload

echo "Removing command links …"
rm -f /usr/local/bin/lysec /usr/local/bin/lysecd /usr/local/bin/lysec-eval /usr/local/bin/lysec-eval-plot /usr/local/bin/lysec-gui
rm -f /usr/local/bin/lysec-watchdog
rm -f /usr/local/bin/dftool /usr/local/bin/dftoold /usr/local/bin/dftool-eval /usr/local/bin/dftool-eval-plot

echo "Removing installation files …"
rm -rf /opt/lysec
rm -rf /opt/dftool

echo ""
echo "LySec uninstalled."
echo ""
echo "The following directories were NOT removed (contain forensic data):"
echo "  /var/log/lysec/          - log files"
echo "  /var/lib/lysec/          - evidence"
echo "  /etc/lysec/              - configuration"
echo ""
echo "Remove them manually if no longer needed:"
echo "  sudo rm -rf /var/log/lysec /var/lib/lysec /etc/lysec"

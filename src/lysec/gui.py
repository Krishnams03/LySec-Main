"""
LySec - Desktop GUI
Simple Tkinter dashboard for daemon control and forensic log exploration.

Launch:
    lysec-gui
"""

import json
import os
import subprocess
import tkinter as tk
from datetime import datetime, timezone
from tkinter import ttk, messagebox

from lysec.config import load_config, DEFAULT_CONFIG_PATH


class LySecGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LySec Forensics Console")
        self.root.geometry("1220x820")
        self.root.minsize(980, 640)

        try:
            self.config = load_config(DEFAULT_CONFIG_PATH)
        except Exception:
            self.config = {
                "logging": {"log_dir": "/var/log/lysec"},
                "alerts": {"alert_log": "/var/log/lysec/alerts.log"},
            }

        self.alert_log = self.config.get("alerts", {}).get("alert_log", "/var/log/lysec/alerts.log")
        log_dir = self.config.get("logging", {}).get("log_dir", "/var/log/lysec")
        self.event_log = os.path.join(log_dir, "lysec.log")
        if not os.path.isfile(self.event_log):
            self.event_log = os.path.join(log_dir, "dftool.log")

        self.time_mode_var = tk.StringVar(value="local")
        self.monitor_filter_var = tk.StringVar(value="all")
        self.severity_filter_var = tk.StringVar(value="all")
        self.auto_refresh_var = tk.BooleanVar(value=True)
        self._last_alert_rows: list[dict] = []

        self._build_ui()
        self.refresh_all()
        self._schedule_auto_refresh()

    def _build_ui(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Title.TLabel", font=("Segoe UI", 17, "bold"))
        style.configure("Muted.TLabel", font=("Segoe UI", 10))
        style.configure("Card.TFrame", relief="flat")
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))

        top = ttk.Frame(self.root, padding=12, style="Card.TFrame")
        top.pack(fill=tk.X)

        ttk.Label(top, text="LySec Forensics Console", style="Title.TLabel").pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="Service: unknown")
        ttk.Label(top, textvariable=self.status_var, style="Muted.TLabel").pack(side=tk.RIGHT)

        actions = ttk.Frame(self.root, padding=(12, 0, 12, 8))
        actions.pack(fill=tk.X)

        ttk.Button(actions, text="Start Service", command=self.start_service).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(actions, text="Stop Service", command=self.stop_service).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(actions, text="Restart Service", command=self.restart_service).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(actions, text="Refresh", style="Accent.TButton", command=self.refresh_all).pack(side=tk.LEFT, padx=(0, 18))

        ttk.Label(actions, text="Time:").pack(side=tk.LEFT)
        ttk.Combobox(
            actions,
            textvariable=self.time_mode_var,
            values=["local", "utc"],
            width=8,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(6, 12))

        ttk.Label(actions, text="Monitor:").pack(side=tk.LEFT)
        ttk.Combobox(
            actions,
            textvariable=self.monitor_filter_var,
            values=["all", "usb", "process", "filesystem", "network", "login", "correlation", "daemon"],
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(6, 12))

        ttk.Label(actions, text="Severity:").pack(side=tk.LEFT)
        ttk.Combobox(
            actions,
            textvariable=self.severity_filter_var,
            values=["all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            width=10,
            state="readonly",
        ).pack(side=tk.LEFT, padx=(6, 12))

        ttk.Checkbutton(actions, text="Auto-refresh", variable=self.auto_refresh_var).pack(side=tk.LEFT)

        tabs = ttk.Notebook(self.root)
        tabs.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        alerts_tab = ttk.Frame(tabs)
        timeline_tab = ttk.Frame(tabs)
        decision_tab = ttk.Frame(tabs)
        tabs.add(alerts_tab, text="Alerts")
        tabs.add(timeline_tab, text="Timeline")
        tabs.add(decision_tab, text="Decision Support")

        self.alert_tree = ttk.Treeview(
            alerts_tab,
            columns=("time", "severity", "monitor", "event", "message"),
            show="headings",
            height=20,
        )
        for col, width in [
            ("time", 210),
            ("severity", 90),
            ("monitor", 110),
            ("event", 210),
            ("message", 430),
        ]:
            self.alert_tree.heading(col, text=col.title())
            self.alert_tree.column(col, width=width, anchor=tk.W)
        self.alert_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        alert_scroll = ttk.Scrollbar(alerts_tab, orient=tk.VERTICAL, command=self.alert_tree.yview)
        alert_scroll.pack(fill=tk.Y, side=tk.RIGHT)
        self.alert_tree.configure(yscrollcommand=alert_scroll.set)

        self.timeline_text = tk.Text(timeline_tab, wrap=tk.NONE, font=("Consolas", 10))
        self.timeline_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        timeline_scroll = ttk.Scrollbar(timeline_tab, orient=tk.VERTICAL, command=self.timeline_text.yview)
        timeline_scroll.pack(fill=tk.Y, side=tk.RIGHT)
        self.timeline_text.configure(yscrollcommand=timeline_scroll.set)

        self.decision_text = tk.Text(decision_tab, wrap=tk.WORD, font=("Segoe UI", 10))
        self.decision_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        decision_scroll = ttk.Scrollbar(decision_tab, orient=tk.VERTICAL, command=self.decision_text.yview)
        decision_scroll.pack(fill=tk.Y, side=tk.RIGHT)
        self.decision_text.configure(yscrollcommand=decision_scroll.set)

        footer = ttk.Frame(self.root, padding=(12, 0, 12, 10))
        footer.pack(fill=tk.X)
        self.footer_var = tk.StringVar(value="Ready")
        ttk.Label(footer, textvariable=self.footer_var, style="Muted.TLabel").pack(side=tk.LEFT)

        self.path_var = tk.StringVar(value=f"alerts: {self.alert_log} | events: {self.event_log}")
        ttk.Label(footer, textvariable=self.path_var, style="Muted.TLabel").pack(side=tk.RIGHT)

    def _schedule_auto_refresh(self):
        if self.auto_refresh_var.get():
            self.refresh_all(silent=True)
        self.root.after(3000, self._schedule_auto_refresh)

    def _run_systemctl(self, action: str):
        cmd = ["systemctl", action, "lysec"]
        try:
            completed = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if completed.returncode != 0:
                messagebox.showerror("LySec", completed.stderr.strip() or "systemctl command failed")
            return completed.returncode == 0
        except FileNotFoundError:
            messagebox.showerror("LySec", "systemctl not found. Run on a systemd Linux host.")
            return False

    def start_service(self):
        if self._run_systemctl("start"):
            self.refresh_all()

    def stop_service(self):
        if self._run_systemctl("stop"):
            self.refresh_all()

    def restart_service(self):
        if self._run_systemctl("restart"):
            self.refresh_all()

    def refresh_all(self, silent: bool = False):
        self.refresh_status()
        self.refresh_alerts(silent=silent)
        self.refresh_timeline(silent=silent)
        self.refresh_decision_support()

    def refresh_status(self):
        try:
            status = subprocess.run(
                ["systemctl", "is-active", "lysec"],
                check=False,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.status_var.set(f"Service: {status or 'unknown'}")
        except Exception:
            self.status_var.set("Service: unknown")

    def refresh_alerts(self, silent: bool = False):
        for row in self.alert_tree.get_children():
            self.alert_tree.delete(row)

        rows, err = self._read_json_lines(self.alert_log, limit=250)
        rows = self._apply_filters(rows)
        self._last_alert_rows = rows

        for e in rows:
            ts = self._format_timestamp(str(e.get("timestamp", "")))
            self.alert_tree.insert(
                "",
                tk.END,
                values=(
                    ts,
                    e.get("severity", "?"),
                    e.get("monitor", "?"),
                    e.get("event_type", "?"),
                    e.get("message", ""),
                ),
            )

        if err and not silent:
            self.footer_var.set(f"Alerts read issue: {err}")
        else:
            self.footer_var.set(f"Loaded {len(rows)} alerts")

    def refresh_timeline(self, silent: bool = False):
        self.timeline_text.delete("1.0", tk.END)
        rows, err = self._read_json_lines(self.event_log, limit=400)
        rows = self._apply_filters(rows)
        lines = []
        for e in rows:
            ts = self._format_timestamp(str(e.get("timestamp", "")))
            level = str(e.get("level", "?"))
            src = str(e.get("source", "?"))
            msg = str(e.get("message", ""))
            lines.append(f"{ts}  {level:<8}  {src:<24}  {msg}")
        self.timeline_text.insert("1.0", "\n".join(lines))

        if err and not silent:
            self.footer_var.set(f"Timeline read issue: {err}")

    def refresh_decision_support(self):
        self.decision_text.delete("1.0", tk.END)
        rows = self._last_alert_rows[-120:]

        if not rows:
            self.decision_text.insert(
                "1.0",
                "No recent alerts in current filters.\n\n"
                "If this is unexpected:\n"
                "1. Run GUI with sufficient permissions (often root)\n"
                "2. Confirm log paths are correct and readable\n"
                "3. Confirm service is active\n",
            )
            return

        sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        mon_count: dict[str, int] = {}
        for e in rows:
            sev = str(e.get("severity", "INFO")).upper()
            sev_count[sev] = sev_count.get(sev, 0) + 1
            mon = str(e.get("monitor", "unknown"))
            mon_count[mon] = mon_count.get(mon, 0) + 1

        risk = "LOW"
        if sev_count.get("CRITICAL", 0) > 0:
            risk = "CRITICAL"
        elif sev_count.get("HIGH", 0) >= 2:
            risk = "HIGH"
        elif sev_count.get("HIGH", 0) >= 1 or sev_count.get("MEDIUM", 0) >= 3:
            risk = "MEDIUM"

        lines = [
            "LySec Decision Assistant\n",
            f"Current risk level: {risk}",
            "",
            "Recent severity counts:",
            f"- CRITICAL: {sev_count.get('CRITICAL', 0)}",
            f"- HIGH:     {sev_count.get('HIGH', 0)}",
            f"- MEDIUM:   {sev_count.get('MEDIUM', 0)}",
            f"- LOW:      {sev_count.get('LOW', 0)}",
            f"- INFO:     {sev_count.get('INFO', 0)}",
            "",
            "Most active monitors:",
        ]

        top_mon = sorted(mon_count.items(), key=lambda kv: kv[1], reverse=True)[:5]
        for mon, count in top_mon:
            lines.append(f"- {mon}: {count}")

        lines.extend([
            "",
            "Recommended analyst actions:",
            "1. Run: lysec alerts --last 30m",
            "2. Run: lysec timeline with exact incident window",
            "3. Pivot indicators: user/ip/pid/path/serial",
            "4. Export evidence JSON+CSV and run lysec verify",
        ])

        if risk in ("HIGH", "CRITICAL"):
            lines.append("5. Escalate incident and preserve host state immediately")

        self.decision_text.insert("1.0", "\n".join(lines))

    @staticmethod
    def _read_json_lines(path: str, limit: int = 200) -> tuple[list[dict], str | None]:
        if not os.path.isfile(path):
            return [], f"missing file: {path}"
        out: list[dict] = []
        try:
            with open(path, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        continue
        except PermissionError:
            return [], f"permission denied reading: {path}"
        except Exception as exc:
            return [], str(exc)
        return out[-limit:], None

    def _apply_filters(self, rows: list[dict]) -> list[dict]:
        monitor_filter = self.monitor_filter_var.get().strip().lower()
        severity_filter = self.severity_filter_var.get().strip().upper()

        out: list[dict] = []
        for e in rows:
            mon = str(e.get("monitor", "")).lower()
            sev = str(e.get("severity", "")).upper()

            if monitor_filter != "all" and mon != monitor_filter:
                continue
            if severity_filter != "all" and sev != severity_filter:
                continue
            out.append(e)
        return out

    def _format_timestamp(self, ts: str) -> str:
        if not ts:
            return ""

        try:
            dt = datetime.fromisoformat(ts)
        except Exception:
            return ts[:26]

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        if self.time_mode_var.get() == "local":
            dt = dt.astimezone()
            return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def main():
    root = tk.Tk()
    app = LySecGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()


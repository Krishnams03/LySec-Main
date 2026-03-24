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
from tkinter import ttk, messagebox

from dftool.config import load_config, DEFAULT_CONFIG_PATH


class LySecGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("LySec Forensics Console")
        self.root.geometry("1080x720")
        self.root.minsize(900, 600)

        self.config = load_config(DEFAULT_CONFIG_PATH)
        self.alert_log = self.config.get("alerts", {}).get("alert_log", "/var/log/lysec/alerts.log")
        log_dir = self.config["logging"]["log_dir"]
        self.event_log = os.path.join(log_dir, "lysec.log")
        if not os.path.isfile(self.event_log):
            self.event_log = os.path.join(log_dir, "dftool.log")

        self._build_ui()
        self.refresh_all()

    def _build_ui(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Muted.TLabel", font=("Segoe UI", 10))

        top = ttk.Frame(self.root, padding=12)
        top.pack(fill=tk.X)

        ttk.Label(top, text="LySec Forensics Console", style="Title.TLabel").pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="Service: unknown")
        ttk.Label(top, textvariable=self.status_var, style="Muted.TLabel").pack(side=tk.RIGHT)

        actions = ttk.Frame(self.root, padding=(12, 0, 12, 8))
        actions.pack(fill=tk.X)

        ttk.Button(actions, text="Start Service", command=self.start_service).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(actions, text="Stop Service", command=self.stop_service).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(actions, text="Restart Service", command=self.restart_service).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(actions, text="Refresh", command=self.refresh_all).pack(side=tk.LEFT)

        tabs = ttk.Notebook(self.root)
        tabs.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        alerts_tab = ttk.Frame(tabs)
        timeline_tab = ttk.Frame(tabs)
        tabs.add(alerts_tab, text="Alerts")
        tabs.add(timeline_tab, text="Timeline")

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

        footer = ttk.Frame(self.root, padding=(12, 0, 12, 10))
        footer.pack(fill=tk.X)
        self.footer_var = tk.StringVar(value="Ready")
        ttk.Label(footer, textvariable=self.footer_var, style="Muted.TLabel").pack(side=tk.LEFT)

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

    def refresh_all(self):
        self.refresh_status()
        self.refresh_alerts()
        self.refresh_timeline()

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

    def refresh_alerts(self):
        for row in self.alert_tree.get_children():
            self.alert_tree.delete(row)

        rows = self._read_json_lines(self.alert_log, limit=200)
        for e in rows:
            self.alert_tree.insert(
                "",
                tk.END,
                values=(
                    str(e.get("timestamp", ""))[:26],
                    e.get("severity", "?"),
                    e.get("monitor", "?"),
                    e.get("event_type", "?"),
                    e.get("message", ""),
                ),
            )
        self.footer_var.set(f"Loaded {len(rows)} alerts")

    def refresh_timeline(self):
        self.timeline_text.delete("1.0", tk.END)
        rows = self._read_json_lines(self.event_log, limit=300)
        lines = []
        for e in rows:
            ts = str(e.get("timestamp", ""))[:26]
            level = str(e.get("level", "?"))
            src = str(e.get("source", "?"))
            msg = str(e.get("message", ""))
            lines.append(f"{ts}  {level:<8}  {src:<24}  {msg}")
        self.timeline_text.insert("1.0", "\n".join(lines))

    @staticmethod
    def _read_json_lines(path: str, limit: int = 200) -> list[dict]:
        if not os.path.isfile(path):
            return []
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
        except Exception:
            return []
        return out[-limit:]


def main():
    root = tk.Tk()
    app = LySecGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

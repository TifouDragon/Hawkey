import threading
import time
import json
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from datetime import datetime
from dataclasses import asdict
import subprocess
import ctypes
import webbrowser
from urllib.parse import quote_plus
import sys
import tempfile
import shutil
import os
import hashlib
import base64

import psutil

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except Exception:
    TRAY_AVAILABLE = False

from hawkeye_core import (
    HawkEyeCore,
    ThreatLevel,
    Finding,
    analyze_connection,
    level_from_score,
    normalize_ip_list,
    normalize_port_list,
)

THEME_BG = "#0a0e27"
THEME_BG2 = "#050812"
ACCENT = "#00ff88"
WARN = "#ffaa00"
DANGER = "#ff5555"
NETWORK_POLL_SECS = 3.0
NET_EVENT_THROTTLE_SECS = 60.0
CONFIG_PATH = Path("hawkeye_config.json")

LEVEL_TEXT = {
    ThreatLevel.MEDIUM: ("🟡 MOYEN", WARN),
    ThreatLevel.HIGH: ("🔴 ÉLEVÉ", "#ff5500"),
    ThreatLevel.CRITICAL: ("⚫ CRITIQUE", "#ff0000"),
}

class HawkEyeUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🦅 HAWK EYE - Core EDR")
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        width = min(1400, max(900, screen_w - 80))
        height = min(850, max(700, screen_h - 120))
        self.root.geometry(f"{width}x{height}")
        self.root.configure(bg=THEME_BG)
        self._set_blank_icon()

        self.core = HawkEyeCore()
        self.scanning = False
        self.network_monitoring = False
        self.background_monitoring = False
        self.bg_seen: dict[str, tuple[int, int]] = {}
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.findings: list[Finding] = []
        self.network_findings: list[dict] = []
        self.persistence_findings: list[dict] = []
        self.persistence_tasks: list[dict] = []
        self.persistence_services: list[dict] = []
        self.current_scan_folder: str | None = None
        self.seen_remote_ips: set[str] = set()
        self.net_last_seen: dict[tuple, float] = {}
        self.auto_quarantined_count = 0
        self.quarantine_items: list[dict] = []
        self.tray_icon = None
        self._loading_settings = False

        self._setup_style()
        self._build_ui()
        self.refresh_quarantine()
        self._bind_settings()
        self._load_settings()
        self._tick()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _set_blank_icon(self):
        try:
            data = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQYGWNgYGBgAAAABAABJzQnCgAAAABJRU5ErkJggg=="
            img = tk.PhotoImage(data=data)
            self._blank_icon = img
            self.root.iconphoto(True, img)
        except Exception:
            pass

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TFrame", background=THEME_BG)
        style.configure("TLabelframe", background=THEME_BG, foreground=ACCENT)
        style.configure("TLabelframe.Label", background=THEME_BG, foreground=ACCENT)
        style.configure("TLabel", background=THEME_BG, foreground="white", font=("Arial", 9))
        style.configure("Title.TLabel", background=THEME_BG, foreground=ACCENT, font=("Arial", 16, "bold"))

        style.configure("Treeview", background=THEME_BG2, fieldbackground=THEME_BG2,
                        foreground=ACCENT, font=("Courier", 9), rowheight=22)
        style.configure("Treeview.Heading", background="#1a1f3a", foreground=ACCENT, font=("Arial", 10, "bold"))

        style.configure("TButton", padding=6)

    def _make_scrollable_tab(self, notebook, title: str):
        outer = ttk.Frame(notebook)
        notebook.add(outer, text=title)
        canvas = tk.Canvas(outer, bg=THEME_BG, highlightthickness=0)
        vbar = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vbar.set)
        vbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        inner = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def on_configure(_event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_configure(event):
            canvas.itemconfigure(window, width=event.width)

        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        inner.bind("<Configure>", on_configure)
        canvas.bind("<Configure>", on_canvas_configure)
        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", on_mousewheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))
        return inner

    def _build_ui(self):
        # HEADER
        header = ttk.Frame(self.root)
        header.grid(row=0, column=0, sticky="ew", padx=15, pady=15)

        ttk.Label(header, text="🦅 HAWK EYE - Core EDR", style="Title.TLabel").pack(side=tk.LEFT)

        self.status = ttk.Label(header, text="Prêt.", foreground=ACCENT)
        self.status.pack(side=tk.RIGHT, padx=10)

        self.stats_lbl = ttk.Label(header, text="Menaces: 0", foreground=WARN)
        self.stats_lbl.pack(side=tk.RIGHT, padx=10)

        self.net_stats_lbl = ttk.Label(header, text="Net alerts: 0", foreground=WARN)
        self.net_stats_lbl.pack(side=tk.RIGHT, padx=10)

        # NOTEBOOK
        notebook = ttk.Notebook(self.root)
        notebook.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # TAB 1 - FINDINGS
        self.tab_findings = self._make_scrollable_tab(notebook, "Menaces")

        frame = ttk.LabelFrame(self.tab_findings, text="Détections", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        cols = ("time", "level", "score", "name", "path", "ips", "reasons", "sha256")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=18)

        self.tree.heading("time", text="Heure")
        self.tree.heading("level", text="Niveau")
        self.tree.heading("score", text="Score")
        self.tree.heading("name", text="Fichier")
        self.tree.heading("path", text="Chemin")
        self.tree.heading("ips", text="IP(s)")
        self.tree.heading("reasons", text="Raisons")
        self.tree.heading("sha256", text="SHA256")

        self.tree.column("time", width=90)
        self.tree.column("level", width=110)
        self.tree.column("score", width=60)
        self.tree.column("name", width=220)
        self.tree.column("path", width=520)
        self.tree.column("ips", width=160)
        self.tree.column("reasons", width=420)
        self.tree.column("sha256", width=210)

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        sbx = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.configure(xscrollcommand=sbx.set)
        sbx.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<Double-1>", self._google_search_selected)
        self.tree.bind("<Button-3>", self._show_findings_menu)

        # TAB 2 - NETWORK
        self.tab_network = self._make_scrollable_tab(notebook, "Network")

        nf = ttk.LabelFrame(self.tab_network, text="Network alerts", padding=10)
        nf.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ncols = ("time", "level", "pid", "proc", "local", "remote", "score", "reasons")
        self.net_tree = ttk.Treeview(nf, columns=ncols, show="headings", height=18)
        self.net_tree.heading("time", text="Time")
        self.net_tree.heading("level", text="Level")
        self.net_tree.heading("pid", text="PID")
        self.net_tree.heading("proc", text="Process")
        self.net_tree.heading("local", text="Local")
        self.net_tree.heading("remote", text="Remote")
        self.net_tree.heading("score", text="Score")
        self.net_tree.heading("reasons", text="Reasons")
        self.net_tree.column("time", width=90)
        self.net_tree.column("level", width=90)
        self.net_tree.column("pid", width=70)
        self.net_tree.column("proc", width=180)
        self.net_tree.column("local", width=160)
        self.net_tree.column("remote", width=180)
        self.net_tree.column("score", width=60)
        self.net_tree.column("reasons", width=520)

        nsb = ttk.Scrollbar(nf, orient=tk.VERTICAL, command=self.net_tree.yview)
        nsbx = ttk.Scrollbar(nf, orient=tk.HORIZONTAL, command=self.net_tree.xview)
        self.net_tree.configure(yscrollcommand=nsb.set)
        self.net_tree.configure(xscrollcommand=nsbx.set)
        nsbx.pack(side=tk.BOTTOM, fill=tk.X)
        self.net_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        nsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.net_tree.bind("<Button-3>", self._show_network_menu)

        # TAB 3 - QUARANTINE (simple)
        self.tab_quarantine = self._make_scrollable_tab(notebook, "Quarantaine")

        qf = ttk.LabelFrame(self.tab_quarantine, text="Quarantine manager", padding=10)
        qf.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        qcols = ("time", "level", "name", "original", "quarantined")
        self.q_tree = ttk.Treeview(qf, columns=qcols, show="headings", height=16)
        self.q_tree.heading("time", text="Time")
        self.q_tree.heading("level", text="Level")
        self.q_tree.heading("name", text="Name")
        self.q_tree.heading("original", text="Original path")
        self.q_tree.heading("quarantined", text="Quarantined path")
        self.q_tree.column("time", width=90)
        self.q_tree.column("level", width=90)
        self.q_tree.column("name", width=200)
        self.q_tree.column("original", width=520)
        self.q_tree.column("quarantined", width=520)

        qsb = ttk.Scrollbar(qf, orient=tk.VERTICAL, command=self.q_tree.yview)
        qsbx = ttk.Scrollbar(qf, orient=tk.HORIZONTAL, command=self.q_tree.xview)
        self.q_tree.configure(yscrollcommand=qsb.set)
        self.q_tree.configure(xscrollcommand=qsbx.set)
        qsbx.pack(side=tk.BOTTOM, fill=tk.X)
        self.q_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        qsb.pack(side=tk.RIGHT, fill=tk.Y)

        qbtns = ttk.Frame(self.tab_quarantine)
        qbtns.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Button(qbtns, text="Refresh", command=self.refresh_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(qbtns, text="Restore selected", command=self.restore_quarantine_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(qbtns, text="Delete selected", command=self.delete_quarantine_selected).pack(side=tk.LEFT, padx=5)

        # TAB 4 - HISTORY
        self.tab_history = self._make_scrollable_tab(notebook, "History")

        hf = ttk.LabelFrame(self.tab_history, text="Events log (last 200)", padding=10)
        hf.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.history_text = tk.Text(hf, height=18, bg=THEME_BG2, fg=ACCENT,
                                    font=("Courier", 10), relief=tk.FLAT, bd=0)
        self.history_text.pack(fill=tk.BOTH, expand=True)
        self.history_text.insert("1.0", "History not loaded yet.\n")
        self.history_text.configure(state=tk.DISABLED)

        ttk.Button(hf, text="Refresh history", command=self.refresh_history).pack(anchor=tk.E, pady=6)
        ttk.Button(hf, text="Load last findings", command=self.load_state).pack(anchor=tk.E, pady=6)
        ttk.Button(hf, text="Refresh timeline", command=self.refresh_timeline).pack(anchor=tk.E, pady=6)

        # TAB 5 - PERSISTENCE+
        self.tab_persistence = self._make_scrollable_tab(notebook, "Persistence+")

        pf2 = ttk.LabelFrame(self.tab_persistence, text="Persistence findings", padding=10)
        pf2.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        pcols = ("type", "name", "detail", "score", "reasons")
        self.persistence_tree = ttk.Treeview(pf2, columns=pcols, show="headings", height=16)
        self.persistence_tree.heading("type", text="Type")
        self.persistence_tree.heading("name", text="Name")
        self.persistence_tree.heading("detail", text="Detail")
        self.persistence_tree.heading("score", text="Score")
        self.persistence_tree.heading("reasons", text="Reasons")
        self.persistence_tree.column("type", width=120)
        self.persistence_tree.column("name", width=220)
        self.persistence_tree.column("detail", width=700)
        self.persistence_tree.column("score", width=60)
        self.persistence_tree.column("reasons", width=360)

        psb = ttk.Scrollbar(pf2, orient=tk.VERTICAL, command=self.persistence_tree.yview)
        self.persistence_tree.configure(yscrollcommand=psb.set)
        self.persistence_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        psb.pack(side=tk.RIGHT, fill=tk.Y)

        pbtns = ttk.Frame(self.tab_persistence)
        pbtns.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Button(pbtns, text="Scan Run keys", command=self.scan_persistence).pack(side=tk.LEFT, padx=5)
        ttk.Button(pbtns, text="Scan Tasks", command=self.scan_tasks).pack(side=tk.LEFT, padx=5)
        ttk.Button(pbtns, text="Scan Services", command=self.scan_services).pack(side=tk.LEFT, padx=5)

        # TAB 6 - OPTIONS
        self.tab_options = self._make_scrollable_tab(notebook, "Options")

        of = ttk.LabelFrame(self.tab_options, text="Options", padding=10)
        of.pack(fill=tk.X, padx=10, pady=10)

        self.kill_proc_var = tk.BooleanVar(value=True)
        self.auto_quarantine_var = tk.BooleanVar(value=True)
        self.read_only_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(of, text="Tuer le process si le fichier est en cours d'exécution (recommandé)",
                        variable=self.kill_proc_var).pack(anchor=tk.W, pady=5)
        ttk.Checkbutton(of, text="Auto-quarantine HIGH/CRITICAL (files only)",
                        variable=self.auto_quarantine_var).pack(anchor=tk.W, pady=5)
        ttk.Checkbutton(of, text="Read-only mode (no quarantine/delete/firewall)",
                        variable=self.read_only_var, command=self._apply_read_only_state).pack(anchor=tk.W, pady=5)

        self.max_files_var = tk.IntVar(value=0)
        self.full_scan_var = tk.BooleanVar(value=False)
        self.log_scanned_var = tk.BooleanVar(value=True)
        self.background_var = tk.BooleanVar(value=False)
        row = ttk.Frame(of)
        row.pack(fill=tk.X, pady=5)
        ttk.Label(row, text="Limite de fichiers (0 = illimité):").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.max_files_var, width=10).pack(side=tk.LEFT, padx=8)

        ttk.Checkbutton(of, text="Full scan with progress (slower)",
                        variable=self.full_scan_var).pack(anchor=tk.W, pady=5)
        ttk.Checkbutton(of, text="Log all scanned files (can be large)",
                        variable=self.log_scanned_var).pack(anchor=tk.W, pady=5)
        ttk.Checkbutton(of, text="Background monitor (Downloads/Desktop)",
                        variable=self.background_var, command=self.toggle_background_monitor).pack(anchor=tk.W, pady=5)

        ex = ttk.LabelFrame(self.tab_options, text="Exclusions", padding=10)
        ex.pack(fill=tk.X, padx=10, pady=10)

        self.exclude_paths_var = tk.StringVar(value="")
        self.exclude_exts_var = tk.StringVar(value="")
        self.exclude_hashes_var = tk.StringVar(value="")

        ex_row1 = ttk.Frame(ex)
        ex_row1.pack(fill=tk.X, pady=4)
        ttk.Label(ex_row1, text="Exclude paths (semicolon separated):").pack(side=tk.LEFT)
        ttk.Entry(ex_row1, textvariable=self.exclude_paths_var, width=80).pack(side=tk.LEFT, padx=8)

        ex_row2 = ttk.Frame(ex)
        ex_row2.pack(fill=tk.X, pady=4)
        ttk.Label(ex_row2, text="Exclude extensions (.tmp;.log):").pack(side=tk.LEFT)
        ttk.Entry(ex_row2, textvariable=self.exclude_exts_var, width=30).pack(side=tk.LEFT, padx=8)

        ex_row3 = ttk.Frame(ex)
        ex_row3.pack(fill=tk.X, pady=4)
        ttk.Label(ex_row3, text="Exclude hashes (sha256;sha256):").pack(side=tk.LEFT)
        ttk.Entry(ex_row3, textvariable=self.exclude_hashes_var, width=80).pack(side=tk.LEFT, padx=8)

        al = ttk.LabelFrame(self.tab_options, text="Network allowlist", padding=10)
        al.pack(fill=tk.X, padx=10, pady=10)

        self.allow_ips_var = tk.StringVar(value="")
        self.allow_ports_var = tk.StringVar(value="")

        al_row1 = ttk.Frame(al)
        al_row1.pack(fill=tk.X, pady=4)
        ttk.Label(al_row1, text="Allow IPs (semicolon separated):").pack(side=tk.LEFT)
        ttk.Entry(al_row1, textvariable=self.allow_ips_var, width=60).pack(side=tk.LEFT, padx=8)

        al_row2 = ttk.Frame(al)
        al_row2.pack(fill=tk.X, pady=4)
        ttk.Label(al_row2, text="Allow ports (semicolon separated):").pack(side=tk.LEFT)
        ttk.Entry(al_row2, textvariable=self.allow_ports_var, width=20).pack(side=tk.LEFT, padx=8)

        winf = ttk.LabelFrame(self.tab_options, text="Windows", padding=10)
        winf.pack(fill=tk.X, padx=10, pady=10)

        self.tray_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(winf, text="Minimize to tray (requires pystray + pillow)",
                        variable=self.tray_var).pack(anchor=tk.W, pady=5)

        admin_state = "YES" if self._is_admin() else "NO"
        ttk.Label(winf, text=f"Admin: {admin_state}").pack(anchor=tk.W, pady=2)

        win_btns = ttk.Frame(winf)
        win_btns.pack(fill=tk.X, pady=4)
        ttk.Button(win_btns, text="Install auto-start task (admin)",
                   command=self.install_autostart_task).pack(side=tk.LEFT, padx=5)
        ttk.Button(win_btns, text="Remove auto-start task",
                   command=self.remove_autostart_task).pack(side=tk.LEFT, padx=5)

        sbf = ttk.LabelFrame(self.tab_options, text="Sandbox (experimental)", padding=10)
        sbf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(sbf, text="Open Windows Sandbox with selected file (manual analysis).").pack(anchor=tk.W, pady=2)
        ttk.Button(sbf, text="Open in Windows Sandbox", command=self.sandbox_selected).pack(anchor=tk.W, pady=4)

        pf = ttk.LabelFrame(self.tab_options, text="Persistance Windows (Run keys)", padding=10)
        pf.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(pf, text="🧬 Scanner Run keys", command=self.scan_persistence).pack(side=tk.LEFT)

        # CONTROLS
        controls = ttk.LabelFrame(self.root, text="🎮 Contrôles", padding=10)
        controls.grid(row=2, column=0, sticky="ew", padx=15, pady=(0, 15))
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self._init_context_menus()
        self._apply_read_only_state()

        self.progress_label = ttk.Label(controls, text="Prêt.")
        self.progress_label.pack(side=tk.LEFT, padx=8)

        self.progress = ttk.Progressbar(controls, mode="indeterminate", length=420)
        self.progress.pack(side=tk.LEFT, padx=8)
        ttk.Button(controls, text="Start/Stop network monitor", command=self.toggle_network_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Export report", command=self.export_report).pack(side=tk.LEFT, padx=5)

        ttk.Button(controls, text="📁 Scan dossier", command=self.pick_folder_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="💽 Scan disque (fast)", command=self.scan_system_drive_fast).pack(side=tk.LEFT, padx=5)
        self.quarantine_btn = ttk.Button(controls, text="Quarantaine (selection)", command=self.quarantine_selected)
        self.quarantine_btn.pack(side=tk.LEFT, padx=5)
        self.open_quarantine_btn = ttk.Button(controls, text="Ouvrir quarantaine", command=self.open_quarantine)
        self.open_quarantine_btn.pack(side=tk.LEFT, padx=5)
        self.pause_btn = ttk.Button(controls, text="Pause", command=self.toggle_pause)
        self.pause_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="⏹️ Stop", command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls, text="Background monitor", command=self.toggle_background_monitor).pack(side=tk.LEFT, padx=5)

    def _init_context_menus(self):
        import os
        self.findings_menu = tk.Menu(self.root, tearoff=0)
        self.findings_menu.add_command(label="Open folder", command=self._open_selected_folder)
        self.findings_menu.add_command(label="Open file", command=self._open_selected_file)
        self.findings_menu.add_separator()
        self.findings_menu.add_command(label="Quarantine", command=self._quarantine_selected_from_menu)
        self.findings_menu.add_command(label="Delete file", command=self._delete_selected_file)
        self.findings_menu.add_separator()
        self.findings_menu.add_command(label="Search web", command=self._google_search_selected)

        self.network_menu = tk.Menu(self.root, tearoff=0)
        self.network_menu.add_command(label="Search IP", command=self._search_network_ip)
        self.network_menu.add_command(label="Search process", command=self._search_network_process)
        self.network_menu.add_separator()
        self.network_menu.add_command(label="Kill process", command=self._kill_network_process)
        self.network_menu.add_command(label="Block IP (firewall)", command=self._block_network_ip)
        self.network_menu.add_command(label="Block port (firewall)", command=self._block_network_port)

    def _show_findings_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.findings_menu.tk_popup(event.x_root, event.y_root)

    def _show_network_menu(self, event):
        row = self.net_tree.identify_row(event.y)
        if row:
            self.net_tree.selection_set(row)
            self.network_menu.tk_popup(event.x_root, event.y_root)

    def _get_selected_finding(self):
        sel = self.tree.selection()
        if not sel:
            return None
        idx = self.tree.index(sel[0])
        if idx < 0 or idx >= len(self.findings):
            return None
        return self.findings[idx]

    def _open_selected_folder(self):
        import os
        f = self._get_selected_finding()
        if not f:
            return
        try:
            os.startfile(str(Path(f.path).parent))
        except Exception:
            messagebox.showerror("Open", "Unable to open folder.")

    def _open_selected_file(self):
        import os
        f = self._get_selected_finding()
        if not f:
            return
        try:
            os.startfile(f.path)
        except Exception:
            messagebox.showerror("Open", "Unable to open file.")

    def _quarantine_selected_from_menu(self):
        f = self._get_selected_finding()
        if not f:
            return
        if self.read_only_var.get():
            messagebox.showinfo("Quarantine", "Read-only mode is enabled.")
            return
        if not Path(f.path).exists():
            messagebox.showinfo("Quarantine", "File not found.")
            return
        res = self.core.quarantine(f, kill_process=self.kill_proc_var.get())
        if res.get("ok"):
            messagebox.showinfo("Quarantine", "Quarantined:\n" + str(res.get("dst")))
            self._notify("Quarantine", str(res.get("dst")))
            self.refresh_quarantine()
        else:
            messagebox.showerror("Quarantine", str(res))

    def _delete_selected_file(self):
        f = self._get_selected_finding()
        if not f:
            return
        if self.read_only_var.get():
            messagebox.showinfo("Delete", "Read-only mode is enabled.")
            return
        if not messagebox.askyesno("Delete", "Delete file?\n" + f.path):
            return
        try:
            Path(f.path).unlink(missing_ok=True)
            messagebox.showinfo("Delete", "File deleted.")
        except Exception as e:
            messagebox.showerror("Delete", str(e))

    def _get_selected_network_event(self):
        sel = self.net_tree.selection()
        if not sel:
            return None
        idx = self.net_tree.index(sel[0])
        if idx < 0 or idx >= len(self.network_findings):
            return None
        return self.network_findings[idx]

    def _search_network_ip(self):
        ev = self._get_selected_network_event()
        if not ev:
            return
        ip = ev.get("remote_ip")
        if not ip:
            return
        webbrowser.open("https://www.google.com/search?q=" + quote_plus(str(ip)))

    def _search_network_process(self):
        ev = self._get_selected_network_event()
        if not ev:
            return
        proc = ev.get("process")
        if not proc:
            return
        webbrowser.open("https://www.google.com/search?q=" + quote_plus(str(proc)))

    def _kill_network_process(self):
        ev = self._get_selected_network_event()
        if not ev:
            return
        pid = ev.get("pid")
        if not pid:
            return
        if not messagebox.askyesno("Kill", "Terminate process " + str(pid) + "?"):
            return
        try:
            psutil.Process(int(pid)).kill()
            messagebox.showinfo("Kill", "Process terminated.")
        except Exception as e:
            messagebox.showerror("Kill", str(e))

    def _block_network_ip(self):
        ev = self._get_selected_network_event()
        if not ev:
            return
        ip = ev.get("remote_ip")
        if not ip:
            return
        if self.read_only_var.get():
            messagebox.showinfo("Firewall", "Read-only mode is enabled.")
            return
        if not self._is_admin():
            messagebox.showerror("Firewall", "Admin required to add firewall rule.")
            return
        name = "HawkEye Block IP " + str(ip)
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=" + name,
            "dir=out", "action=block",
            "remoteip=" + str(ip),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            messagebox.showinfo("Firewall", "IP blocked (outbound).")
        else:
            messagebox.showerror("Firewall", res.stderr or res.stdout)

    def _block_network_port(self):
        ev = self._get_selected_network_event()
        if not ev:
            return
        port = ev.get("remote_port")
        if not port:
            return
        if self.read_only_var.get():
            messagebox.showinfo("Firewall", "Read-only mode is enabled.")
            return
        if not self._is_admin():
            messagebox.showerror("Firewall", "Admin required to add firewall rule.")
            return
        name = "HawkEye Block Port " + str(port)
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=" + name,
            "dir=out", "action=block",
            "protocol=TCP",
            "remoteport=" + str(port),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            messagebox.showinfo("Firewall", "Port blocked (outbound TCP).")
        else:
            messagebox.showerror("Firewall", res.stderr or res.stdout)

    def _notify(self, title: str, body: str):
        try:
            safe_title = title.replace("\"", "")
            safe_body = body.replace("\"", "")
            ps = f"""$null=[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
$template=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$xml=$template.GetXml()
$xml.GetElementsByTagName("text")[0].AppendChild($xml.CreateTextNode("{safe_title}"))|Out-Null
$xml.GetElementsByTagName("text")[1].AppendChild($xml.CreateTextNode("{safe_body}"))|Out-Null
$toast=[Windows.UI.Notifications.ToastNotification]::new($xml)
$notifier=[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("HawkEye")
$notifier.Show($toast)
"""
            enc = base64.b64encode(ps.encode("utf-16le")).decode("ascii")
            subprocess.run(["powershell", "-NoProfile", "-EncodedCommand", enc], capture_output=True)
        except Exception:
            pass

    def _bind_settings(self):
        vars_to_watch = [
            self.kill_proc_var,
            self.auto_quarantine_var,
            self.read_only_var,
            self.full_scan_var,
            self.log_scanned_var,
            self.background_var,
            self.max_files_var,
            self.exclude_paths_var,
            self.exclude_exts_var,
            self.exclude_hashes_var,
            self.allow_ips_var,
            self.allow_ports_var,
            self.tray_var,
        ]
        for v in vars_to_watch:
            try:
                v.trace_add("write", lambda *_: self._save_settings())
            except Exception:
                pass

    def _save_settings(self):
        if self._loading_settings:
            return
        data = {
            "kill_proc": bool(self.kill_proc_var.get()),
            "auto_quarantine": bool(self.auto_quarantine_var.get()),
            "read_only": bool(self.read_only_var.get()),
            "full_scan": bool(self.full_scan_var.get()),
            "log_scanned": bool(self.log_scanned_var.get()),
            "background": bool(self.background_var.get()),
            "max_files": int(self.max_files_var.get()) if self.max_files_var.get() else 0,
            "exclude_paths": self.exclude_paths_var.get(),
            "exclude_exts": self.exclude_exts_var.get(),
            "exclude_hashes": self.exclude_hashes_var.get(),
            "allow_ips": self.allow_ips_var.get(),
            "allow_ports": self.allow_ports_var.get(),
            "tray": bool(self.tray_var.get()),
        }
        try:
            CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _load_settings(self):
        if not CONFIG_PATH.exists():
            return
        try:
            self._loading_settings = True
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            self.kill_proc_var.set(bool(data.get("kill_proc", True)))
            self.auto_quarantine_var.set(bool(data.get("auto_quarantine", True)))
            self.read_only_var.set(bool(data.get("read_only", True)))
            self.full_scan_var.set(bool(data.get("full_scan", False)))
            self.log_scanned_var.set(bool(data.get("log_scanned", True)))
            self.background_var.set(bool(data.get("background", False)))
            self.max_files_var.set(int(data.get("max_files", 0)))
            self.exclude_paths_var.set(data.get("exclude_paths", ""))
            self.exclude_exts_var.set(data.get("exclude_exts", ""))
            self.exclude_hashes_var.set(data.get("exclude_hashes", ""))
            self.allow_ips_var.set(data.get("allow_ips", ""))
            self.allow_ports_var.set(data.get("allow_ports", ""))
            self.tray_var.set(bool(data.get("tray", False)))
            self._apply_read_only_state()
            if self.background_var.get() and not self.background_monitoring:
                self.toggle_background_monitor()
        except Exception:
            pass
        finally:
            self._loading_settings = False

    def _apply_read_only_state(self):
        ro = self.read_only_var.get() if hasattr(self, "read_only_var") else False
        state = tk.DISABLED if ro else tk.NORMAL
        if hasattr(self, "quarantine_btn"):
            self.quarantine_btn.config(state=state)
        if hasattr(self, "open_quarantine_btn"):
            self.open_quarantine_btn.config(state=state)
        if hasattr(self, "findings_menu"):
            try:
                self.findings_menu.entryconfig("Quarantine", state=state)
                self.findings_menu.entryconfig("Delete file", state=state)
            except Exception:
                pass
        if hasattr(self, "network_menu"):
            try:
                self.network_menu.entryconfig("Block IP (firewall)", state=state)
                self.network_menu.entryconfig("Block port (firewall)", state=state)
            except Exception:
                pass

    def _tick(self):
        # mini refresh stats
        self.stats_lbl.config(text=f"Menaces: {len(self.findings)}")
        self.net_stats_lbl.config(text=f"Net alerts: {len(self.network_findings)}")
        self.root.after(500, self._tick)

    def _set_progress_determinate(self, total: int):
        self.progress.stop()
        self.progress.config(value=0)
        self.progress.config(mode="determinate", maximum=total, value=0)

    def _update_progress(self, seen: int, total: int, folder: str):
        self.progress.config(value=seen)
        self.progress_label.config(text=f"Scan: {folder} ({seen}/{total})")

    def _parse_semicolon_list(self, text: str) -> list[str]:
        return [p.strip() for p in text.split(";") if p.strip()]

    def _parse_exclude_paths(self) -> list[str]:
        out = []
        for p in self._parse_semicolon_list(self.exclude_paths_var.get()):
            try:
                out.append(str(Path(p).resolve()).lower())
            except Exception:
                out.append(p.lower())
        return out

    def _parse_exclude_exts(self) -> set[str]:
        exts = set()
        for e in self._parse_semicolon_list(self.exclude_exts_var.get()):
            e = e.lower()
            if not e.startswith("."):
                e = "." + e
            exts.add(e)
        return exts

    def _parse_exclude_hashes(self) -> set[str]:
        return {h.lower() for h in self._parse_semicolon_list(self.exclude_hashes_var.get())}

    def pick_folder_scan(self):
        if self.scanning:
            return
        folder = filedialog.askdirectory(title="Choisir un dossier à scanner")
        if not folder:
            return
        self.current_scan_folder = folder
        self.start_scan(folder)

    def scan_system_drive_fast(self):
        if self.scanning:
            return
        drive = self._prompt_drive()
        if not drive:
            return
        folder = f"{drive}\\"
        self.current_scan_folder = folder
        self.start_scan(folder, max_files_override=5000)

    def _prompt_drive(self) -> str | None:
        drives = self._list_drives()
        if not drives:
            messagebox.showwarning("Disque", "Aucun disque detecte.")
            return None

        win = tk.Toplevel(self.root)
        win.title("Choisir un disque")
        win.configure(bg=THEME_BG)
        win.resizable(False, False)

        ttk.Label(win, text="Disque:", foreground=ACCENT).grid(row=0, column=0, padx=10, pady=10)
        choice = tk.StringVar(value=drives[0])
        combo = ttk.Combobox(win, textvariable=choice, values=drives, state="readonly", width=10)
        combo.grid(row=0, column=1, padx=10, pady=10)

        result: dict[str, str | None] = {"drive": None}

        def on_ok():
            result["drive"] = choice.get()
            win.destroy()

        def on_cancel():
            win.destroy()

        btns = ttk.Frame(win)
        btns.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 10))
        ttk.Button(btns, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btns, text="Annuler", command=on_cancel).pack(side=tk.LEFT, padx=5)

        win.transient(self.root)
        win.grab_set()
        self.root.wait_window(win)
        return result["drive"]

    def _list_drives(self) -> list[str]:
        drives = []
        try:
            for p in psutil.disk_partitions(all=False):
                if p.device and p.device.endswith("\\"):
                    drives.append(p.device.rstrip("\\"))
        except Exception:
            pass
        if not drives:
            drive = Path.home().drive
            if drive:
                drives.append(drive)
        return sorted(set(drives))

    def start_scan(self, folder: str, max_files_override: int | None = None):
        self.scanning = True
        self.stop_event.clear()
        self.pause_event.clear()
        if hasattr(self, "pause_btn"):
            self.pause_btn.config(text="Pause")
        self.findings = []
        self.auto_quarantined_count = 0
        for it in self.tree.get_children():
            self.tree.delete(it)

        self.status.config(text="Scan en cours…", foreground=ACCENT)
        self.progress_label.config(text=f"Scan: {folder}")
        self.progress.config(mode="indeterminate")
        self.progress.stop()
        self.progress.start(12)

        if max_files_override is not None:
            max_files = max_files_override
        else:
            max_files = int(self.max_files_var.get()) if self.max_files_var.get() else None
        exclude_paths = self._parse_exclude_paths()
        exclude_exts = self._parse_exclude_exts()
        exclude_hashes = self._parse_exclude_hashes()
        auto_quarantine = self.auto_quarantine_var.get() and not self.read_only_var.get()
        full_scan = self.full_scan_var.get()
        log_scanned = self.log_scanned_var.get()

        t = threading.Thread(
            target=self._scan_thread,
            args=(folder, max_files, exclude_paths, exclude_exts, exclude_hashes, auto_quarantine, full_scan, log_scanned),
            daemon=True,
        )
        t.start()

    def _scan_thread(self, folder: str, max_files, exclude_paths, exclude_exts, exclude_hashes,
                     auto_quarantine, full_scan, log_scanned):
        try:
            total = None
            if full_scan:
                self.root.after(0, lambda: self.progress_label.config(text=f"Counting files: {folder}"))
                total = 0
                for p in Path(folder).rglob("*"):
                    if self.stop_event.is_set():
                        break
                    if not p.is_file():
                        continue
                    if self.core._should_skip(p, exclude_paths, exclude_exts, exclude_hashes):
                        continue
                    total += 1
                if self.stop_event.is_set():
                    return
                total = max(1, total)
                self.root.after(0, lambda t=total: self._set_progress_determinate(t))

            def on_progress(seen):
                if total:
                    self.root.after(0, lambda s=seen, t=total: self._update_progress(s, t, folder))

            findings = self.core.scan_path(
                folder,
                max_files=max_files,
                exclude_paths=exclude_paths,
                exclude_exts=exclude_exts,
                exclude_hashes=exclude_hashes,
                stop_event=self.stop_event,
                pause_event=self.pause_event,
                progress_callback=on_progress if full_scan else None,
                log_scanned=log_scanned,
            )
            if not self.scanning:
                return
            self.findings = findings
            if auto_quarantine:
                for f in findings:
                    if f.level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                        res = self.core.quarantine(f, kill_process=self.kill_proc_var.get())
                        if res.get("ok"):
                            self.auto_quarantined_count += 1
            if auto_quarantine:
                self.root.after(0, self.refresh_quarantine)
            self.root.after(0, self.render_findings)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Erreur scan", str(e)))
        finally:
            self.scanning = False
            self.root.after(0, self.scan_done)

    def render_findings(self):
        for f in self.findings:
            lvl_txt, _color = LEVEL_TEXT.get(f.level, ("🟢 FAIBLE", ACCENT))
            ips = ",".join(f.remote_ips) if f.remote_ips else ""
            reasons = ";".join(f.reasons[:10])
            sha = (f.sha256[:18] + "…") if f.sha256 else ""
            self.tree.insert("", "end", values=(f.timestamp.split()[-1], lvl_txt, f.score, f.name, f.path, ips, reasons, sha))

    def _google_search_selected(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        if not values or len(values) < 4:
            return
        name = str(values[3]).strip()
        if not name:
            return
        url = "https://www.google.com/search?q=" + quote_plus(name)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    def scan_done(self):
        self.progress.stop()
        if self.stop_event.is_set():
            self.status.config(text="Scan stoppe.", foreground=WARN)
            self.progress_label.config(text="Scan stoppe.")
            messagebox.showinfo("Scan stoppe", f"Menaces detectees: {len(self.findings)}")
        else:
            if self.findings:
                self.status.config(text=f"Termine: {len(self.findings)} detection(s).", foreground=WARN)
            else:
                self.status.config(text="Termine: rien de suspect (selon regles actuelles).", foreground=ACCENT)
            self.progress_label.config(text="Pret.")
            messagebox.showinfo("Scan termine", f"Menaces detectees: {len(self.findings)}")

        self.progress.config(value=0)
        self._save_state()
        self.stop_event.clear()

    def stop_scan(self):
        self.stop_event.set()
        self.pause_event.clear()
        self.progress.stop()
        self.progress.config(value=0)
        self.status.config(text="Stop demandé.", foreground=WARN)
        self.progress_label.config(text="Stop demandé.")

    def toggle_pause(self):
        if not self.scanning:
            return
        if self.pause_event.is_set():
            self.pause_event.clear()
            self.status.config(text="Scan repris.", foreground=ACCENT)
            if hasattr(self, "pause_btn"):
                self.pause_btn.config(text="Pause")
        else:
            self.pause_event.set()
            self.status.config(text="Scan en pause.", foreground=WARN)
            if hasattr(self, "pause_btn"):
                self.pause_btn.config(text="Reprendre")

    def quarantine_selected(self):
        if self.read_only_var.get():
            messagebox.showinfo("Quarantaine", "Read-only mode is enabled.")
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Info", "Sélectionne une menace dans la liste.")
            return

        idx = self.tree.index(sel[0])
        if idx < 0 or idx >= len(self.findings):
            return

        f = self.findings[idx]
        if messagebox.askyesno("Quarantaine", f"Mettre en quarantaine:\n{f.path}\n\nNiveau: {f.level.name}\nScore: {f.score}"):
            res = self.core.quarantine(f, kill_process=self.kill_proc_var.get())
            if res.get("ok"):
                messagebox.showinfo("OK", f"Quarantaine OK:\n{res['dst']}")
                self._notify("Quarantine", f"{f.name} sent to quarantine")
                self.refresh_quarantine()
            else:
                messagebox.showerror("Erreur", str(res))

    def refresh_quarantine(self):
        items = self.core.list_quarantine_items()
        self.quarantine_items = items
        for it in self.q_tree.get_children():
            self.q_tree.delete(it)
        for item in items:
            ts = item.get("timestamp", "")
            lvl = item.get("level", "")
            name = item.get("name", "")
            original = item.get("path", "")
            quarantined = item.get("quarantined_to", "")
            self.q_tree.insert("", "end", values=(ts.split()[-1], lvl, name, original, quarantined))

    def _get_selected_quarantine_item(self):
        sel = self.q_tree.selection()
        if not sel:
            return None
        idx = self.q_tree.index(sel[0])
        if idx < 0 or idx >= len(self.quarantine_items):
            return None
        return self.quarantine_items[idx]

    def restore_quarantine_selected(self):
        item = self._get_selected_quarantine_item()
        if not item:
            messagebox.showwarning("Info", "Selectionne un element en quarantaine.")
            return
        meta_path = item.get("_meta_path")
        if not meta_path:
            messagebox.showerror("Restore", "Metadata path missing.")
            return
        res = self.core.restore_quarantine(meta_path)
        if res.get("ok"):
            messagebox.showinfo("Restore", "Restored to:\\n" + str(res.get("restored_to")))
            self.refresh_quarantine()
        else:
            err = res.get("error", "restore_failed")
            if err == "original_exists":
                messagebox.showerror("Restore", "Original path exists. Remove it first.")
            else:
                messagebox.showerror("Restore", str(res))

    def delete_quarantine_selected(self):
        item = self._get_selected_quarantine_item()
        if not item:
            messagebox.showwarning("Info", "Selectionne un element en quarantaine.")
            return
        if not messagebox.askyesno("Delete", "Delete this quarantined file?"):
            return
        meta_path = item.get("_meta_path")
        if not meta_path:
            messagebox.showerror("Delete", "Metadata path missing.")
            return
        res = self.core.delete_quarantine(meta_path)
        if res.get("ok"):
            messagebox.showinfo("Delete", "Deleted.")
            self.refresh_quarantine()
        else:
            messagebox.showerror("Delete", str(res))

    def sandbox_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Sandbox", "Select a file finding first.")
            return
        idx = self.tree.index(sel[0])
        if idx < 0 or idx >= len(self.findings):
            return
        f = self.findings[idx]
        src = Path(f.path)
        if not src.exists():
            messagebox.showerror("Sandbox", "File not found.")
            return
        def _hash_file(p: Path) -> str | None:
            try:
                h = hashlib.sha256()
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        h.update(chunk)
                return h.hexdigest()
            except Exception:
                return None
        src_hash = _hash_file(src)
        sandbox_exe = Path(r"C:\Windows\System32\WindowsSandbox.exe")
        if not sandbox_exe.exists():
            messagebox.showerror("Sandbox", "Windows Sandbox is not available.")
            return
        temp_dir = Path(tempfile.mkdtemp(prefix="hawkeye_sandbox_"))
        dst = temp_dir / src.name
        try:
            shutil.copy2(src, dst)
        except Exception as e:
            messagebox.showerror("Sandbox", str(e))
            return
        dst_hash = _hash_file(dst)
        if src_hash and dst_hash and src_hash != dst_hash:
            messagebox.showerror("Sandbox", "Hash mismatch after copy.")
            return
        wsb = temp_dir / "hawkeye.wsb"
        config = f"""<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{temp_dir}</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
</Configuration>
"""
        wsb.write_text(config, encoding="utf-8")
        try:
            subprocess.Popen([str(sandbox_exe), str(wsb)])
        except Exception as e:
            messagebox.showerror("Sandbox", str(e))

    def open_quarantine(self):
        import os
        try:
            os.startfile(str(Path("hawkeye_quarantine").resolve()))
        except Exception:
            messagebox.showerror("Erreur", "Impossible d’ouvrir le dossier quarantaine.")

    def _render_persistence_items(self):
        for it in self.persistence_tree.get_children():
            self.persistence_tree.delete(it)
        for r in self.persistence_findings:
            detail = str(r.get("hive")) + "\\" + str(r.get("key")) + " " + str(r.get("name")) + " = " + str(r.get("value"))
            self.persistence_tree.insert("", "end", values=("runkey", r.get("name"), detail, r.get("score"), ";".join(r.get("reasons") or [])))
        for t in self.persistence_tasks:
            self.persistence_tree.insert("", "end", values=("task", t.get("name"), t.get("action"), t.get("score"), ";".join(t.get("reasons") or [])))
        for s in self.persistence_services:
            self.persistence_tree.insert("", "end", values=("service", s.get("name"), s.get("bin_path"), s.get("score"), ";".join(s.get("reasons") or [])))

    def scan_persistence(self):
        res = self.core.scan_run_keys()
        self.persistence_findings = res or []
        self._render_persistence_items()
        if not res:
            messagebox.showinfo("Persistance", "Rien de suspect dans Run keys (selon règles actuelles).")
            return

        txt = "\n\n".join(
            [f"{r['hive']}\\{r['key']}\n{r['name']} = {r['value']}\nscore={r['score']} reasons={r['reasons']}"
             for r in res]
        )
        messagebox.showwarning("Persistance suspecte", txt[:3500])

    def scan_tasks(self):
        res = self.core.scan_schtasks()
        self.persistence_tasks = res or []
        self._render_persistence_items()
        if not res:
            messagebox.showinfo("Tasks", "No suspicious scheduled tasks found.")
            return
        messagebox.showwarning("Tasks suspect", "Suspicious tasks found: " + str(len(res)))

    def scan_services(self):
        res = self.core.scan_services()
        self.persistence_services = res or []
        self._render_persistence_items()
        if not res:
            messagebox.showinfo("Services", "No suspicious services found.")
            return
        messagebox.showwarning("Services suspect", "Suspicious services found: " + str(len(res)))


    def toggle_background_monitor(self):
        if self.background_monitoring:
            self.background_monitoring = False
            self.status.config(text="Background monitor: OFF", foreground=WARN)
            return
        self.background_monitoring = True
        self.status.config(text="Background monitor: ON", foreground=ACCENT)
        t = threading.Thread(target=self._background_thread, daemon=True)
        t.start()

    def _background_thread(self):
        watch_dirs = [Path.home() / "Downloads", Path.home() / "Desktop"]
        while self.background_monitoring:
            for base in watch_dirs:
                if not base.exists():
                    continue
                try:
                    for p in base.rglob("*"):
                        if not p.is_file():
                            continue
                        try:
                            st = p.stat()
                            sig = (st.st_size, int(st.st_mtime))
                        except Exception:
                            continue
                        key = str(p)
                        if self.bg_seen.get(key) == sig:
                            continue
                        self.bg_seen[key] = sig
                        f = self.core.analyze_file(p)
                        if not f:
                            continue
                        self.findings.append(f)
                        self.core.log({"type": "finding", **asdict(f), "level": f.level.name})
                        self.root.after(0, lambda ff=f: self._render_finding_row(ff))
                        if self.auto_quarantine_var.get() and not self.read_only_var.get() and f.level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                            res = self.core.quarantine(f, kill_process=self.kill_proc_var.get())
                            if res.get("ok"):
                                self.root.after(0, self.refresh_quarantine)
                                self._notify("Quarantine", f"{f.name} sent to quarantine")
                except Exception:
                    continue
            time.sleep(5)

    def _render_finding_row(self, f):
        lvl_txt, _color = LEVEL_TEXT.get(f.level, ("LOW", ACCENT))
        ips = ",".join(f.remote_ips) if f.remote_ips else ""
        reasons = ";".join(f.reasons[:10])
        sha = (f.sha256[:18] + "...") if f.sha256 else ""
        self.tree.insert("", "end", values=(f.timestamp.split()[-1], lvl_txt, f.score, f.name, f.path, ips, reasons, sha))

    def toggle_network_monitor(self):
        if self.network_monitoring:
            self.network_monitoring = False
            self.status.config(text="Network monitor: OFF", foreground=WARN)
            return
        self.network_monitoring = True
        self.status.config(text="Network monitor: ON", foreground=ACCENT)
        t = threading.Thread(target=self._network_thread, daemon=True)
        t.start()

    def _network_thread(self):
        while self.network_monitoring:
            try:
                allow_ips = normalize_ip_list(self._parse_semicolon_list(self.allow_ips_var.get()))
                allow_ports = normalize_port_list(self._parse_semicolon_list(self.allow_ports_var.get()))
                now = time.time()
                for c in psutil.net_connections(kind="inet"):
                    if not c.raddr:
                        continue
                    remote_ip = c.raddr.ip
                    remote_port = c.raddr.port
                    local_port = c.laddr.port if c.laddr else None
                    pid = c.pid
                    proc_name = None
                    if pid:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except Exception:
                            proc_name = None
                    key = (pid, remote_ip, remote_port)
                    last = self.net_last_seen.get(key, 0)
                    if now - last < NET_EVENT_THROTTLE_SECS:
                        continue
                    res = analyze_connection(
                        remote_ip,
                        remote_port,
                        local_port,
                        proc_name,
                        self.seen_remote_ips,
                        allow_ips,
                        allow_ports,
                    )
                    self.seen_remote_ips.add(remote_ip)
                    if not res:
                        continue
                    self.net_last_seen[key] = now
                    event = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "pid": pid,
                        "process": proc_name,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "score": res["score"],
                        "reasons": res["reasons"],
                        "level": level_from_score(res["score"]).name,
                    }
                    self.network_findings.append(event)
                    self.core.log({"type": "network", **event})
                    self.root.after(0, lambda ev=event: self._render_network_event(ev))
            except Exception:
                pass
            time.sleep(NETWORK_POLL_SECS)

    def _render_network_event(self, ev: dict):
        local = f":{ev.get('local_port')}" if ev.get("local_port") else ""
        remote = f"{ev.get('remote_ip')}:{ev.get('remote_port')}"
        reasons = ";".join(ev.get("reasons") or [])
        self.net_tree.insert(
            "",
            "end",
            values=(
                ev.get("timestamp", "").split()[-1],
                ev.get("level", ""),
                ev.get("pid") or "",
                ev.get("process") or "",
                local,
                remote,
                ev.get("score") or 0,
                reasons,
            ),
        )

    def refresh_history(self):
        path = Path("hawkeye_events.jsonl")
        if not path.exists():
            txt = "No events log found.\n"
        else:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-200:]
            out = []
            for line in lines:
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                ts = ev.get("timestamp", "-")
                et = ev.get("type", "event")
                if et == "finding":
                    out.append(f"{ts} finding {ev.get('level')} {ev.get('path')} score={ev.get('score')}")
                elif et == "quarantine":
                    out.append(f"{ts} quarantine {ev.get('src')} -> {ev.get('dst')}")
                elif et == "network":
                    out.append(f"{ts} network {ev.get('remote_ip')}:{ev.get('remote_port')} pid={ev.get('pid')} score={ev.get('score')}")
                elif et == "persistence":
                    out.append(f"{ts} persistence {ev.get('name')} score={ev.get('score')}")
                else:
                    out.append(f"{ts} {et}")
            txt = "\n".join(out) + "\n"

        self.history_text.configure(state=tk.NORMAL)
        self.history_text.delete("1.0", tk.END)
        self.history_text.insert("1.0", txt)
        self.history_text.configure(state=tk.DISABLED)

    def refresh_timeline(self):
        events = self.core.build_timeline()
        if not events:
            txt = "No timeline data.\n"
        else:
            groups = {}
            order = []
            for ev in events:
                eid = ev.get("event_id", "unknown")
                if eid not in groups:
                    groups[eid] = []
                    order.append(eid)
                groups[eid].append(ev)
            out = []
            type_order = {"finding": 0, "network": 1, "quarantine": 2}
            for eid in order:
                items = groups[eid]
                items.sort(key=lambda e: type_order.get(e.get("type"), 9))
                file_item = next((e for e in items if e.get("type") == "finding"), None)
                net_count = sum(1 for e in items if e.get("type") == "network")
                q_count = sum(1 for e in items if e.get("type") == "quarantine")
                summary = ""
                if file_item:
                    summary = (file_item.get("summary") or str(file_item))
                out.append("event_id=" + str(eid) + " | summary=" + summary + " | net=" + str(net_count) + " | quar=" + str(q_count))
                for ev in items:
                    ts = ev.get("timestamp", "-")
                    et = ev.get("type", "event")
                    summary = ev.get("summary") or str(ev)
                    out.append(ts + " | " + et + " | " + summary)
                out.append("")
            txt = "\n".join(out) + "\n"

        self.history_text.configure(state=tk.NORMAL)
        self.history_text.delete("1.0", tk.END)
        self.history_text.insert("1.0", txt)
        self.history_text.configure(state=tk.DISABLED)

    def _save_state(self):
        try:
            state = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_folder": self.current_scan_folder,
                "findings": [],
            }
            for f in self.findings:
                d = asdict(f)
                d["level"] = f.level.name
                state["findings"].append(d)
            Path("hawkeye_state.json").write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    def load_state(self):
        path = Path("hawkeye_state.json")
        if not path.exists():
            messagebox.showinfo("State", "No saved state found.")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            findings = []
            for f in data.get("findings", []):
                try:
                    level = ThreatLevel[f.get("level")]
                except Exception:
                    level = ThreatLevel.MEDIUM
                findings.append(Finding(
                    timestamp=f.get("timestamp", ""),
                    path=f.get("path", ""),
                    name=f.get("name", ""),
                    level=level,
                    category=f.get("category", "file"),
                    score=int(f.get("score", 0)),
                    reasons=f.get("reasons", []),
                    sha256=f.get("sha256"),
                    process_pids=f.get("process_pids"),
                    remote_ips=f.get("remote_ips"),
                ))
            self.findings = findings
            self.current_scan_folder = data.get("scan_folder")
            for it in self.tree.get_children():
                self.tree.delete(it)
            self.render_findings()
            messagebox.showinfo("State", f"Loaded findings: {len(findings)}")
        except Exception as e:
            messagebox.showerror("State error", str(e))

    def export_report(self):
        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("TXT", "*.txt"), ("CSV", "*.csv")],
        )
        if not path:
            return
        try:
            if Path(path).suffix.lower() == ".csv":
                self._export_csv(path)
            elif Path(path).suffix.lower() == ".txt":
                self._export_txt(path)
            else:
                self._export_json(path)
            messagebox.showinfo("Export", f"Report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def _export_json(self, path: str):
        files = []
        for f in self.findings:
            d = asdict(f)
            d["level"] = f.level.name
            files.append(d)
        report = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_folder": self.current_scan_folder,
            "files": files,
            "network": self.network_findings,
            "persistence": self.persistence_findings,
            "persistence_tasks": self.persistence_tasks,
            "persistence_services": self.persistence_services,
            "timeline": self.core.build_timeline(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    def _export_txt(self, path: str):
        lines = []
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Scan folder: {self.current_scan_folder}")
        lines.append(f"Findings: {len(self.findings)}")
        lines.append("")
        for f in self.findings:
            lines.append(f"[{f.level.name}] score={f.score} file={f.path}")
            if f.reasons:
                lines.append(f"  reasons: {', '.join(f.reasons)}")
            if f.sha256:
                lines.append(f"  sha256: {f.sha256}")
            if f.confidence:
                lines.append(f"  confidence: {f.confidence}")
            if f.remote_ips:
                lines.append(f"  remote_ips: {', '.join(f.remote_ips)}")
        lines.append("")
        lines.append(f"Network alerts: {len(self.network_findings)}")
        for ev in self.network_findings:
            lines.append(f"[{ev.get('score')}] {ev.get('remote_ip')}:{ev.get('remote_port')} pid={ev.get('pid')} proc={ev.get('process')}")
            if ev.get("reasons"):
                reasons = [str(r) for r in (ev.get("reasons") or [])]
                lines.append(f"  reasons: {', '.join(reasons)}")
        lines.append("")
        lines.append(f"Persistence: {len(self.persistence_findings)}")
        for ev in self.persistence_findings:
            lines.append(f"[{ev.get('score')}] {ev.get('hive')}\\{ev.get('key')} {ev.get('name')} = {ev.get('value')}")
        lines.append("")
        lines.append(f"Tasks: {len(self.persistence_tasks)}")
        for ev in self.persistence_tasks:
            lines.append(f"[{ev.get('score')}] {ev.get('name')} {ev.get('action')}")
        lines.append("")
        lines.append(f"Services: {len(self.persistence_services)}")
        for ev in self.persistence_services:
            lines.append(f"[{ev.get('score')}] {ev.get('name')} {ev.get('bin_path')}")
        lines.append("")
        timeline = self.core.build_timeline()
        lines.append(f"Timeline: {len(timeline)}")
        for ev in timeline:
            ts = ev.get("timestamp", "-")
            et = ev.get("type", "event")
            lines.append(f"{ts} | {et} | {ev}")
        Path(path).write_text("\\n".join(lines) + "\\n", encoding="utf-8")

    def _export_csv(self, path: str):
        fieldnames = [
            "type",
            "time",
            "level",
            "score",
            "confidence",
            "name",
            "path",
            "remote_ip",
            "remote_port",
            "local_port",
            "process",
            "reasons",
            "sha256",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for fi in self.findings:
                writer.writerow({
                    "type": "file",
                    "time": fi.timestamp,
                    "level": fi.level.name,
                    "score": fi.score,
                    "confidence": fi.confidence,
                    "name": fi.name,
                    "path": fi.path,
                    "remote_ip": ",".join(fi.remote_ips or []),
                    "remote_port": "",
                    "local_port": "",
                    "process": "",
                    "reasons": ";".join(fi.reasons or []),
                    "sha256": fi.sha256 or "",
                })
            for ev in self.network_findings:
                writer.writerow({
                    "type": "network",
                    "time": ev.get("timestamp"),
                    "level": "",
                    "score": ev.get("score"),
                    "confidence": "",
                    "name": "",
                    "path": "",
                    "remote_ip": ev.get("remote_ip"),
                    "remote_port": ev.get("remote_port"),
                    "local_port": ev.get("local_port"),
                    "process": ev.get("process"),
                    "reasons": ";".join(ev.get("reasons") or []),
                    "sha256": "",
                })
            for ev in self.persistence_findings:
                writer.writerow({
                    "type": "persistence",
                    "time": "",
                    "level": "",
                    "score": ev.get("score"),
                    "confidence": "",
                    "name": ev.get("name"),
                    "path": f"{ev.get('hive')}\\{ev.get('key')}",
                    "remote_ip": "",
                    "remote_port": "",
                    "local_port": "",
                    "process": "",
                    "reasons": ";".join(ev.get("reasons") or []),
                    "sha256": "",
                })
            for ev in self.persistence_tasks:
                writer.writerow({
                    "type": "persistence_task",
                    "time": "",
                    "level": "",
                    "score": ev.get("score"),
                    "confidence": "",
                    "name": ev.get("name"),
                    "path": ev.get("action"),
                    "remote_ip": "",
                    "remote_port": "",
                    "local_port": "",
                    "process": "",
                    "reasons": ";".join(ev.get("reasons") or []),
                    "sha256": "",
                })
            for ev in self.persistence_services:
                writer.writerow({
                    "type": "persistence_service",
                    "time": "",
                    "level": "",
                    "score": ev.get("score"),
                    "confidence": "",
                    "name": ev.get("name"),
                    "path": ev.get("bin_path"),
                    "remote_ip": "",
                    "remote_port": "",
                    "local_port": "",
                    "process": "",
                    "reasons": ";".join(ev.get("reasons") or []),
                    "sha256": "",
                })
            for ev in self.core.build_timeline():
                writer.writerow({
                    "type": "timeline",
                    "time": ev.get("timestamp"),
                    "level": "",
                    "score": ev.get("score"),
                    "confidence": "",
                    "name": ev.get("type"),
                    "path": ev.get("path") or ev.get("src") or ev.get("dst") or "",
                    "remote_ip": ev.get("remote_ip") or "",
                    "remote_port": ev.get("remote_port") or "",
                    "local_port": ev.get("local_port") or "",
                    "process": ev.get("process") or "",
                    "reasons": "",
                    "sha256": ev.get("sha256") or "",
                })

    def _on_close(self):
        self._save_settings()
        if hasattr(self, "tray_var") and self.tray_var.get():
            if self._ensure_tray():
                self.root.withdraw()
                return
        self.network_monitoring = False
        self.stop_event.set()
        self.pause_event.clear()
        self.scanning = False
        self.root.destroy()

    def _is_admin(self) -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def install_autostart_task(self):
        if not self._is_admin():
            messagebox.showerror("Auto-start", "Admin required to install scheduled task.")
            return
        if getattr(sys, "frozen", False):
            tr = f"\"{sys.executable}\""
        else:
            tr = f"\"{sys.executable}\" \"{Path(__file__).resolve()}\""
        cmd = [
            "schtasks",
            "/Create",
            "/TN",
            "HawkEyeEDR",
            "/TR",
            tr,
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/F",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            messagebox.showinfo("Auto-start", "Scheduled task installed.")
        else:
            messagebox.showerror("Auto-start error", res.stderr or res.stdout)

    def remove_autostart_task(self):
        if not self._is_admin():
            messagebox.showerror("Auto-start", "Admin required to remove scheduled task.")
            return
        cmd = ["schtasks", "/Delete", "/TN", "HawkEyeEDR", "/F"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            messagebox.showinfo("Auto-start", "Scheduled task removed.")
        else:
            messagebox.showerror("Auto-start error", res.stderr or res.stdout)

    def _ensure_tray(self):
        if not TRAY_AVAILABLE:
            messagebox.showerror("Tray", "pystray + pillow not installed.")
            return False
        if self.tray_icon is not None:
            return True

        image = Image.new("RGB", (64, 64), THEME_BG2)
        draw = ImageDraw.Draw(image)
        draw.rectangle((8, 8, 56, 56), outline=ACCENT, width=3)
        draw.line((16, 48, 28, 32, 40, 44, 52, 20), fill=ACCENT, width=3)

        menu = pystray.Menu(
            pystray.MenuItem("Show", self._show_window),
            pystray.MenuItem("Exit", self._exit_app),
        )
        self.tray_icon = pystray.Icon("HawkEye", image, "HawkEye", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()
        return True

    def _show_window(self, _icon=None, _item=None):
        self.root.after(0, lambda: self.root.deiconify())

    def _exit_app(self, _icon=None, _item=None):
        self.network_monitoring = False
        self.scanning = False
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.after(0, self.root.destroy)

if __name__ == "__main__":
    root = tk.Tk()
    app = HawkEyeUI(root)
    root.mainloop()

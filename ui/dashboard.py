import threading
import tkinter as tk
from datetime import datetime
from tkinter import scrolledtext, ttk

APP_VERSION = "v0.1.0"

class SecMonitorDashboard:
    def __init__(self, root: tk.Tk, scan_callback, max_failed_logins: int = 3):
        self.root = root
        self.scan_callback = scan_callback
        self.max_failed_logins = max_failed_logins
        self.refresh_interval_ms = 5000  # Auto-scan every 5 seconds
        self.expanded_groups: set[str] = set()  # Remembers which dropdowns are open

        self.root.title(f"SecMonitor {APP_VERSION} - Cross-Platform Live Dashboard")
        self.root.geometry("1220x680")
        self.root.configure(bg="#1e1e2e")

        self._configure_styles()
        self._build_layout()
        self._schedule_auto_scan()

    def _configure_styles(self):
        """Centralized styling to easily customize the UI later."""
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background="#11111b",
            foreground="#cdd6f4",
            fieldbackground="#11111b",
            rowheight=28,
            font=("Consolas", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#313244",
            foreground="#cdd6f4",
            font=("Arial", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#45475a")])

    def _build_layout(self):
        # Top Header & Live Indicator
        top_frame = tk.Frame(self.root, bg="#1e1e2e")
        top_frame.pack(fill="x", padx=20, pady=(15, 8))

        tk.Label(
            top_frame,
            text="Local Security & Network Monitor",
            font=("Arial", 16, "bold"),
            bg="#1e1e2e",
            fg="#cdd6f4",
        ).pack(side="left")

        self.live_status_var = tk.StringVar(value="● LIVE (Scanning every 5s)")
        tk.Label(
            top_frame,
            textvariable=self.live_status_var,
            font=("Consolas", 10, "bold"),
            bg="#1e1e2e",
            fg="#a6e3a1",
        ).pack(side="right")

        # System Info Card
        info_frame = tk.Frame(self.root, bg="#313244", padx=15, pady=10)
        info_frame.pack(fill="x", padx=20, pady=5)

        self.local_ip_var = tk.StringVar(value="Local IP: Scanning...")
        self.public_ip_var = tk.StringVar(value="Public IP: Scanning...")
        self.firewall_var = tk.StringVar(value="Firewall: Checking...")

        tk.Label(info_frame, textvariable=self.local_ip_var, font=("Consolas", 11), bg="#313244", fg="#a6e3a1").pack(anchor="w")
        tk.Label(info_frame, textvariable=self.public_ip_var, font=("Consolas", 11), bg="#313244", fg="#89b4fa").pack(anchor="w")
        tk.Label(info_frame, textvariable=self.firewall_var, font=("Consolas", 11), bg="#313244", fg="#f9e2af").pack(anchor="w")

        # Resizable Split Container (PanedWindow) for Network Table & Intrusion Logs
        self.paned_window = tk.PanedWindow(
            self.root,
            orient=tk.VERTICAL,
            bg="#45475a",        # Color of the draggable divider bar
            sashwidth=6,         # Thickness of the drag handle
            sashrelief=tk.RAISED,
            bd=0,
        )
        self.paned_window.pack(fill="both", expand=True, padx=20, pady=(10, 15))

        # --- TOP PANE: Active External Network Connections ---
        network_pane = tk.Frame(self.paned_window, bg="#1e1e2e")

        tk.Label(
            network_pane,
            text="Active External Network Connections (Click arrow ▸ to inspect TCP sockets | Drag bar below to resize)",
            font=("Arial", 11, "bold"),
            bg="#1e1e2e",
            fg="#cdd6f4",
        ).pack(anchor="w", pady=(0, 4))

        table_frame = tk.Frame(network_pane, bg="#1e1e2e")
        table_frame.pack(fill="both", expand=True)

        columns = ("time", "service", "website", "ip", "port", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="tree headings")

        self.tree.heading("#0", text="Application")
        self.tree.heading("time", text="Date & Time")
        self.tree.heading("service", text="Website / Service")
        self.tree.heading("website", text="Hostname / Server")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("port", text="Port")
        self.tree.heading("status", text="Status")

        self.tree.column("#0", width=165, anchor="w")
        self.tree.column("time", width=155, anchor="w")
        self.tree.column("service", width=195, anchor="w")
        self.tree.column("website", width=270, anchor="w")
        self.tree.column("ip", width=165, anchor="w")
        self.tree.column("port", width=65, anchor="center")
        self.tree.column("status", width=95, anchor="center")

        self.tree.tag_configure("SECURE", foreground="#a6e3a1")   # Green
        self.tree.tag_configure("WARNING", foreground="#f9e2af")  # Yellow
        self.tree.tag_configure("DANGER", foreground="#f38ba8")   # Red
        self.tree.tag_configure("CHILD", foreground="#9399b2")    # Subtle gray

        self.tree.bind("<<TreeviewOpen>>", self._on_row_open)
        self.tree.bind("<<TreeviewClose>>", self._on_row_close)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # --- BOTTOM PANE: Intrusion Detection (Failed Logins) ---
        logs_pane = tk.Frame(self.paned_window, bg="#1e1e2e")

        tk.Label(
            logs_pane,
            text="Intrusion Detection (Failed Logins)",
            font=("Arial", 11, "bold"),
            bg="#1e1e2e",
            fg="#cdd6f4",
        ).pack(anchor="w", pady=(6, 4))

        self.log_box = scrolledtext.ScrolledText(
            logs_pane,
            font=("Consolas", 9),
            bg="#11111b",
            fg="#cdd6f4",
        )
        self.log_box.pack(fill="both", expand=True)

        # Add both panes to the resizable splitter with minimum heights
        self.paned_window.add(network_pane, minsize=120, height=340)
        self.paned_window.add(logs_pane, minsize=90, height=160)

    def _on_row_open(self, event):
        selected = self.tree.focus()
        if selected:
            self.expanded_groups.add(selected)

    def _on_row_close(self, event):
        selected = self.tree.focus()
        if selected in self.expanded_groups:
            self.expanded_groups.remove(selected)

    def _schedule_auto_scan(self):
        """Triggers a background scan and schedules the next one in 5 seconds."""
        threading.Thread(target=self._worker, daemon=True).start()
        self.root.after(self.refresh_interval_ms, self._schedule_auto_scan)

    def _worker(self):
        data = self.scan_callback()
        self.root.after(0, self.update_display, data)

    def update_display(self, data: dict):
        now = datetime.now().strftime("%H:%M:%S")
        self.live_status_var.set(f"● LIVE | Updated: {now} (5s interval)")

        self.local_ip_var.set(f"Local IP: {data['local_ip']}")
        self.public_ip_var.set(f"Public IP: {data['public_ip']}")
        self.firewall_var.set(f"Firewall: {data['firewall']}")

        # Clear existing rows
        for row in self.tree.get_children():
            self.tree.delete(row)

        for conn in data["connections"]:
            group_id = conn["group_id"]
            status = conn["status"]
            is_open = group_id in self.expanded_groups

            self.tree.insert(
                "",
                tk.END,
                iid=group_id,
                text=conn["app"],
                open=is_open,
                values=(
                    conn["time"],
                    conn["service"],
                    conn["website"],
                    conn["ip"],
                    conn["port"],
                    status,
                ),
                tags=(status,),
            )

            if len(conn["details"]) > 1:
                for detail in conn["details"]:
                    self.tree.insert(
                        group_id,
                        tk.END,
                        text=detail["app"],
                        values=(
                            detail["time"],
                            detail["service"],
                            detail["website"],
                            detail["ip"],
                            detail["port"],
                            detail["status"],
                        ),
                        tags=("CHILD",),
                    )

        # Refresh Intrusion Logs
        self.log_box.delete(1.0, tk.END)
        alerts = data["alerts"]
        if len(alerts) >= self.max_failed_logins:
            self.log_box.insert(tk.END, f"[WARNING] {len(alerts)} failed login attempts detected!\n")

        if alerts:
            for alert in alerts:
                self.log_box.insert(tk.END, f"! {alert}\n")
        else:
            self.log_box.insert(tk.END, "No failed login attempts found in recent logs.\n")
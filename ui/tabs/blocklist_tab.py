
import tkinter as tk
from tkinter import ttk, messagebox, Menu, filedialog, scrolledtext
import os
import sys
import threading
import time
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

from core.logger import Logger
from core.config import Config
from core.utils import is_admin, run_as_admin, is_local_ip, safe_subprocess_run
from core.exceptions import (
    WinDetoxError, SecurityError, ValidationError, FirewallError, 
    BlocklistError, UpdateError, PermissionError, DetailedError
)
from managers.settings_manager import SettingsManager
from network.network_service import NetworkService
from network.network_monitor import NetworkMonitor, ConnectionInfo
from ui.system_tray import SystemTrayManager


class WinDetoxGUI:
    """GUI class fragment for blocklist_tab"""
    
    def __init__(self, root: tk.Tk = None, 
                 logger: Logger = None,
                 network_service: NetworkService = None,
                 settings_manager: SettingsManager = None):
        self.root = root
        self.logger = logger
        self.network_service = network_service
        self.settings = settings_manager

    def _unblock_from_treeview(self, tree):
            """Unblock IPs selected in treeview"""
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("No Selection", "Please select one or more IPs.")
                return

            ips_to_unblock = []
            for item in sel:
                values = tree.item(item, "values")
                if values:
                    ips_to_unblock.append(values[0])  # First column is IP

            if not ips_to_unblock:
                return

            ip_list = "\n".join(ips_to_unblock)
            if messagebox.askyesno(
                "Unblock IPs", 
                f"Really unblock these IPs?\n\n{ip_list}\n\nTotal: {len(ips_to_unblock)} IPs"
            ):
                try:
                    results = self.network_service.unblock_ips(ips_to_unblock)

                    # Remove from tree
                    for item in sel:
                        tree.delete(item)

                    if results["failed"]:
                        messagebox.showwarning(
                            "Partial Success", 
                            f"{results['unblocked']}/{results['total']} IPs unblocked.\n"
                            f"Failed: {', '.join(results['failed'][:5])}"
                        )
                    else:
                        messagebox.showinfo(
                            "Success", 
                            f"{results['unblocked']} IPs have been unblocked."
                        )
                except (BlocklistError, FirewallError) as e:
                    messagebox.showerror("Error", f"Failed to unblock IPs: {e}")

    def _copy_selected_ip(self, tree):
            """Copy selected IP to clipboard"""
            sel = tree.selection()
            if not sel:
                return

            item = sel[0]
            values = tree.item(item, "values")
            if values:
                ip = values[0]
                self.root.clipboard_clear()
                self.root.clipboard_append(ip)
                self.log_append(f"Copied IP to clipboard: {ip}\n")

    def _refresh_dns_resolution(tree, blocklist, status_var, stats_vars, progress, details_text, cancelled):
            """Refresh DNS resolution for all IPs in current window"""
            # Clear tree
            for item in tree.get_children():
                tree.delete(item)

            # Reset stats
            stats_vars["resolved"].set("Resolved: 0")
            stats_vars["timeout"].set("Timeout: 0")
            stats_vars["error"].set("Error: 0")
            stats_vars["total"].set(f"Total: {len(blocklist.blocked_ips)}")

            # Clear details log
            details_text.config(state="normal")
            details_text.delete(1.0, tk.END)
            details_text.insert(tk.END, "=== DNS REFRESH STARTED ===\n")
            details_text.config(state="disabled")

            # Reset progress bar
            progress['value'] = 0
            status_var.set("Starting DNS refresh...")
            win.update_idletasks()

            # Cancel any ongoing resolution
            cancelled.set()
            time.sleep(0.1)  # Give thread time to stop
            cancelled.clear()

            # Re-display all IPs (without hostname resolution yet)
            ips = sorted(blocklist.blocked_ips)
            for idx, ip in enumerate(ips):
                src = blocklist.sources.get(ip, "Unknown")
                tree.insert("", "end", text=str(idx+1), 
                           values=(ip, "Resolving...", src))

            # Start new resolution in background thread
            def refresh_turbo_resolve():
                # Call the existing turbo_resolve function
                turbo_resolve()

            resolution_thread = threading.Thread(target=refresh_turbo_resolve, daemon=True)
            resolution_thread.start()

    def _refresh_dns_for_selected(self, tree, blocklist):
            """Refresh DNS resolution only for selected IPs"""
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("No Selection", "Please select IPs to refresh.")
                return

            def resolve_selected():
                for item in sel:
                    values = tree.item(item, "values")
                    if values:
                        ip = values[0]
                        try:
                            socket.setdefaulttimeout(1.0)
                            hostname = socket.gethostbyaddr(ip)[0]
                            hostname = hostname.split('.')[0]
                            tree.item(item, values=(ip, hostname, values[2]))
                            tree.item(item, tags=("resolved",))
                        except:
                            tree.item(item, values=(ip, "unknown", values[2]))

            threading.Thread(target=resolve_selected, daemon=True).start()

    def _export_blocked_ips(self, tree, blocklist):
            """Export blocked IPs to CSV file"""
            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[
                    ("CSV file", "*.csv"),
                    ("Text file", "*.txt"),
                    ("All files", "*.*")
                ],
                initialfile="windetox_blocked_ips.csv"
            )

            if not filepath:
                return

            try:
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    # Write header
                    writer.writerow(["ID", "IP Address", "Hostname", "Source", "Timestamp"])

                    # Write data
                    for idx, item in enumerate(tree.get_children(), 1):
                        values = tree.item(item, "values")
                        if values:
                            writer.writerow([idx] + list(values) + [datetime.now().strftime("%Y-%m-%d %H:%M:%S")])

                messagebox.showinfo("Export Successful", 
                                  f"Blocked IPs exported to:\n{filepath}\n\n"
                                  f"Total: {len(tree.get_children())} IPs")
                self.log_append(f"Exported blocked IPs to: {filepath}\n")

            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {e}")


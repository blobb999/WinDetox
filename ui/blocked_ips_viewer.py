"""
Blocked IPs Viewer - GUI window for displaying and managing blocked IPs
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, Menu, filedialog, messagebox
from typing import Dict, List, Optional, Callable
import threading
import csv
from datetime import datetime

from network.dns_resolver import TurboDNSResolver


class BlockedIPsViewer:
    """GUI window for displaying blocked IPs with enhanced DNS resolution"""
    
    def __init__(self, parent, network_service, logger=None, 
                 on_unblock_callback=None, on_copy_callback=None):
        """
        Initialize blocked IPs viewer
        
        Args:
            parent: Parent tkinter window
            network_service: NetworkService instance
            logger: Logger instance
            on_unblock_callback: Callback for unblocking IPs
            on_copy_callback: Callback for copying IPs
        """
        self.parent = parent
        self.network_service = network_service
        self.logger = logger
        self.on_unblock = on_unblock_callback
        self.on_copy = on_copy_callback
        
        self.blocklist = network_service.blocklist
        self.window = None
        self.tree = None
        self.dns_resolver = TurboDNSResolver(logger=logger)
        self.ip_analyzer = self.dns_resolver.ip_analyzer
        
        # Statistics variables
        self.stats_vars = {
            "resolved": tk.StringVar(value="Resolved: 0"),
            "timeout": tk.StringVar(value="Timeout: 0"),
            "error": tk.StringVar(value="Error: 0"),
            "microsoft": tk.StringVar(value="Microsoft: 0"),
            "cloud": tk.StringVar(value="Cloud: 0"),
            "total": tk.StringVar(value="Total: 0")
        }
        
        # UI elements
        self.progress = None
        self.status_var = None
        self.details_text = None
        
        # Thread control
        self.resolution_thread = None
        self.is_window_destroyed = threading.Event()
    
    def show(self):
        """Show the blocked IPs window"""
        if not self.blocklist.blocked_ips:
            messagebox.showinfo("Empty Blocklist", "No IPs blocked.")
            return
        
        # Create window
        self.window = tk.Toplevel(self.parent)
        self.window.title("Blocked IPs – Turbo Resolver")
        self.window.geometry("1100x750")
        self.window.transient(self.parent)
        self.window.grab_set()
        
        self._setup_gui()
        self._setup_events()
        
        # Reset destroyed flag
        self.is_window_destroyed.clear()
        
        # Start DNS resolution in background
        self.resolution_thread = threading.Thread(target=self._start_resolution, daemon=True)
        self.resolution_thread.start()
    
    def _setup_gui(self):
        """Setup GUI components"""
        # Title
        title_label = ttk.Label(self.window, text="⚡ TURBO DNS RESOLUTION - Blocked IPs", 
                               font=("", 14, "bold"), foreground="#0066cc")
        title_label.pack(pady=15)
        
        # Info frame
        info_frame = ttk.Frame(self.window)
        info_frame.pack(pady=5, padx=20, fill="x")
        
        total_ips = len(self.blocklist.blocked_ips)
        ttk.Label(info_frame, 
                  text=f"Resolving {total_ips} blocked IPs with parallel DNS queries...",
                  font=("", 10)).pack(side="left")
        
        # Progress bar
        progress_frame = ttk.Frame(self.window)
        progress_frame.pack(pady=10, padx=20, fill="x")
        
        self.progress = ttk.Progressbar(progress_frame, length=800, mode='determinate')
        self.progress.pack(fill="x", pady=(5, 0))
        
        # Status
        self.status_var = tk.StringVar(value="Initializing Turbo DNS Resolver...")
        status_label = ttk.Label(self.window, textvariable=self.status_var, 
                                font=("", 10, "bold"), wraplength=800)
        status_label.pack(pady=10)
        
        # Enhanced statistics frame
        stats_frame = ttk.Frame(self.window)
        stats_frame.pack(pady=10, padx=20, fill="x")

        # First row
        stats_row1 = ttk.Frame(stats_frame)
        stats_row1.pack(fill="x", pady=2)

        ttk.Label(stats_row1, textvariable=self.stats_vars["resolved"], 
                 foreground="green", font=("", 9)).pack(side="left", padx=10)
        ttk.Label(stats_row1, textvariable=self.stats_vars["timeout"], 
                 foreground="orange", font=("", 9)).pack(side="left", padx=10)
        ttk.Label(stats_row1, textvariable=self.stats_vars["error"], 
                 foreground="red", font=("", 9)).pack(side="left", padx=10)
        ttk.Label(stats_row1, textvariable=self.stats_vars["total"], 
                 font=("", 9, "bold")).pack(side="left", padx=10)

        # Second row for cloud stats
        stats_row2 = ttk.Frame(stats_frame)
        stats_row2.pack(fill="x", pady=2)

        ttk.Label(stats_row2, textvariable=self.stats_vars["microsoft"], 
                 foreground="#1565c0", font=("", 9)).pack(side="left", padx=10)
        ttk.Label(stats_row2, textvariable=self.stats_vars["cloud"], 
                 foreground="#7b1fa2", font=("", 9)).pack(side="left", padx=10)
        
        # Main content frame
        content_frame = ttk.Frame(self.window)
        content_frame.pack(pady=15, padx=20, fill="both", expand=True)
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(0, weight=1)
        
        # Treeview with scrollbars
        tree_frame = ttk.Frame(content_frame)
        tree_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Create Treeview with columns
        self.tree = ttk.Treeview(tree_frame, columns=("IP", "Hostname", "Source"), 
                                show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="ID")
        self.tree.column("#0", width=50, stretch=False)
        self.tree.heading("IP", text="IP Address")
        self.tree.column("IP", width=150, stretch=False)
        self.tree.heading("Hostname", text="Resolved Hostname")
        self.tree.column("Hostname", width=300)
        self.tree.heading("Source", text="Source")
        self.tree.column("Source", width=200)

        # Configure tree tags for colors
        self.tree.tag_configure("resolved", background="#e8f5e8", foreground="#006400")
        self.tree.tag_configure("timeout", background="#fff3e0", foreground="#ff8c00")
        self.tree.tag_configure("error", background="#ffebee", foreground="#d32f2f")
        self.tree.tag_configure("microsoft", background="#e3f2fd", foreground="#1565c0")
        self.tree.tag_configure("cloud", background="#f3e5f5", foreground="#7b1fa2")
        self.tree.tag_configure("no-dns", background="#f5f5f5", foreground="#616161")
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        # Details text widget
        details_frame = ttk.LabelFrame(self.window, text="Details", padding=10)
        details_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, width=80,
                                                     state="disabled", font=("Consolas", 9))
        self.details_text.pack(fill="both", expand=True)
        
        # Action buttons frame
        self._setup_action_buttons()
        
        # Context menu
        self._setup_context_menu()
    
    def _setup_action_buttons(self):
        """Setup action buttons"""
        action_frame = ttk.Frame(self.window)
        action_frame.pack(pady=15)
        
        ttk.Button(action_frame, text="Unblock Selected IPs", 
                  command=self._unblock_selected).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Copy IP", 
                  command=self._copy_selected).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Refresh DNS", 
                  command=self._refresh_dns).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Export to CSV", 
                  command=self._export_csv).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Close", 
                  command=self._safe_destroy).pack(side="left", padx=5)
        
        # Cancel button
        cancel_button = ttk.Button(self.window, text="Cancel Resolution", 
                                  command=self._cancel_resolution)
        cancel_button.pack(pady=10)
    
    def _setup_context_menu(self):
        """Setup context menu for treeview"""
        ctx_menu = Menu(self.tree, tearoff=0)
        ctx_menu.add_command(label="Unblock IP", command=self._unblock_selected)
        ctx_menu.add_command(label="Copy IP", command=self._copy_selected)
        ctx_menu.add_separator()
        ctx_menu.add_command(label="Refresh DNS for selected", 
                            command=self._refresh_selected_dns)
        
        self.tree.bind("<Button-3>", 
                      lambda e: ctx_menu.tk_popup(e.x_root, e.y_root) 
                      if self.tree.selection() else None)
    
    def _setup_events(self):
        """Setup window events"""
        self.window.protocol("WM_DELETE_WINDOW", self._safe_destroy)
    
    def _safe_destroy(self):
        """Safely destroy window and stop all threads"""
        # Mark window as destroyed
        self.is_window_destroyed.set()
        
        # Cancel DNS resolution
        self.dns_resolver.cancel()
        
        # Wait a bit for thread to respond
        if self.resolution_thread and self.resolution_thread.is_alive():
            self.resolution_thread.join(timeout=1.0)
        
        # Destroy window
        self.window.destroy()
    
    def _safe_after(self, delay_ms: int, func: Callable, *args):
        """Safely schedule a function with after(), checking if window exists"""
        if not self.is_window_destroyed.is_set() and self.window:
            try:
                self.window.after(delay_ms, func, *args)
            except:
                # Window might be destroyed between check and after()
                pass
    
    def _log_detail(self, message: str):
        """Add message to details log"""
        if self.is_window_destroyed.is_set() or not self.window:
            return
            
        try:
            self.details_text.config(state="normal")
            self.details_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
            self.details_text.see(tk.END)
            self.details_text.config(state="disabled")
            self.window.update_idletasks()
        except:
            # Window destroyed during update
            self.is_window_destroyed.set()
    
    def _update_progress(self, current: int, total: int, text: str):
        """Update progress bar and status"""
        if self.is_window_destroyed.is_set() or not self.window:
            return
            
        try:
            progress_percent = (current / total) * 100 if total > 0 else 100
            self.progress['value'] = progress_percent
            self.status_var.set(text)
            self.window.update_idletasks()
        except:
            # Window destroyed during update
            self.is_window_destroyed.set()
    
    def _update_stats(self, resolved: int, timeout: int, error: int, 
                     microsoft: int, cloud: int, total: int):
        """Update statistics display"""
        if self.is_window_destroyed.is_set() or not self.window:
            return
            
        try:
            self.stats_vars["resolved"].set(f"Resolved: {resolved}")
            self.stats_vars["timeout"].set(f"Timeout: {timeout}")
            self.stats_vars["error"].set(f"Error: {error}")
            self.stats_vars["microsoft"].set(f"Microsoft: {microsoft}")
            self.stats_vars["cloud"].set(f"Cloud: {cloud}")
            self.stats_vars["total"].set(f"Total: {total}")
            self.window.update_idletasks()
        except:
            # Window destroyed during update
            self.is_window_destroyed.set()
    
    def _update_tree_item(self, idx: int, ip: str, hostname: str, source: str, 
                         is_microsoft: bool, is_cloud: bool):
        """Update a single tree item (thread-safe)"""
        if self.is_window_destroyed.is_set() or not self.window:
            return
            
        try:
            # Find item with the given ID
            for item in self.tree.get_children():
                if self.tree.item(item, "text") == str(idx + 1):
                    self.tree.item(item, values=(ip, hostname, source))
                    
                    # Set tags based on IP type
                    tags = []
                    if hostname == "timeout":
                        tags.append("timeout")
                    elif hostname in ["error", "invalid-ip"]:
                        tags.append("error")
                    elif is_microsoft:
                        tags.append("microsoft")
                    elif is_cloud:
                        tags.append("cloud")
                    elif hostname not in ["unknown", "N/A", "Resolving...", "no-reverse-dns"]:
                        tags.append("resolved")
                    else:
                        tags.append("no-dns")
                    
                    self.tree.item(item, tags=tuple(tags))
                    break
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Failed to update tree item: {e}")
            # Window likely destroyed
            self.is_window_destroyed.set()
    
    def _start_resolution(self):
        """Start DNS resolution process"""
        ips = sorted(self.blocklist.blocked_ips)
        total = len(ips)
        
        # Check if window still exists
        if self.is_window_destroyed.is_set():
            return
        
        # Initial display of IPs
        self._safe_after(0, self._update_progress, 0, total, "Initial display setup...")
        self._safe_after(0, lambda: self.stats_vars["total"].set(f"Total: {total}"))
        
        # Quick analysis for initial counts
        microsoft_count, cloud_count = self.dns_resolver.quick_analyze_ips(ips)
        
        # Insert all IPs initially
        for idx, ip in enumerate(ips):
            if self.is_window_destroyed.is_set():
                break
                
            source = self.blocklist.sources.get(ip, "Unknown")
            
            # Quick detection for initial coloring
            is_microsoft = self.ip_analyzer.is_microsoft_ip(ip)
            is_cloud = self.ip_analyzer.is_cloud_ip(ip) and not is_microsoft
            
            tags = []
            if is_microsoft:
                tags.append("microsoft")
                source = f"{source} (Microsoft)"
            elif is_cloud:
                tags.append("cloud")
                source = f"{source} (Cloud)"
            
            self._safe_after(0, self._insert_tree_item, idx, ip, "Resolving...", source, tuple(tags))
            
            if idx % 100 == 0:
                self._safe_after(0, self._update_stats, 0, 0, 0, microsoft_count, cloud_count, total)
        
        # Start DNS resolution with safe callbacks
        stats = self.dns_resolver.batch_resolve(
            ips,
            progress_callback=lambda curr, tot, msg: self._safe_after(
                0, self._update_progress, curr, tot, msg
            ) if not self.is_window_destroyed.is_set() else None,
            result_callback=lambda idx, ip, hostname, status, is_ms, is_cl: self._safe_after(
                0, self._handle_dns_result, idx, ip, hostname, status, is_ms, is_cl
            ) if not self.is_window_destroyed.is_set() else None
        )
        
        # Final update (only if window still exists)
        if not self.is_window_destroyed.is_set():
            self._safe_after(0, self._finalize_resolution, stats)
    
    def _insert_tree_item(self, idx: int, ip: str, hostname: str, source: str, tags: tuple):
        """Insert item into treeview (GUI thread)"""
        if self.is_window_destroyed.is_set() or not self.window:
            return
            
        try:
            self.tree.insert("", "end", text=str(idx + 1), 
                            values=(ip, hostname, source), tags=tags)
        except:
            # Window destroyed
            self.is_window_destroyed.set()
    
    def _handle_dns_result(self, idx: int, ip: str, hostname: str, 
                          status: str, is_microsoft: bool, is_cloud: bool):
        """Handle DNS resolution result (GUI thread)"""
        if self.is_window_destroyed.is_set():
            return
            
        try:
            source = self.blocklist.sources.get(ip, "Unknown")
            
            # Enhance source with provider info if available
            provider = self.ip_analyzer.get_provider_info(ip)
            if provider != "Unknown ISP":
                source = f"{source} ({provider})"
            
            self._update_tree_item(idx, ip, hostname, source, is_microsoft, is_cloud)
            self._log_detail(f"Resolved {ip} -> {hostname}")
        except:
            # Window destroyed during update
            self.is_window_destroyed.set()
    
    def _finalize_resolution(self, stats: Dict):
        """Finalize resolution process (GUI thread)"""
        if self.is_window_destroyed.is_set():
            return
            
        try:
            self._update_progress(stats["total"], stats["total"], 
                                 f"✅ TURBO DNS resolution complete! "
                                 f"Resolved: {stats['resolved']}/{stats['total']} "
                                 f"(Microsoft: {stats['microsoft']}, Cloud: {stats['cloud']})")
            
            self._update_stats(stats["resolved"], stats["timeout"], stats["error"],
                              stats["microsoft"], stats["cloud"], stats["total"])
            
            self._log_detail("✅ DNS resolution completed successfully!")
        except:
            # Window destroyed during update
            self.is_window_destroyed.set()
    
    def _unblock_selected(self):
        """Unblock selected IPs"""
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Please select one or more IPs.")
            return
        
        ips_to_unblock = []
        for item in sel:
            values = self.tree.item(item, "values")
            if values:
                ips_to_unblock.append(values[0])  # First column is IP
        
        if not ips_to_unblock:
            return
        
        ip_list = "\n".join(ips_to_unblock)
        if messagebox.askyesno(
            "Unblock IPs", 
            f"Really unblock these IPs?\n\n{ip_list}\n\nTotal: {len(ips_to_unblock)} IPs"
        ):
            if self.on_unblock:
                # Use the callback from main application
                self.on_unblock(self.tree)
            else:
                # Fallback: direct unblock
                try:
                    results = self.network_service.unblock_ips(ips_to_unblock)
                    # Remove from tree
                    for item in sel:
                        self.tree.delete(item)
                    
                    messagebox.showinfo(
                        "Success", 
                        f"{results['unblocked']} IPs have been unblocked."
                    )
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to unblock IPs: {e}")
    
    def _copy_selected(self):
        """Copy selected IP to clipboard"""
        sel = self.tree.selection()
        if not sel:
            return
        
        item = sel[0]
        values = self.tree.item(item, "values")
        if values:
            ip = values[0]
            self.window.clipboard_clear()
            self.window.clipboard_append(ip)
            self._log_detail(f"Copied IP to clipboard: {ip}")
    
    def _refresh_dns(self):
        """Refresh DNS resolution for all IPs"""
        self.dns_resolver.cancel()
        
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Reset stats
        self._update_stats(0, 0, 0, 0, 0, 0)
        self.progress['value'] = 0
        self.status_var.set("Starting DNS refresh...")
        
        # Start new resolution
        threading.Thread(target=self._start_resolution, daemon=True).start()
    
    def _refresh_selected_dns(self):
        """Refresh DNS resolution only for selected IPs"""
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Please select IPs to refresh.")
            return
        
        def resolve_selected():
            import socket
            for item in sel:
                values = self.tree.item(item, "values")
                if values:
                    ip = values[0]
                    try:
                        socket.setdefaulttimeout(1.0)
                        hostname = socket.gethostbyaddr(ip)[0]
                        hostname = hostname.split('.')[0]
                        
                        # Determine IP type
                        is_microsoft = self.ip_analyzer.is_microsoft_ip(ip)
                        is_cloud = self.ip_analyzer.is_cloud_ip(ip) and not is_microsoft
                        
                        source = values[2] if len(values) > 2 else "Unknown"
                        self.window.after(0, self._update_tree_item, 
                                         int(self.tree.item(item, "text")) - 1,
                                         ip, hostname, source, is_microsoft, is_cloud)
                    except:
                        source = values[2] if len(values) > 2 else "Unknown"
                        self.window.after(0, self._update_tree_item,
                                         int(self.tree.item(item, "text")) - 1,
                                         ip, "unknown", source, False, False)
        
        threading.Thread(target=resolve_selected, daemon=True).start()
    
    def _cancel_resolution(self):
        """Cancel DNS resolution"""
        self.dns_resolver.cancel()
        self.status_var.set("❌ Resolution cancelled by user")
        self._log_detail("DNS resolution cancelled by user")
    
    def _export_csv(self):
        """Export blocked IPs to CSV file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV file", "*.csv"),
                ("Text file", "*.txt"),
                ("All files", "*.*")
            ],
            initialfile=f"windetox_blocked_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if not filepath:
            return
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # Enhanced header
                writer.writerow([
                    "ID", "IP Address", "Hostname", "Source", 
                    "Provider", "Is Cloud", "Is Microsoft", "Is CDN",
                    "Country", "Organization", "Timestamp"
                ])
                
                # Write data with enhanced info
                for idx, item in enumerate(self.tree.get_children(), 1):
                    values = self.tree.item(item, "values")
                    if values:
                        ip = values[0]
                        
                        # Get additional info from analyzer
                        info = self.ip_analyzer.analyze_ip(ip)
                        
                        writer.writerow([
                            idx,
                            ip,
                            values[1],  # hostname
                            values[2],  # source
                            info.get('provider', 'Unknown'),
                            "Yes" if info.get('is_cloud') else "No",
                            "Yes" if info.get('is_microsoft') else "No",
                            "Yes" if info.get('is_cdn') else "No",
                            info.get('country', 'N/A'),
                            info.get('org', 'N/A'),
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        ])
            
            messagebox.showinfo("Export Successful", 
                              f"Enhanced blocklist exported to:\n{filepath}\n\n"
                              f"Total: {len(self.tree.get_children())} IPs\n"
                              f"Includes provider and location information!")
            
            if self.logger:
                self.logger.info(f"Exported enhanced blocklist to: {filepath}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")

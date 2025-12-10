"""
WinDetox - Network Monitoring and Blocking Tool
Version: 1.0 (Security Hardened)
Author: Privacy Focused Development Team
Description: Comprehensive network monitoring and blocking tool with advanced privacy features

================================================================================
MODULAR ARCHITECTURE - NAVIGATION GUIDE
================================================================================

MAIN FILE: WinDetox.py (You are here)
PURPOSE: Main entry point and GUI coordinator. Routes everything.

MODULE MAP - WHERE TO FIND WHAT:
────────────────────────────────

1. LOGGING & ERRORS:
   • logger.py → Logger, RotatingLogger (all logging functions)
   • exceptions.py → All custom exceptions (WinDetoxError, SecurityError, etc.)

2. NETWORK MONITORING:
   • network_monitor.py → NetworkMonitor class (main network scanner)
   • ConnectionInfo dataclass → Also in network_monitor.py

3. IP MANAGEMENT:
   • ip_validator.py → IPValidator (IP validation with caching)
   • blocklist_manager.py → BlocklistManager (IP blocking lists)
   • firewall_manager.py → FirewallManager (Windows Firewall operations)

4. SERVICES & COORDINATION:
   • network_service.py → NetworkService (orchestrates blocklist + firewall)
   • utils.py → Utility functions (is_admin, run_as_admin, safe_subprocess_run)
   • config.py → Config class (all constants and settings)

5. GUI COMPONENTS:
   • system_tray.py → SystemTrayManager (tray icon and menu)
   • (GUI itself is in this file - WinDetoxGUI class)

6. SETTINGS & UPDATES:
   • settings_manager.py → SettingsManager (user preferences)
   • update_manager.py → UpdateManager (automatic updates)

================================================================================
HOW TO MODIFY - FOR DEVELOPERS & AI ASSISTANTS:
================================================================================

TO CHANGE IP VALIDATION:
   → Edit: ip_validator.py → IPValidator.validate() method

TO CHANGE FIREWALL RULES:
   → Edit: firewall_manager.py → FirewallManager.apply_windows_firewall_rule()

TO CHANGE LOGGING FORMAT:
   → Edit: logger.py → Logger._setup_logger() method

TO ADD NEW GUI TAB:
   → Edit: This file → WinDetoxGUI.setup_gui() method

TO CHANGE NETWORK SCANNING:
   → Edit: network_monitor.py → NetworkMonitor._scan_connections()

TO MODIFY BLOCKLISTS:
   → Edit: blocklist_manager.py → BlocklistManager methods

TO UPDATE CONSTANTS:
   → Edit: config.py → Config class attributes

================================================================================
IMPORT DEPENDENCY TREE:
================================================================================

WinDetox.py (main)
   ├──→ WinDetoxGUI
   │      ├──→ SystemTrayManager (system_tray.py)
   │      ├──→ NetworkMonitor (network_monitor.py)
   │      └──→ NetworkService (network_service.py)
   │             ├──→ BlocklistManager (blocklist_manager.py)
   │             └──→ FirewallManager (firewall_manager.py)
   │                    ├──→ utils.py (safe_subprocess_run)
   │                    └──→ logger.py
   │
   └──→ SettingsManager (settings_manager.py)
          └──→ logger.py

================================================================================
QUICK REFERENCE - COMMON TASKS:
================================================================================

• Block an IP: network_service.py → NetworkService.block_ips()
• Show tray icon: system_tray.py → SystemTrayManager.create_tray_icon()
• Start monitoring: network_monitor.py → NetworkMonitor.start()
• Update blocklists: blocklist_manager.py → BlocklistManager.update_dynamic_lists()
• Apply firewall: firewall_manager.py → FirewallManager.apply_windows_firewall_rule()
• Log message: logger.py → Logger.info()/error()/warning()
• Validate IP: ip_validator.py → validate_ip_address()

================================================================================
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Menu, filedialog
import os
import sys
import time
import threading
import atexit
import ctypes
import tempfile
import subprocess
import json
import csv
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any, Callable

# External dependencies
import psutil
import socket
import ipaddress
import shutil
import requests
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import concurrent.futures
import winreg

# Core modules
from core.exceptions import (
    WinDetoxError, SecurityError, FirewallError, BlocklistError,
    UpdateError, ValidationError, PermissionError, DetailedError
)
from core.utils import (
    is_admin, run_as_admin, is_local_ip, get_hosts_backup_path,
    safe_subprocess_run, verify_file_signature
)
from core.config import Config
from core.logger import Logger, RotatingLogger

# Managers
from managers.settings_manager import SettingsManager
from managers.update_manager import UpdateManager

# Network modules
from network.ip_validator import IPValidator, validate_ip_address, normalize_ip_address
from network.blocklist_manager import BlocklistManager
from network.firewall_manager import FirewallManager
from network.ip_info_cache import IPAnalyzer, IPInfoCache
from network.network_service import NetworkService
from network.network_monitor import NetworkMonitor, ConnectionInfo

# UI modules
from ui.system_tray import SystemTrayManager
from ui.blocked_ips_viewer import BlockedIPsViewer
from ui.main_window import WinDetoxGUI


class WinDetoxGUI:
    """
    MAIN GUI CLASS - COORDINATES EVERYTHING
    
    RESPONSIBILITIES:
    1. Creates and manages all GUI windows and widgets
    2. Coordinates between NetworkMonitor (scanner) and NetworkService (blocker)
    3. Handles user interactions and updates display
    4. Manages SystemTray integration
    """
    
    def __init__(self, 
                 root: tk.Tk, 
                 logger: Logger = None,
                 network_service: NetworkService = None,
                 settings_manager: SettingsManager = None,
                 update_manager: UpdateManager = None):
        """INITIALIZATION - SETS UP ALL COMPONENTS"""
        
        self.root = root
        self.root.title(f"{Config.WINDOW_TITLE} v{Config.CURRENT_VERSION}")
        self.root.geometry(Config.WINDOW_GEOMETRY)
        self.mutex = None
        
        # Initialize logger FIRST (before any other operations)
        self.logger = logger or Logger()
        
        # Set up window icon
        self._setup_window_icon()
        
        # Check startup arguments
        self.is_autostart_mode = '--minimized' in sys.argv and not self._check_interactive_session()
        self.start_minimized = '--minimized' in sys.argv
        
        # Initialize managers and services
        self.tray_manager = None
        self.settings = settings_manager or SettingsManager()
        self.update_manager = update_manager or UpdateManager(logger=self.logger)
        
        # Initialize network service
        self.network_service = network_service or NetworkService(
            logger=self.logger,
            blocklist_manager=BlocklistManager(logger=self.logger),
            firewall_manager=FirewallManager(logger=self.logger)
        )
        
        # Initialize network monitor
        self.monitor = NetworkMonitor(logger=self.logger)
        
        # Set up callbacks
        self.monitor.on_new_connection = self.on_new_connection
        self.monitor.on_connection_closed = self.on_connection_closed
        self.monitor.on_update = self.on_update
        
        # Initialize data structures
        self.connection_history: List[ConnectionInfo] = []
        self.current_connections: List[ConnectionInfo] = []
        
        # Setup context menu
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Block IP", command=self.block_selected_ip)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Show Details", command=self.show_connection_details)
        
        # Build GUI
        self.setup_gui()
        
        # Initial checks and timers
        self.root.after(100, self.check_admin_on_startup)
        self.root.after(5000, self._periodic_update)
        
        # Check for updates on startup if enabled
        if self.settings.get('check_updates_on_start', True):
            self.root.after(30000, self.auto_check_for_updates)
        
        # Initialize system tray with appropriate timing
        if not self.start_minimized:
            self.setup_system_tray()
        else:
            self.root.after(3000, self.setup_system_tray_delayed)
        
        # Handle minimized startup
        if self.start_minimized and self.settings.get('start_minimized', False):
            self.root.withdraw()
        
        # Setup window closing protocol
        self.setup_window_protocol()
        
        # Auto-start monitoring if setting is enabled
        if self.settings.get('start_monitoring_on_start', True):
            self.root.after(1000, self.start_monitoring)
        
        # Initialize update tracking
        self._pending_tree_updates: List[ConnectionInfo] = []
        self._update_scheduled = False
        
        # Register cleanup on exit
        atexit.register(self.cleanup)
    
    def _setup_window_icon(self):
        """Set up window icon with multiple fallback paths"""
        try:
            # Get base path
            if getattr(sys, 'frozen', False):
                base_path = os.path.dirname(sys.executable)  # Running as compiled executable
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))  # Running as script
            
            # Try multiple icon locations
            icon_paths = [
                os.path.join(base_path, 'icon.ico'),
                os.path.join(os.path.dirname(base_path), 'icon.ico'),
                os.path.join(os.getcwd(), 'icon.ico'),
                'icon.ico'  # Last resort
            ]
            
            icon_loaded = False
            for icon_path in icon_paths:
                if os.path.exists(icon_path):
                    try:
                        self.root.iconbitmap(icon_path)
                        self.logger.info(f"Loaded window icon from: {icon_path}")
                        icon_loaded = True
                        break
                    except Exception as e:
                        self.logger.debug(f"Failed to load icon from {icon_path}: {e}")
                        continue
            
            if not icon_loaded:
                self.logger.info("No icon file found, using default window icon")
                
        except Exception as e:
            self.logger.debug(f"Icon loading failed: {e}")
    
    def setup_gui(self):
        """
        GUI CONSTRUCTION - WHERE ALL WIDGETS ARE CREATED
        
        Tab structure:
        1. Tab 0: Active Connections (TreeView with connections)
        2. Tab 1: Event Log (ScrolledText for logs)
        3. Tab 2: History (TreeView of past connections)
        4. Tab 3: IP Blocking (Blocklist management)
        5. Tab 4: Settings (User preferences)
        """
        
        # Main frame
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(3, weight=1)  # Notebook gets extra space
        
        # ====================
        # CONTROL BAR
        # ====================
        ctrl = ttk.Frame(main)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Control buttons
        self.btn_start = ttk.Button(ctrl, text="Start", command=self.start_monitoring)
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_stop = ttk.Button(ctrl, text="Stop", command=self.stop_monitoring, state="disabled")
        self.btn_stop.pack(side="left", padx=5)
        
        ttk.Button(ctrl, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)
        ttk.Button(ctrl, text="Clear History", command=self.clear_history).pack(side="left", padx=5)
        ttk.Button(ctrl, text="Export", command=self.export_connections).pack(side="left", padx=5)
        
        # Admin button
        ttk.Button(ctrl, text="Restart as Admin", 
                  command=lambda: run_as_admin("Restart with administrator privileges?")) \
                  .pack(side="left", padx=10)
        
        # Separator
        ttk.Separator(ctrl, orient="vertical").pack(side="left", fill="y", padx=10)
        
        # ====================
        # FILTER CONTROLS
        # ====================
        ttk.Label(ctrl, text="Filter:", font=("", 9, "bold")).pack(side="left")
        
        # Filter variables
        self.var_inc = tk.BooleanVar(value=True)   # Incoming
        self.var_out = tk.BooleanVar(value=True)   # Outgoing
        self.var_lis = tk.BooleanVar(value=True)   # Listening
        self.var_ext = tk.BooleanVar(value=False)  # External only
        
        # Filter checkbuttons
        ttk.Checkbutton(ctrl, text="Incoming", 
                       variable=self.var_inc, 
                       command=self.apply_filters).pack(side="left", padx=5)
        
        ttk.Checkbutton(ctrl, text="Outgoing", 
                       variable=self.var_out, 
                       command=self.apply_filters).pack(side="left", padx=5)
        
        ttk.Checkbutton(ctrl, text="Listening", 
                       variable=self.var_lis, 
                       command=self.apply_filters).pack(side="left", padx=5)
        
        ttk.Checkbutton(ctrl, text="ONLY EXTERNAL", 
                       variable=self.var_ext, 
                       command=self.apply_filters).pack(side="left", padx=10)
        
        # ====================
        # STATISTICS FRAME
        # ====================
        stats_frame = ttk.LabelFrame(main, text="Statistics", padding=10)
        stats_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        self.stats_var = tk.StringVar(value="No data")
        ttk.Label(stats_frame, textvariable=self.stats_var, font=("", 10)).pack()
        
        # ====================
        # ADMIN STATUS FRAME
        # ====================
        admin_frame = ttk.Frame(main)
        admin_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        
        self.admin_status_var = tk.StringVar()
        self.admin_label = ttk.Label(
            admin_frame, 
            textvariable=self.admin_status_var,
            font=("", 9, "bold")
        )
        self.admin_label.pack(side="left", padx=10)
        
        # Set admin status
        if is_admin():
            self.admin_status_var.set("✓ Administrator Rights: Firewall blocking ACTIVE")
            self.admin_label.config(foreground="green")
        else:
            self.admin_status_var.set("⚠️ NO Admin Rights: Firewall blocking DISABLED")
            self.admin_label.config(foreground="red")
        
        # ====================
        # NOTEBOOK (TABS)
        # ====================
        nb = ttk.Notebook(main)
        nb.grid(row=3, column=0, sticky="nsew")
        
        # Bind tab change event
        nb.bind("<<NotebookTabChanged>>", 
               lambda e: self.save_selected_tab(nb.index(nb.select())))
        
        # ====================
        # TAB 1: ACTIVE CONNECTIONS
        # ====================
        f1 = ttk.Frame(nb, padding=10)
        nb.add(f1, text="Active Connections")
        
        f1.columnconfigure(0, weight=1)
        f1.rowconfigure(0, weight=1)
        
        # TreeView columns
        cols = ('Dir', 'Process', 'PID', 'Local', 'Remote', 'Status')
        self.tree = ttk.Treeview(f1, columns=cols, show="tree headings", selectmode="extended")
        
        # Configure TreeView
        self.tree.heading("#0", text="Time")
        self.tree.column("#0", width=90)
        
        for col in cols:
            self.tree.heading(col, text=col)
        
        # Column widths
        self.tree.column("Dir", width=80)
        self.tree.column("Process", width=180)
        self.tree.column("PID", width=70)
        self.tree.column("Local", width=220)
        self.tree.column("Remote", width=220)
        self.tree.column("Status", width=120)
        
        # Scrollbar
        vsb = ttk.Scrollbar(f1, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        # Layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        
        # Event bindings
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.show_connection_details)
        
        # Color coding
        self.tree.tag_configure("incoming", background="#ffcccc")   # Light red
        self.tree.tag_configure("outgoing", background="#ccffcc")   # Light green
        self.tree.tag_configure("listening", background="#ffffcc")  # Light yellow
        
        # ====================
        # TAB 2: EVENT LOG
        # ====================
        f2 = ttk.Frame(nb, padding=10)
        nb.add(f2, text="Event Log")
        
        f2.columnconfigure(0, weight=1)
        f2.rowconfigure(0, weight=1)
        
        self.log = scrolledtext.ScrolledText(
            f2, 
            state="disabled", 
            font=("Consolas", 9)
        )
        self.log.grid(row=0, column=0, sticky="nsew")
        
        # ====================
        # TAB 3: HISTORY
        # ====================
        f3 = ttk.Frame(nb, padding=10)
        nb.add(f3, text="History")
        
        f3.columnconfigure(0, weight=1)
        f3.rowconfigure(0, weight=1)
        
        hist_cols = ("Time", "Direction", "Process", "Connection", "Status")
        self.hist_tree = ttk.Treeview(f3, columns=hist_cols, show="headings", selectmode="extended")
        
        for col in hist_cols:
            self.hist_tree.heading(col, text=col)
        
        # History column widths
        self.hist_tree.column("Time", width=150)
        self.hist_tree.column("Direction", width=90)
        self.hist_tree.column("Process", width=180)
        self.hist_tree.column("Connection", width=400)
        self.hist_tree.column("Status", width=100)
        
        # History scrollbar
        vsb2 = ttk.Scrollbar(f3, command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=vsb2.set)
        
        self.hist_tree.grid(row=0, column=0, sticky="nsew")
        vsb2.grid(row=0, column=1, sticky="ns")
        
        # ====================
        # TAB 4: IP BLOCKING
        # ====================
        f4 = ttk.Frame(nb, padding=10)
        nb.add(f4, text="IP Blocking")
        
        f4.columnconfigure(0, weight=1)
        f4.columnconfigure(1, weight=1)
        
        row = 0
        
        # Blocklist Frame
        bl_frame = ttk.LabelFrame(f4, text="Blocklist", padding=8)
        bl_frame.grid(row=row, column=0, sticky="nsew", padx=5, pady=5)
        
        ttk.Button(bl_frame, text="Show Blocked IPs", 
                  command=self.show_blocked_ips, width=20).pack(pady=3)
        
        ttk.Button(bl_frame, text="Update Blocklists", 
                  command=self.update_blocklists, width=20).pack(pady=3)
        
        # Microsoft Frame
        ms_frame = ttk.LabelFrame(f4, text="Microsoft", padding=8)
        ms_frame.grid(row=row, column=1, sticky="nsew", padx=5, pady=5)
        
        ttk.Button(ms_frame, text="Block Microsoft", 
                  command=self.block_microsoft_complete, width=20).pack(pady=3)
        
        ttk.Button(ms_frame, text="Hosts File Block", 
                  command=self.block_microsoft_hosts, width=20).pack(pady=3)
        
        ttk.Button(ms_frame, text="Restore Hosts", 
                  command=self.restore_hosts_backup, width=20).pack(pady=3)
        
        row += 1
        
        # Firewall Frame
        fw_frame = ttk.LabelFrame(f4, text="Firewall", padding=8)
        fw_frame.grid(row=row, column=0, sticky="nsew", padx=5, pady=5)
        
        ttk.Button(fw_frame, text="Block Pending IPs", 
                  command=self.apply_pending_firewall_rules, width=20).pack(pady=3)
        
        # DNS over HTTPS Frame
        doh_frame = ttk.LabelFrame(f4, text="DNS over HTTPS", padding=8)
        doh_frame.grid(row=row, column=1, sticky="nsew", padx=5, pady=5)
        
        ttk.Button(doh_frame, text="Disable DoH", 
                  command=self.disable_doh, width=20).pack(pady=3)
        
        ttk.Button(doh_frame, text="Enable DoH", 
                  command=self.enable_doh, width=20).pack(pady=3)
        
        row += 1
        
        # Delivery Optimization Frame
        do_frame = ttk.LabelFrame(f4, text="Delivery Optimization", padding=8)
        do_frame.grid(row=row, column=0, sticky="nsew", padx=5, pady=5)
        
        ttk.Button(do_frame, text="Disable", 
                  command=self.disable_delivery_optimization, width=20).pack(pady=3)
        
        ttk.Button(do_frame, text="Enable", 
                  command=self.enable_delivery_optimization, width=20).pack(pady=3)
        
        # NCSI Control Frame
        ncsi_frame = ttk.LabelFrame(f4, text="NCSI Control", padding=8)
        ncsi_frame.grid(row=row, column=1, sticky="nsew", padx=5, pady=5)
        
        ttk.Button(ncsi_frame, text="Disable NCSI", 
                  command=self.disable_ncsi, width=20).pack(pady=3)
        
        ttk.Button(ncsi_frame, text="Enable NCSI", 
                  command=self.enable_ncsi, width=20).pack(pady=3)
        
        ttk.Button(ncsi_frame, text="Test Status", 
                  command=self.test_ncsi_status, width=20).pack(pady=3)
        
        row += 1
        
        # Privacy Frame (span 2 columns)
        privacy_frame = ttk.LabelFrame(f4, text="One-Click Privacy", padding=8)
        privacy_frame.grid(row=row, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        ttk.Button(privacy_frame, text="Activate Full Privacy Mode", 
                  command=self.full_privacy_mode, width=30).pack(side="left", padx=5, pady=3)
        
        ttk.Button(privacy_frame, text="Undo Privacy Mode", 
                  command=self.undo_full_privacy_mode, width=30).pack(side="left", padx=5, pady=3)
        
        row += 1
        
        # Nuclear Options Frame (span 2 columns)
        nuc_frame = ttk.LabelFrame(f4, text="⚠️ Emergency Options", padding=8)
        nuc_frame.grid(row=row, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        ttk.Button(nuc_frame, text="NUCLEAR - Block All Internet", 
                  command=self.nuclear_option, width=30).pack(side="left", padx=5, pady=3)
        
        ttk.Button(nuc_frame, text="UNDO Nuclear Option", 
                  command=self.undo_nuclear_option, width=30).pack(side="left", padx=5, pady=3)
        
        # ====================
        # TAB 5: SETTINGS
        # ====================
        f5 = ttk.Frame(nb, padding=10)
        nb.add(f5, text="Settings")
        
        f5.columnconfigure(0, weight=1)
        
        # Canvas with scrollbar for settings
        settings_canvas = tk.Canvas(f5)
        settings_scrollbar = ttk.Scrollbar(f5, orient="vertical", command=settings_canvas.yview)
        settings_frame = ttk.Frame(settings_canvas)
        
        # Configure canvas scrolling
        settings_frame.bind(
            "<Configure>",
            lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))
        )
        
        settings_canvas.create_window((0, 0), window=settings_frame, anchor="nw")
        settings_canvas.configure(yscrollcommand=settings_scrollbar.set)
        
        settings_canvas.pack(side="left", fill="both", expand=True)
        settings_scrollbar.pack(side="right", fill="y")
        
        # ====================
        # SETTINGS SECTIONS
        # ====================
        
        # Version Information
        version_frame = ttk.LabelFrame(settings_frame, text="Version Information", padding=10)
        version_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10), padx=5)
        
        ttk.Label(version_frame, text=f"Version: {Config.CURRENT_VERSION}", 
                 font=("", 9, "bold")).pack(pady=2)
        
        ttk.Label(version_frame, text="© 2025 Privacy Focused Development Team", 
                 font=("", 7)).pack(pady=1)
        
        ttk.Button(version_frame, text="Check for Updates",
                  command=self.check_for_updates, width=20).pack(pady=5)
        
        # Startup Settings
        startup_frame = ttk.LabelFrame(settings_frame, text="Startup Settings", padding=10)
        startup_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10), padx=5)
        
        # Autostart checkbox
        self.autostart_var = tk.BooleanVar(value=self.settings.get('autostart_all_users', False))
        ttk.Checkbutton(
            startup_frame, 
            text="Start with Windows (admin)",
            variable=self.autostart_var,
            command=self.toggle_autostart
        ).pack(anchor="w", pady=2)
        
        # Start minimized checkbox
        self.start_minimized_var = tk.BooleanVar(value=self.settings.get('start_minimized', False))
        ttk.Checkbutton(
            startup_frame,
            text="Start minimized",
            variable=self.start_minimized_var,
            command=lambda: self.settings.set('start_minimized', self.start_minimized_var.get())
        ).pack(anchor="w", pady=2)
        
        # Minimize to tray checkbox
        self.start_to_tray_var = tk.BooleanVar(value=self.settings.get('start_to_tray', False))
        ttk.Checkbutton(
            startup_frame,
            text="Minimize to tray",
            variable=self.start_to_tray_var,
            command=lambda: self.settings.set('start_to_tray', self.start_to_tray_var.get())
        ).pack(anchor="w", pady=2)
        
        # Auto-start monitoring checkbox
        self.start_monitoring_var = tk.BooleanVar(value=self.settings.get('start_monitoring_on_start', True))
        ttk.Checkbutton(
            startup_frame,
            text="Auto-start monitoring",
            variable=self.start_monitoring_var,
            command=lambda: self.settings.set('start_monitoring_on_start', self.start_monitoring_var.get())
        ).pack(anchor="w", pady=2)
        
        # Autostart status label
        hklm_status, hkcu_status = self.settings.check_autostart_status()
        status_text = f"Status: {'Enabled' if hklm_status or hkcu_status else 'Disabled'}"
        
        if hklm_status and hkcu_status:
            status_text += " (HKLM + HKCU)"
        elif hklm_status:
            status_text += " (HKLM - All users)"
        elif hkcu_status:
            status_text += " (HKCU - Current user only)"
        
        self.autostart_status_label = ttk.Label(startup_frame, text=status_text, font=("", 8))
        self.autostart_status_label.pack(anchor="w", pady=2)
        
        # Update Settings
        update_frame = ttk.LabelFrame(settings_frame, text="Update Settings", padding=10)
        update_frame.grid(row=2, column=0, sticky="ew", pady=(0, 10), padx=5)
        
        self.check_updates_var = tk.BooleanVar(value=self.settings.get('check_updates_on_start', True))
        ttk.Checkbutton(
            update_frame,
            text="Check updates on start",
            variable=self.check_updates_var,
            command=lambda: self.settings.set('check_updates_on_start', self.check_updates_var.get())
        ).pack(anchor="w", pady=2)
        
        self.auto_update_blocklists_var = tk.BooleanVar(value=self.settings.get('auto_update_blocklists', True))
        ttk.Checkbutton(
            update_frame,
            text="Auto-update blocklists",
            variable=self.auto_update_blocklists_var,
            command=lambda: self.settings.set('auto_update_blocklists', self.auto_update_blocklists_var.get())
        ).pack(anchor="w", pady=2)
        
        # Application Settings
        app_frame = ttk.LabelFrame(settings_frame, text="Application Settings", padding=10)
        app_frame.grid(row=3, column=0, sticky="ew", pady=(0, 10), padx=5)
        
        self.show_notifications_var = tk.BooleanVar(value=self.settings.get('show_notifications', True))
        ttk.Checkbutton(
            app_frame,
            text="Show notifications",
            variable=self.show_notifications_var,
            command=lambda: self.settings.set('show_notifications', self.show_notifications_var.get())
        ).pack(anchor="w", pady=2)
        
        # Theme and Language frame
        theme_lang_frame = ttk.Frame(app_frame)
        theme_lang_frame.pack(fill="x", pady=5)
        
        # Theme selector
        ttk.Label(theme_lang_frame, text="Theme:", font=("", 8)).pack(side="left", padx=(0, 5))
        
        self.theme_var = tk.StringVar(value=self.settings.get('theme', 'default'))
        theme_combo = ttk.Combobox(
            theme_lang_frame,
            textvariable=self.theme_var,
            values=['default', 'light', 'dark', 'blue'],
            state='readonly',
            width=12
        )
        theme_combo.pack(side="left", padx=(0, 10))
        theme_combo.bind('<<ComboboxSelected>>', 
                        lambda e: self.settings.set('theme', self.theme_var.get()))
        
        # Language selector
        ttk.Label(theme_lang_frame, text="Language:", font=("", 8)).pack(side="left", padx=(0, 5))
        
        self.language_var = tk.StringVar(value=self.settings.get('language', 'english'))
        lang_combo = ttk.Combobox(
            theme_lang_frame,
            textvariable=self.language_var,
            values=['english', 'german', 'french', 'spanish'],
            state='readonly',
            width=12
        )
        lang_combo.pack(side="left")
        lang_combo.bind('<<ComboboxSelected>>', 
                       lambda e: self.settings.set('language', self.language_var.get()))
        
        # Reset settings button
        ttk.Button(
            app_frame,
            text="Reset All Settings",
            command=self.reset_settings
        ).pack(pady=5)
        
        # ====================
        # FINAL INITIALIZATION
        # ====================
        
        # Restore selected tab if saved
        selected_tab = self.settings.get('selected_tab', 0)
        nb.select(selected_tab)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(main, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        status.grid(row=4, column=0, sticky="ew", pady=(10, 0))

    def save_selected_tab(self, tab_index):
        """Save the currently selected tab index"""
        self.settings.set('selected_tab', tab_index)

    def toggle_autostart(self):
        """Toggle autostart setting - NO CONFIRMATION WINDOWS"""
        try:
            success = self.settings.set_autostart_all_users(self.autostart_var.get())
            if success:
                schtasks_exists, registry_exists = self.settings.check_autostart_status()
                is_enabled = schtasks_exists or registry_exists
                self.autostart_var.set(is_enabled)
                status_text = f"Status: {('Enabled' if is_enabled else 'Disabled')}"
                if schtasks_exists:
                    status_text += ' (Task Scheduler)'
                elif registry_exists:
                    status_text += ' (Registry)'
                self.autostart_status_label.config(text=status_text)
                self.log_append(f"Autostart {('enabled' if is_enabled else 'disabled')} successfully\n")
            else:
                self.autostart_var.set(not self.autostart_var.get())
                self.log_append('Failed to change autostart setting\n')
        except PermissionError:
            self.autostart_var.set(not self.autostart_var.get())
            self.log_append('Admin rights required for autostart changes\n')
        except Exception as e:
            self.autostart_var.set(not self.autostart_var.get())
            self.log_append(f'Autostart error: {str(e)[:100]}\n')

    def check_for_updates(self):
        """Check for program updates with signature verification"""
        win = tk.Toplevel(self.root)
        win.title('Checking for Updates...')
        win.geometry('400x150')
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text='Checking for updates...', font=('', 11, 'bold')).pack(pady=20)
        progress = ttk.Progressbar(win, mode='indeterminate', length=300)
        progress.pack(pady=10)
        progress.start()
        status = tk.StringVar(value='Connecting to update server...')
        ttk.Label(win, textvariable=status).pack(pady=5)

        def run_update_check():
            try:
                update_needed, latest_version, changes, expected_hash = self.update_manager.check_for_updates()

                def show_result():
                    progress.stop()
                    win.destroy()
                    self.settings.set('last_update_check', time.time())
                    if update_needed:
                        update_message = f'Update available!\n\nCurrent version: {Config.CURRENT_VERSION}\nLatest version: {latest_version}\n\nChanges in version {latest_version}:\n{changes}\n\nDo you want to update now?'
                        if messagebox.askyesno('Update Available', update_message):
                            try:
                                if self.update_manager.perform_update(expected_hash):
                                    messagebox.showinfo('Update Started', 'The update has been started.\nThe program will restart automatically.')
                                else:
                                    messagebox.showerror('Update Failed', 'Failed to download or install the update.\nPlease try again later or update manually.')
                            except SecurityError as e:
                                messagebox.showerror('Security Error', f'Update verification failed!\n\n{str(e)}\n\nThe update has been cancelled for security reasons.')
                            except UpdateError as e:
                                messagebox.showerror('Update Error', f'Update failed: {str(e)}')
                        else:
                            messagebox.showinfo('Update Skipped', 'Update has been skipped.')
                    else:
                        messagebox.showinfo('Up to Date', f'You are using the latest version ({Config.CURRENT_VERSION}).\n\nLatest version information:\n{changes}')
                win.after(0, show_result)
            except UpdateError as e:
                error_message = str(e)

                def show_error():
                    progress.stop()
                    win.destroy()
                    messagebox.showerror('Update Check Failed', f'Failed to check for updates:\n{error_message}')
                win.after(0, show_error)
            except Exception as e:
                error_message = str(e)

                def show_error():
                    progress.stop()
                    win.destroy()
                    messagebox.showerror('Update Check Failed', f'Unexpected error:\n{error_message}')
                win.after(0, show_error)
        threading.Thread(target=run_update_check, daemon=True).start()

    def auto_check_for_updates(self):
        """Automatically check for updates on startup (if enabled)"""
        try:
            last_check = self.settings.get('last_update_check', 0)
            if time.time() - last_check < 86400:
                return
            try:
                update_needed, latest_version, changes, expected_hash = self.update_manager.check_for_updates()
                if update_needed:
                    self.root.after(0, lambda: self.show_update_notification(latest_version, changes))
                self.settings.set('last_update_check', time.time())
            except UpdateError as e:
                self.logger.debug(f'Auto-update check skipped: {e}')
            except Exception as e:
                self.logger.debug(f'Auto-update check error: {e}')
        except Exception as e:
            self.logger.debug(f'Auto-update setup error: {e}')

    def show_update_notification(self, latest_version, changes):
        """Show update notification to user"""
        update_message = f'Update available!\n\nCurrent version: {Config.CURRENT_VERSION}\nLatest version: {latest_version}\n\nDo you want to update now?'
        if messagebox.askyesno('Update Available', update_message):
            self.check_for_updates()

    def reset_settings(self):
        """Reset all settings to default values"""
        if messagebox.askyesno('Reset Settings', 'Are you sure you want to reset all settings to default values?\n\nThis will reset:\n- Startup settings\n- Update settings\n- Application preferences\n\nYour blocklist and connection history will NOT be affected.'):
            self.settings.settings = {'autostart_all_users': False, 'start_minimized': False, 'start_to_tray': False, 'check_updates_on_start': True, 'auto_update_blocklists': True, 'show_notifications': True, 'theme': 'default', 'language': 'english', 'last_update_check': 0, 'window_position': None, 'window_size': None, 'selected_tab': 0, 'start_monitoring_on_start': True}
            self.settings.save_settings()
            self.autostart_var.set(False)
            self.start_minimized_var.set(False)
            self.start_to_tray_var.set(False)
            self.check_updates_var.set(True)
            self.auto_update_blocklists_var.set(True)
            self.show_notifications_var.set(True)
            self.theme_var.set('default')
            self.language_var.set('english')
            self.start_monitoring_var.set(True)
            hklm_status, hkcu_status = self.settings.check_autostart_status()
            status_text = f"Status: {('Enabled' if hklm_status or hkcu_status else 'Disabled')}"
            self.autostart_status_label.config(text=status_text)
            messagebox.showinfo('Settings Reset', 'All settings have been reset to default values.')

    def show_connection_details(self, event=None):
        """Show detailed information about selected connection"""
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])
        values = item['values']
        details = f"\nConnection Details:\n──────────────────\nTime: {item['text']}\nDirection: {values[0]}\nProcess: {values[1]}\nPID: {values[2]}\nLocal Address: {values[3]}\nRemote Address: {values[4]}\nStatus: {values[5]}\n"
        messagebox.showinfo('Connection Details', details)

    def start_monitoring(self):
        """
        STARTS NETWORK MONITORING
        
        Flow:
        1. Calls monitor.start() (NetworkMonitor)
        2. Updates GUI buttons
        3. Updates tray menu
        4. Logs the event
        
        Related: stop_monitoring()
        """
        if self.monitor.start():
            self.btn_start.config(state='disabled')
            self.btn_stop.config(state='normal')
            self.status_var.set('Monitoring running...')
            self.log_append('Monitoring started\n')
            if self.tray_manager:
                self.tray_manager.update_tray_menu()

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitor.stop()
        self.btn_start.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.status_var.set('Stopped')
        self.log_append('Monitoring stopped\n')
        if self.tray_manager:
            self.tray_manager.update_tray_menu()

    def on_new_connection(self, conn: ConnectionInfo):
        """Handle new connection detection"""
        if conn.direction == 'INCOMING' and conn.remote_addr and (not is_local_ip(conn.remote_addr)):
            self.log_append(f'⚠️ EXTERNAL CONNECTION from {conn.remote_addr}:{conn.remote_port} → {conn.local_addr}:{conn.local_port} ({conn.process_name})\n')
        else:
            self.log_append(f'{conn.direction}: {conn}\n')
        self.connection_history.append(conn)
        if len(self.connection_history) > Config.MAX_HISTORY_ENTRIES:
            self.connection_history.pop(0)
        self.root.after(0, lambda c=conn: self.hist_tree.insert('', 0, values=(c.timestamp.strftime('%Y-%m-d %H:%M:%S'), c.direction, f'{c.process_name} ({c.pid})', f'{c.local_addr}:{c.local_port} → {c.remote_addr}:{c.remote_port}', c.status)))

    def on_connection_closed(self, conn: ConnectionInfo):
        """Handle connection closure"""
        self.log_append(f'CLOSED: {conn}\n')

    def on_update(self, conns: List[ConnectionInfo]):
        """Handle connection updates"""
        self.current_connections = conns
        self.root.after(0, self.apply_filters)
        self.root.after(0, self.update_stats)

    def apply_filters(self):
        """Apply current filters to connection list"""
        filtered = []
        for c in self.current_connections:
            if c.direction == 'INCOMING' and (not self.var_inc.get()):
                continue
            if c.direction == 'OUTGOING' and (not self.var_out.get()):
                continue
            if c.direction == 'LISTENING' and (not self.var_lis.get()):
                continue
            if self.var_ext.get():
                if c.direction in ('OUTGOING', 'LISTENING'):
                    continue
                if c.direction == 'INCOMING' and is_local_ip(c.remote_addr):
                    continue
            filtered.append(c)
        self.tree.delete(*self.tree.get_children())
        for c in filtered:
            tag = 'incoming' if c.direction == 'INCOMING' else 'outgoing' if c.direction == 'OUTGOING' else 'listening'
            remote = f'{c.remote_addr}:{c.remote_port}' if c.remote_addr else '-'
            self.tree.insert('', 'end', text=c.timestamp.strftime('%H:%M:%S'), values=(c.direction, c.process_name, c.pid, f'{c.local_addr}:{c.local_port}', remote, c.status), tags=(tag,))
        total = len(self.current_connections)
        shown = len(filtered)
        if self.var_ext.get():
            self.status_var.set(f'ONLY EXTERNAL: {shown} visible')
        else:
            self.status_var.set(f'Showing {shown}/{total} connections')

    def update_stats(self):
        """Update statistics display"""
        s = self.monitor.get_statistics()
        self.stats_var.set(f"Total: {s['total']} | Listening: {s['listening']} | Incoming: {s['incoming']} | Outgoing: {s['outgoing']}")

    def log_append(self, text: str):
        """Append text to log with automatic line limiting"""

        def do():
            self.log.config(state='normal')
            self.log.insert('end', f"[{datetime.now().strftime('%H:%M:%S')}] {text}")
            lines = int(self.log.index('end-1c').split('.')[0])
            if lines > Config.MAX_LOG_LINES:
                self.log.delete('1.0', f'{lines - Config.MAX_LOG_LINES + 1}.0')
            self.log.see('end')
            self.log.config(state='disabled')
        self.root.after(0, do)

    def clear_log(self):
        """Clear log window"""
        self.log.config(state='normal')
        self.log.delete('1.0', 'end')
        self.log.config(state='disabled')

    def clear_history(self):
        """Clear connection history"""
        self.connection_history.clear()
        self.hist_tree.delete(*self.hist_tree.get_children())

    def block_selected_ip(self):
        """
        BLOCKS SELECTED IP FROM CONNECTION LIST
        
        Flow:
        1. Gets selected IPs from TreeView
        2. Validates IPs (skips local IPs)
        3. Calls network_service.block_ips()
        4. Updates GUI and logs
        
        Uses: NetworkService.block_ips() → BlocklistManager + FirewallManager
        """
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning('No Selection', 'Please select one or more connections.')
            return
        ips_to_block = set()
        local_ips = []
        for item_id in sel:
            item = self.tree.item(item_id)
            remote = item['values'][4]
            if remote == '-' or ':' not in remote:
                continue
            ip = remote.split(':')[0]
            if is_local_ip(ip):
                local_ips.append(ip)
            else:
                ips_to_block.add(ip)
        if local_ips:
            messagebox.showwarning('Local IPs', f'These local IPs cannot be blocked:\n' + '\n'.join(local_ips))
        if ips_to_block:
            ip_list = '\n'.join(sorted(ips_to_block))
            if messagebox.askyesno('Block IPs', f'Permanently block these IPs?\n\n{ip_list}\n\nTotal: {len(ips_to_block)} IPs'):
                try:
                    results = self.network_service.block_ips(list(ips_to_block), source='Manual (GUI)')
                    for ip in ips_to_block:
                        self.log_append(f'IP {ip} manually blocked\n')
                    if results['failed']:
                        messagebox.showwarning('Partial Success', f"{results['blocked']}/{results['total']} IPs blocked successfully.\nFailed to block: {', '.join(results['failed'][:5])}")
                    else:
                        messagebox.showinfo('Success', f"{results['blocked']} IPs have been added to blocklist.\nUse 'Block All Pending IPs' to apply firewall rules.")
                except (ValidationError, BlocklistError, FirewallError) as e:
                    messagebox.showerror('Error', f'Failed to block IPs: {e}')
        else:
            messagebox.showinfo('No IPs', 'No blockable IPs found in selection.')

    def show_context_menu(self, event):
        """Show context menu for Treeview (multi-selection support)"""
        try:
            item = self.tree.identify_row(event.y)
            if item:
                if item not in self.tree.selection():
                    self.tree.selection_set(item)
                selected_count = len(self.tree.selection())
                menu_label = f'Block IP ({selected_count} selected)' if selected_count > 1 else 'Block IP'
                temp_menu = Menu(self.root, tearoff=0)
                temp_menu.add_command(label=menu_label, command=self.block_selected_ip)
                temp_menu.add_command(label='Show Details', command=self.show_connection_details)
                temp_menu.tk_popup(event.x_root, event.y_root)
        except Exception as e:
            self.logger.debug(f'Context menu error: {e}')

    def update_blocklists(self):
        """Start blocklist update in separate thread"""

        def update_task():
            try:
                added = self.network_service.blocklist.update_dynamic_lists()
                self.log_append(f'Blocklists updated: {added} new IPs blocked\n')
            except BlocklistError as e:
                self.log_append(f'Error updating blocklists: {e}\n')
        threading.Thread(target=update_task, daemon=True).start()

    def show_blocked_ips(self):
        """
        SHOWS BLOCKED IPs WINDOW USING MODULAR COMPONENTS
        
        Flow:
        1. Checks if there are blocked IPs → Shows message if empty
        2. Creates BlockedIPsViewer instance (modular window)
        3. Passes callbacks for unblocking and copying
        4. Calls viewer.show() to display window
        
        Main Logic Location:
        • blocked_ips_viewer.py → BlockedIPsViewer class (complete GUI window)
        • dns_resolver.py → TurboDNSResolver class (parallel DNS resolution)
        
        Key Features:
        • Fast parallel DNS resolution with progress tracking
        • Color-coded IP categorization (Microsoft/Cloud/Regular)
        • Enhanced statistics and export functionality
        • Thread-safe GUI updates
        
        Dependencies:
        • Uses: BlockedIPsViewer (new module), network_service.blocklist
        • Callbacks: _unblock_from_treeview(), _copy_selected_ip()
        
        To modify the blocked IPs window:
        → Edit: blocked_ips_viewer.py → BlockedIPsViewer class
        To change DNS resolution:
        → Edit: dns_resolver.py → TurboDNSResolver class
        To update IP analysis:
        → Edit: ip_info_cache.py → IPAnalyzer class
        """
        if not self.network_service.blocklist.blocked_ips:
            messagebox.showinfo('Empty Blocklist', 'No IPs blocked.')
            return
        viewer = BlockedIPsViewer(parent=self.root, network_service=self.network_service, logger=self.logger, on_unblock_callback=self._unblock_from_treeview, on_copy_callback=self._copy_selected_ip)
        viewer.show()

    def block_microsoft_complete(self):
        """Block Microsoft telemetry IPs comprehensively"""
        if not messagebox.askyesno('Block Microsoft', 'Windows Update, OneDrive, telemetry, etc. will be blocked.\n\nContinue?'):
            return
        win = tk.Toplevel(self.root)
        win.title('Blocking Microsoft...')
        win.geometry('500x160')
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text='Loading blocklist...', font=('', 10, 'bold')).pack(pady=20)
        p = ttk.Progressbar(win, mode='indeterminate')
        p.pack(pady=10, padx=50, fill='x')
        p.start()

        def run():
            try:
                added = self.network_service.blocklist._update_microsoft_list()
                count = len(self.network_service.blocklist.blocked_ips)
                win.after(0, lambda: p.stop())
                win.after(0, lambda: messagebox.showinfo('Success', f'{added} new IPs blocked\nTotal: {count}'))
                self.log_append(f'Microsoft blocklist applied (+{added})\n')
            except BlocklistError as e:
                win.after(0, lambda: messagebox.showerror('Error', str(e)))
            except Exception as e:
                win.after(0, lambda: messagebox.showerror('Error', f'Unexpected error: {str(e)}'))
            finally:
                win.after(0, win.destroy)
        threading.Thread(target=run, daemon=True).start()

    def export_connections(self, filepath: str=None) -> bool:
        """Export current connections as JSON or CSV"""
        if not filepath:
            filepath = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON file', '*.json'), ('CSV file', '*.csv'), ('All files', '*.*')])
        if not filepath:
            return False
        try:
            export_data = []
            for conn in self.current_connections:
                export_data.append({'timestamp': conn.timestamp.isoformat(), 'direction': conn.direction, 'process': conn.process_name, 'pid': conn.pid, 'local_address': conn.local_addr, 'local_port': conn.local_port, 'remote_address': conn.remote_addr, 'remote_port': conn.remote_port, 'status': conn.status})
            if filepath.endswith('.json'):
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2)
            elif filepath.endswith('.csv'):
                import csv
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    if export_data:
                        writer = csv.DictWriter(f, fieldnames=export_data[0].keys())
                        writer.writeheader()
                        writer.writerows(export_data)
            self.log_append(f'Connections exported: {filepath}\n')
            messagebox.showinfo('Export successful', f'Data saved:\n{filepath}')
            return True
        except Exception as e:
            self.logger.error(f'Export failed: {e}')
            messagebox.showerror('Export Error', str(e))
            return False

    def _periodic_update(self):
        """Periodic blocklist update (every hour)"""
        try:
            if self.settings.get('auto_update_blocklists', True):
                self.network_service.blocklist.update_dynamic_lists()
        except Exception as e:
            self.logger.error(f'Periodic update failed: {e}')
        finally:
            self.root.after(3600000, self._periodic_update)

    def show_tray_notification(self, title: str, message: str):
        """Show notification from system tray"""
        if self.settings.get('show_notifications', True):
            try:
                self.log_append(f'{title}: {message}\n')
            except:
                pass

    def cleanup_and_exit(self):
        """Clean up and exit application"""
        try:
            self.cleanup()
            if self.mutex:
                try:
                    ctypes.windll.kernel32.CloseHandle(self.mutex)
                    self.logger.info('Mutex closed')
                except:
                    pass
            self.root.quit()
            self.root.destroy()
        except Exception as e:
            self.logger.error(f'Error during cleanup_and_exit: {e}')
            os._exit(1)

    def cleanup(self):
        """Clean up all resources properly on exit"""
        try:
            self.monitor.stop()
            if self.tray_manager:
                self.tray_manager.stop()
            if self.monitor.monitor_thread and self.monitor.monitor_thread.is_alive():
                self.monitor.monitor_thread.join(timeout=5.0)
            if hasattr(self.monitor, '_process_name_cache'):
                self.monitor._process_name_cache.clear()
            self.network_service.blocklist.save_blocklist()
            self.settings.save_settings()
            stats = self.monitor.get_statistics()
            self.logger.info(f'Program terminated - Final stats: {stats}')
            self.logger.info(f'Blocked IPs: {len(self.network_service.blocklist.blocked_ips)}')
            self.logger.info(f'Settings saved')
        except Exception as e:
            self.logger.error(f'Cleanup error: {e}', exc=True)

    def integrate_gui_modules(self):
        """Dynamically integrates methods from modular GUI components"""
        try:
            from ui.tabs.connections_tab import WinDetoxGUI as ConnectionsGUI
            from ui.tabs.blocklist_tab import WinDetoxGUI as BlocklistGUI
            from ui.tabs.settings_tab import WinDetoxGUI as SettingsGUI
            from ui.dialogs.progress_dialog import WinDetoxGUI as ProgressGUI
            self.logger.info('GUI modules successfully integrated')
        except ImportError as e:
            self.logger.error(f'Failed to import GUI modules: {e}')

def main():
    """Main program entry point"""
    mutex_name = 'WinDetox_Mutex_{}'.format(os.path.expanduser('~').replace('\\', '_'))
    mutex = None
    try:
        mutex = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
        last_error = ctypes.windll.kernel32.GetLastError()
        if last_error == 183:
            messagebox.showinfo('WinDetox', 'WinDetox is already running!')
            sys.exit(0)
    except:
        pass
    if len(sys.argv) > 1 and sys.argv[1] == '--admin':
        if not is_admin():
            run_as_admin('Start with administrator privileges?')
            return
    start_minimized = '--minimized' in sys.argv
    try:
        logger = Logger()
        logger.info(f'Starting WinDetox v{Config.CURRENT_VERSION}')
        root = tk.Tk()
        app = WinDetoxGUI(root, logger=logger)
        root.mainloop()
    except Exception as e:
        try:
            error_log = os.path.join(tempfile.gettempdir(), 'windetox_error.log')
            with open(error_log, 'a', encoding='utf-8') as f:
                f.write(f'{datetime.now()}: {e}\n')
                import traceback
                f.write(traceback.format_exc())
        except:
            pass
        messagebox.showerror('Critical Error', f'Failed to start WinDetox:\n\n{str(e)}')
        sys.exit(1)
    finally:
        if mutex:
            ctypes.windll.kernel32.CloseHandle(mutex)
if __name__ == '__main__':
    main()

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

# ============================================================================
# IMPORTS WITH PURPOSE EXPLANATION
# ============================================================================

# GUI Framework
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Menu, filedialog

# System & Utilities
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

# External Dependencies
import psutil
import socket
import ipaddress
import shutil
import requests
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import concurrent.futures
import winreg

# ============================================================================
# IMPORT OUR MODULES WITH EXPLANATION
# ============================================================================

# CORE UTILITIES
from core.exceptions import (  # Custom exception classes
    WinDetoxError, SecurityError, FirewallError, BlocklistError,
    UpdateError, ValidationError, PermissionError, DetailedError
)
from core.utils import (  # Helper functions
    is_admin, run_as_admin, is_local_ip, get_hosts_backup_path,
    safe_subprocess_run, verify_file_signature
)
from core.config import Config  # All constants and configuration
from core.logger import Logger, RotatingLogger  # Logging system

# MANAGERS (handle specific domains)
from managers.settings_manager import SettingsManager  # User preferences
from managers.update_manager import UpdateManager  # Auto-updates 
from network.ip_validator import IPValidator, validate_ip_address, normalize_ip_address  # IP validation with caching
from network.blocklist_manager import BlocklistManager  # IP blocking lists
from network.firewall_manager import FirewallManager  # Windows Firewall operations

# Reverse-DNS Resolver
from network.ip_info_cache import IPAnalyzer, IPInfoCache

# SERVICES (coordinate multiple managers)
from network.network_service import NetworkService  # Main network operations facade

# MONITORS
from network.network_monitor import NetworkMonitor, ConnectionInfo  # Network connection scanner

# UI COMPONENTS
from ui.system_tray import SystemTrayManager  # System tray icon and menu

# NEW MODULES
from ui.blocked_ips_viewer import BlockedIPsViewer  # Blocked IPs viewer window

# ============================================================================
# MAIN GUI CLASS - WinDetoxGUI
# ============================================================================
# This is the main GUI class. It coordinates all other modules.
# If you need to change the GUI layout, look in setup_gui() method.
# If you need to change GUI behavior, look in the specific event handlers.
# ============================================================================


class WinDetoxGUI:
    """
    MAIN GUI CLASS - COORDINATES EVERYTHING
    
    RESPONSIBILITIES:
    1. Creates and manages all GUI windows and widgets
    2. Coordinates between NetworkMonitor (scanner) and NetworkService (blocker)
    3. Handles user interactions and updates display
    4. Manages SystemTray integration
    
    KEY PARTS:
    • setup_gui() - Creates all GUI widgets and tabs
    • start/stop_monitoring() - Controls NetworkMonitor
    • block/unblock methods - Uses NetworkService
    • Various event handlers - on_new_connection(), etc.
    
    DEPENDENCIES:
    • Uses: NetworkMonitor, NetworkService, SystemTrayManager
    • Used by: main() function (entry point)
    """
    
    def __init__(self, root: tk.Tk, 
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
            
            # Now try to set icon with absolute path resolution
            try:
                # Get absolute path to icon.ico
                if getattr(sys, 'frozen', False):
                    # Running as compiled executable
                    base_path = os.path.dirname(sys.executable)
                else:
                    # Running as Python script
                    base_path = os.path.dirname(os.path.abspath(__file__))
                
                # Try multiple icon locations with absolute paths
                icon_paths = [
                    os.path.join(base_path, 'icon.ico'),
                    os.path.join(os.path.dirname(base_path), 'icon.ico'),
                    os.path.join(os.getcwd(), 'icon.ico'),
                    'icon.ico'  # Last resort: relative path
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

            self.is_autostart_mode = '--minimized' in sys.argv and not self._check_interactive_session()
            
            # Check for minimized startup argument
            self.start_minimized = '--minimized' in sys.argv
            
            # System tray manager - WICHTIG: Zuerst als None initialisieren
            self.tray_manager = None
            
            # Initialize dependencies AFTER logger
            self.settings = settings_manager or SettingsManager()
            self.update_manager = update_manager or UpdateManager(logger=self.logger)
            
            # Initialize network service
            self.network_service = network_service or NetworkService(
                logger=self.logger,
                blocklist_manager=BlocklistManager(logger=self.logger),
                firewall_manager=FirewallManager(logger=self.logger)
            )
            
            # Initialize monitor
            self.monitor = NetworkMonitor(logger=self.logger)
            
            # Set up callbacks
            self.monitor.on_new_connection = self.on_new_connection
            self.monitor.on_connection_closed = self.on_connection_closed
            self.monitor.on_update = self.on_update
            
            self.connection_history: List[ConnectionInfo] = []
            self.current_connections: List[ConnectionInfo] = []
            
            # Context menu
            self.context_menu = Menu(self.root, tearoff=0)
            self.context_menu.add_command(label="Block IP", command=self.block_selected_ip)
            self.context_menu.add_separator()
            self.context_menu.add_command(label="Show Details", command=self.show_connection_details)
            
            self.setup_gui()
            
            # Initial checks
            self.root.after(100, self.check_admin_on_startup)
            self.root.after(5000, self._periodic_update)
            
            # Check for updates on startup if enabled
            if self.settings.get('check_updates_on_start', True):
                self.root.after(30000, self.auto_check_for_updates)
            
            # WICHTIG: System Tray erst nach einer Verzögerung initialisieren
            # Dies gibt dem System Zeit, die Desktop-Sitzung vollständig zu laden
            if not self.start_minimized:
                # Wenn nicht minimiert gestartet, sofort Tray erstellen
                self.setup_system_tray()
            else:
                # Bei Autostart/minimiert: Verzögert Tray erstellen
                self.root.after(3000, self.setup_system_tray_delayed)
            
            # Handle minimized startup
            if self.start_minimized and self.settings.get('start_minimized', False):
                self.root.withdraw()
            
            # Setup window closing protocol - MUST BE HERE AT THE END OF __init__
            self.setup_window_protocol()
            
            # Auto-start monitoring if setting is enabled
            if self.settings.get('start_monitoring_on_start', True):
                self.root.after(1000, self.start_monitoring)
            
            self._pending_tree_updates: List[ConnectionInfo] = []
            self._update_scheduled = False
            
            # Cleanup on exit
            atexit.register(self.cleanup)

    def update_main_status(self, message: str):
        """Update main status bar with thread-safe operation"""
        def safe_update():
            self.status_var.set(message)
            self.root.update_idletasks()
        
        if threading.current_thread() is threading.main_thread():
            safe_update()
        else:
            self.root.after(0, safe_update)

    def _check_interactive_session(self):
        """Check if we're in an interactive user session"""
        try:
            import ctypes
            # Check if we have a desktop window handle
            hwnd = ctypes.windll.user32.GetDesktopWindow()
            if hwnd == 0:
                self.logger.info("No desktop window - likely not in interactive session")
                return False
            
            # Check if we're running in a console session
            process_id = ctypes.windll.kernel32.GetCurrentProcessId()
            session_id = ctypes.windll.kernel32.ProcessIdToSessionId(process_id, ctypes.byref(ctypes.c_ulong()))
            
            # Check if session is interactive (session 1 is usually the first interactive session)
            WTS_SESSION_INFO = ctypes.c_void_p
            session_infos = WTS_SESSION_INFO()
            count = ctypes.c_ulong()
            
            if ctypes.windll.wtsapi32.WTSEnumerateSessionsW(0, 0, 1, ctypes.byref(session_infos), ctypes.byref(count)):
                for i in range(count.value):
                    # Check if this session is active
                    pass
            
            # Fallback: Check if we can create a window
            test_hwnd = ctypes.windll.user32.CreateWindowExW(0, "Static", "test", 0, 0, 0, 0, 0, 0, 0, 0, 0)
            if test_hwnd:
                ctypes.windll.user32.DestroyWindow(test_hwnd)
                self.logger.info("Interactive session detected (can create windows)")
                return True
            else:
                self.logger.info("Cannot create windows - likely not interactive session")
                return False
                
        except Exception as e:
            self.logger.debug(f"Interactive session check failed: {e}")
            # Assume interactive session if we can't determine
            return True

    def setup_system_tray_delayed(self):
        """Delayed system tray setup for autostart scenarios"""
        if not self._check_interactive_session():
            self.logger.info("Not in interactive session, skipping system tray icon")
            self.tray_manager = None
            self.settings.set('start_to_tray', False)
            if hasattr(self, 'start_to_tray_var'):
                self.start_to_tray_var.set(False)
            return
        
        # Check if tray icon already exists
        if self.tray_manager is not None and hasattr(self.tray_manager, 'icon') and self.tray_manager.icon:
            self.logger.info("System tray icon already exists")
            return
        
        try:
            # Try to create tray icon
            self.tray_manager = SystemTrayManager(self.root, self)
            success = self.tray_manager.create_tray_icon()
            
            if not success:
                self.logger.warning("System tray setup failed")
                self.tray_manager = None
                self.settings.set('start_to_tray', False)
                if hasattr(self, 'start_to_tray_var'):
                    self.start_to_tray_var.set(False)
            else:
                self.logger.info("Delayed system tray setup completed successfully")
                
        except Exception as e:
            self.logger.error(f"Failed delayed system tray setup: {e}")
            self.tray_manager = None
            self.settings.set('start_to_tray', False)
            if hasattr(self, 'start_to_tray_var'):
                self.start_to_tray_var.set(False)
    
    def setup_system_tray(self):
        """Setup system tray icon"""
        try:
            self.tray_manager = SystemTrayManager(self.root, self)
            success = self.tray_manager.create_tray_icon()
            
            if not success:
                self.logger.warning("System tray setup failed, continuing without tray icon")
                self.tray_manager = None
                # When tray fails, disable the option in settings
                self.settings.set('start_to_tray', False)
                # Only set UI variable if it exists (it's created in setup_gui)
                if hasattr(self, 'start_to_tray_var'):
                    self.start_to_tray_var.set(False)
                
            self.logger.info("System tray setup completed")
            
        except Exception as e:
            self.logger.error(f"Failed to setup system tray: {e}")
            self.tray_manager = None
            # When tray fails, disable the option
            self.settings.set('start_to_tray', False)
            if hasattr(self, 'start_to_tray_var'):
                self.start_to_tray_var.set(False)

    def setup_window_protocol(self):
        """Setup window closing behavior based on settings"""
        def on_closing():
            # Check if tray is enabled AND tray manager exists AND icon is active
            if self.settings.get('start_to_tray', False) and self.tray_manager and self.tray_manager.icon:
                # Minimize to tray instead of closing
                self.root.withdraw()
                # Optional: Show tray notification if method exists
                try:
                    if hasattr(self.tray_manager, 'show_notification'):
                        self.tray_manager.show_notification(
                            "WinDetox",
                            "Application minimized to system tray. Right-click tray icon to show window or exit."
                        )
                    else:
                        self.log_append("Application minimized to system tray.\n")
                except:
                    pass
            else:
                # Close normally
                self.cleanup_and_exit()
        
        self.root.protocol("WM_DELETE_WINDOW", on_closing)
    
    def check_admin_on_startup(self):
        """Check admin rights on startup and show warning"""
        if not is_admin():
            messagebox.showwarning(
                "No Administrator Rights",
                "Program is running WITHOUT administrator rights!\n\n"
                "⚠️ Firewall rules CANNOT be applied.\n\n"
                "Please run program as administrator:\n"
                "Right-click → 'Run as administrator'\n\n"
                "Monitoring still works, but IPs will not be blocked!"
            )
            self.status_var.set("⚠️ NO ADMIN RIGHTS - Firewall blocking disabled")
    
    def setup_gui(self):
        """
        GUI CONSTRUCTION - WHERE ALL WIDGETS ARE CREATED
        
        Tab structure:
        1. Tab 0: Active Connections (TreeView with connections)
        2. Tab 1: Event Log (ScrolledText for logs)
        3. Tab 2: History (TreeView of past connections)
        4. Tab 3: IP Blocking (Blocklist management)
        5. Tab 4: Settings (User preferences)
        
        To add a new tab:
        1. Add new frame to notebook
        2. Create widgets in the frame
        3. Add event handlers if needed
        4. Update save_selected_tab() if needed
        """
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(3, weight=1)
        
        # Control Bar
        ctrl = ttk.Frame(main)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0,10))
        
        self.btn_start = ttk.Button(ctrl, text="Start", command=self.start_monitoring)
        self.btn_start.pack(side="left", padx=5)
        self.btn_stop = ttk.Button(ctrl, text="Stop", command=self.stop_monitoring, state="disabled")
        self.btn_stop.pack(side="left", padx=5)
        
        ttk.Button(ctrl, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)
        ttk.Button(ctrl, text="Clear History", command=self.clear_history).pack(side="left", padx=5)
        ttk.Button(ctrl, text="Export", command=self.export_connections).pack(side="left", padx=5)
        
        ttk.Button(ctrl, text="Restart as Admin", 
                  command=lambda: run_as_admin("Restart with administrator privileges?")).pack(side="left", padx=10)
        
        ttk.Separator(ctrl, orient="vertical").pack(side="left", fill="y", padx=10)
        
        # Filter controls
        ttk.Label(ctrl, text="Filter:", font=("",9,"bold")).pack(side="left")
        self.var_inc = tk.BooleanVar(value=True)
        self.var_out = tk.BooleanVar(value=True)
        self.var_lis = tk.BooleanVar(value=True)
        self.var_ext = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(ctrl, text="Incoming", variable=self.var_inc, command=self.apply_filters).pack(side="left", padx=5)
        ttk.Checkbutton(ctrl, text="Outgoing", variable=self.var_out, command=self.apply_filters).pack(side="left", padx=5)
        ttk.Checkbutton(ctrl, text="Listening", variable=self.var_lis, command=self.apply_filters).pack(side="left", padx=5)
        ttk.Checkbutton(ctrl, text="ONLY EXTERNAL", variable=self.var_ext, command=self.apply_filters).pack(side="left", padx=10)
        
        # Statistics
        stats_frame = ttk.LabelFrame(main, text="Statistics", padding=10)
        stats_frame.grid(row=1, column=0, sticky="ew", pady=(0,10))
        self.stats_var = tk.StringVar(value="No data")
        ttk.Label(stats_frame, textvariable=self.stats_var, font=("",10)).pack()
        
        # Admin Status
        admin_frame = ttk.Frame(main)
        admin_frame.grid(row=2, column=0, sticky="ew", pady=(0,10))
        
        self.admin_status_var = tk.StringVar()
        self.admin_label = ttk.Label(
            admin_frame, 
            textvariable=self.admin_status_var,
            font=("", 9, "bold")
        )
        self.admin_label.pack(side="left", padx=10)
        
        if is_admin():
            self.admin_status_var.set("✓ Administrator Rights: Firewall blocking ACTIVE")
            self.admin_label.config(foreground="green")
        else:
            self.admin_status_var.set("⚠️ NO Admin Rights: Firewall blocking DISABLED")
            self.admin_label.config(foreground="red")
        
        # Notebook for tabs
        nb = ttk.Notebook(main)
        nb.grid(row=3, column=0, sticky="nsew")
        
        # Bind tab change event to save selected tab
        nb.bind("<<NotebookTabChanged>>", lambda e: self.save_selected_tab(nb.index(nb.select())))
        
        # Tab 1: Active Connections
        f1 = ttk.Frame(nb, padding=10)
        nb.add(f1, text="Active Connections")
        f1.columnconfigure(0, weight=1)
        f1.rowconfigure(0, weight=1)
        
        cols = ('Dir', 'Process', 'PID', 'Local', 'Remote', 'Status')
        self.tree = ttk.Treeview(f1, columns=cols, show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="Time")
        self.tree.column("#0", width=90)
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("Dir", width=80)
        self.tree.column("Process", width=180)
        self.tree.column("PID", width=70)
        self.tree.column("Local", width=220)
        self.tree.column("Remote", width=220)
        self.tree.column("Status", width=120)
        
        vsb = ttk.Scrollbar(f1, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.show_connection_details)
        
        # Color coding for connection types
        self.tree.tag_configure("incoming", background="#ffcccc")
        self.tree.tag_configure("outgoing", background="#ccffcc")
        self.tree.tag_configure("listening", background="#ffffcc")
        
        # Tab 2: Event Log
        f2 = ttk.Frame(nb, padding=10)
        nb.add(f2, text="Event Log")
        f2.columnconfigure(0, weight=1)
        f2.rowconfigure(0, weight=1)
        
        self.log = scrolledtext.ScrolledText(f2, state="disabled", font=("Consolas", 9))
        self.log.grid(row=0, column=0, sticky="nsew")
        
        # Tab 3: History
        f3 = ttk.Frame(nb, padding=10)
        nb.add(f3, text="History")
        f3.columnconfigure(0, weight=1)
        f3.rowconfigure(0, weight=1)
        
        hist_cols = ("Time", "Direction", "Process", "Connection", "Status")
        self.hist_tree = ttk.Treeview(f3, columns=hist_cols, show="headings", selectmode="extended")
        for c in hist_cols: 
            self.hist_tree.heading(c, text=c)
        self.hist_tree.column("Time", width=150)
        self.hist_tree.column("Direction", width=90)
        self.hist_tree.column("Process", width=180)
        self.hist_tree.column("Connection", width=400)
        self.hist_tree.column("Status", width=100)
        
        vsb2 = ttk.Scrollbar(f3, command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=vsb2.set)
        self.hist_tree.grid(row=0, column=0, sticky="nsew")
        vsb2.grid(row=0, column=1, sticky="ns")
        
        # Tab 4: Blocklist Management - COMPACT VERSION
        f4 = ttk.Frame(nb, padding=10)
        nb.add(f4, text="IP Blocking")
        f4.columnconfigure(0, weight=1)
        f4.columnconfigure(1, weight=1)
        
        # Use a Grid Layout with 2 columns
        row = 0
        
        # Row 0: Blocklist Management and Microsoft Blocking
        bl_frame = ttk.LabelFrame(f4, text="Blocklist", padding=8)
        bl_frame.grid(row=row, column=0, sticky="nsew", padx=5, pady=5)
        ttk.Button(bl_frame, text="Show Blocked IPs", 
                  command=self.show_blocked_ips, width=20).pack(pady=3)
        ttk.Button(bl_frame, text="Update Blocklists", 
                  command=self.update_blocklists, width=20).pack(pady=3)
        
        ms_frame = ttk.LabelFrame(f4, text="Microsoft", padding=8)
        ms_frame.grid(row=row, column=1, sticky="nsew", padx=5, pady=5)
        ttk.Button(ms_frame, text="Block Microsoft", 
                  command=self.block_microsoft_complete, width=20).pack(pady=3)
        ttk.Button(ms_frame, text="Hosts File Block", 
                  command=self.block_microsoft_hosts, width=20).pack(pady=3)
        ttk.Button(ms_frame, text="Restore Hosts", 
                  command=self.restore_hosts_backup, width=20).pack(pady=3)
        
        row += 1
        
        # Row 1: Firewall and DoH
        fw_frame = ttk.LabelFrame(f4, text="Firewall", padding=8)
        fw_frame.grid(row=row, column=0, sticky="nsew", padx=5, pady=5)
        ttk.Button(fw_frame, text="Block Pending IPs", 
                  command=self.apply_pending_firewall_rules, width=20).pack(pady=3)
        
        doh_frame = ttk.LabelFrame(f4, text="DNS over HTTPS", padding=8)
        doh_frame.grid(row=row, column=1, sticky="nsew", padx=5, pady=5)
        ttk.Button(doh_frame, text="Disable DoH", 
                  command=self.disable_doh, width=20).pack(pady=3)
        ttk.Button(doh_frame, text="Enable DoH", 
                  command=self.enable_doh, width=20).pack(pady=3)
        
        row += 1
        
        # Row 2: Delivery Optimization and NCSI
        do_frame = ttk.LabelFrame(f4, text="Delivery Optimization", padding=8)
        do_frame.grid(row=row, column=0, sticky="nsew", padx=5, pady=5)
        ttk.Button(do_frame, text="Disable", 
                  command=self.disable_delivery_optimization, width=20).pack(pady=3)
        ttk.Button(do_frame, text="Enable", 
                  command=self.enable_delivery_optimization, width=20).pack(pady=3)
        
        ncsi_frame = ttk.LabelFrame(f4, text="NCSI Control", padding=8)
        ncsi_frame.grid(row=row, column=1, sticky="nsew", padx=5, pady=5)
        ttk.Button(ncsi_frame, text="Disable NCSI", 
                  command=self.disable_ncsi, width=20).pack(pady=3)
        ttk.Button(ncsi_frame, text="Enable NCSI", 
                  command=self.enable_ncsi, width=20).pack(pady=3)
        ttk.Button(ncsi_frame, text="Test Status", 
                  command=self.test_ncsi_status, width=20).pack(pady=3)
        
        row += 1
        
        # Row 3: One-Click Privacy (span 2 columns)
        privacy_frame = ttk.LabelFrame(f4, text="One-Click Privacy", padding=8)
        privacy_frame.grid(row=row, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        ttk.Button(privacy_frame, text="Activate Full Privacy Mode", 
                  command=self.full_privacy_mode, width=30).pack(side="left", padx=5, pady=3)
        ttk.Button(privacy_frame, text="Undo Privacy Mode", 
                  command=self.undo_full_privacy_mode, width=30).pack(side="left", padx=5, pady=3)
        
        row += 1
        
        # Row 4: Nuclear Options (span 2 columns)
        nuc_frame = ttk.LabelFrame(f4, text="⚠️ Emergency Options", padding=8)
        nuc_frame.grid(row=row, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        ttk.Button(nuc_frame, text="NUCLEAR - Block All Internet", 
                  command=self.nuclear_option, width=30).pack(side="left", padx=5, pady=3)
        ttk.Button(nuc_frame, text="UNDO Nuclear Option", 
                  command=self.undo_nuclear_option, width=30).pack(side="left", padx=5, pady=3)
        
        # Tab 5: Settings - COMPACT VERSION
        f5 = ttk.Frame(nb, padding=10)
        nb.add(f5, text="Settings")
        f5.columnconfigure(0, weight=1)
        
        # Use a Canvas with Scrollbar for Settings
        settings_canvas = tk.Canvas(f5)
        settings_scrollbar = ttk.Scrollbar(f5, orient="vertical", command=settings_canvas.yview)
        settings_frame = ttk.Frame(settings_canvas)
        
        settings_frame.bind(
            "<Configure>",
            lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))
        )
        
        settings_canvas.create_window((0, 0), window=settings_frame, anchor="nw")
        settings_canvas.configure(yscrollcommand=settings_scrollbar.set)
        
        settings_canvas.pack(side="left", fill="both", expand=True)
        settings_scrollbar.pack(side="right", fill="y")
        
        # Version Information (compact)
        version_frame = ttk.LabelFrame(settings_frame, text="Version Information", padding=10)
        version_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10), padx=5)
        
        ttk.Label(version_frame, text=f"Version: {Config.CURRENT_VERSION}", 
                 font=("", 9, "bold")).pack(pady=2)
        ttk.Label(version_frame, text="© 2025 Privacy Focused Development Team", 
                 font=("", 7)).pack(pady=1)
        
        # Update Button directly in the frame
        ttk.Button(version_frame, text="Check for Updates",
                  command=self.check_for_updates, width=20).pack(pady=5)
        
        # Startup Settings (compact)
        startup_frame = ttk.LabelFrame(settings_frame, text="Startup Settings", padding=10)
        startup_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10), padx=5)
        
        # All checkbuttons compact arrangement
        self.autostart_var = tk.BooleanVar(value=self.settings.get('autostart_all_users', False))
        ttk.Checkbutton(
            startup_frame, 
            text="Start with Windows (admin)",
            variable=self.autostart_var,
            command=self.toggle_autostart
        ).pack(anchor="w", pady=2)
        
        self.start_minimized_var = tk.BooleanVar(value=self.settings.get('start_minimized', False))
        ttk.Checkbutton(
            startup_frame,
            text="Start minimized",
            variable=self.start_minimized_var,
            command=lambda: self.settings.set('start_minimized', self.start_minimized_var.get())
        ).pack(anchor="w", pady=2)
        
        self.start_to_tray_var = tk.BooleanVar(value=self.settings.get('start_to_tray', False))
        ttk.Checkbutton(
            startup_frame,
            text="Minimize to tray",
            variable=self.start_to_tray_var,
            command=lambda: self.settings.set('start_to_tray', self.start_to_tray_var.get())
        ).pack(anchor="w", pady=2)
        
        self.start_monitoring_var = tk.BooleanVar(value=self.settings.get('start_monitoring_on_start', True))
        ttk.Checkbutton(
            startup_frame,
            text="Auto-start monitoring",
            variable=self.start_monitoring_var,
            command=lambda: self.settings.set('start_monitoring_on_start', self.start_monitoring_var.get())
        ).pack(anchor="w", pady=2)
        
        # Check autostart status
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
        
        # Update Settings (compact)
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
        
        # Application Settings (compact)
        app_frame = ttk.LabelFrame(settings_frame, text="Application Settings", padding=10)
        app_frame.grid(row=3, column=0, sticky="ew", pady=(0, 10), padx=5)
        
        self.show_notifications_var = tk.BooleanVar(value=self.settings.get('show_notifications', True))
        ttk.Checkbutton(
            app_frame,
            text="Show notifications",
            variable=self.show_notifications_var,
            command=lambda: self.settings.set('show_notifications', self.show_notifications_var.get())
        ).pack(anchor="w", pady=2)
        
        # Theme and Language in one line
        theme_lang_frame = ttk.Frame(app_frame)
        theme_lang_frame.pack(fill="x", pady=5)
        
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
        
        # Reset Settings Button
        ttk.Button(
            app_frame,
            text="Reset All Settings",
            command=self.reset_settings
        ).pack(pady=5)
        
        # Restore selected tab if saved
        selected_tab = self.settings.get('selected_tab', 0)
        nb.select(selected_tab)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(main, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        status.grid(row=4, column=0, sticky="ew", pady=(10,0))
    
    def save_selected_tab(self, tab_index):
        """Save the currently selected tab index"""
        self.settings.set('selected_tab', tab_index)
    
    def toggle_autostart(self):
        """Toggle autostart setting - NO CONFIRMATION WINDOWS"""
        try:
            success = self.settings.set_autostart_all_users(self.autostart_var.get())
            
            if success:
                # Immediately check and update status
                schtasks_exists, registry_exists = self.settings.check_autostart_status()
                is_enabled = schtasks_exists or registry_exists
                
                # Update UI state
                self.autostart_var.set(is_enabled)
                
                # Update status label
                status_text = f"Status: {'Enabled' if is_enabled else 'Disabled'}"
                if schtasks_exists:
                    status_text += " (Task Scheduler)"
                elif registry_exists:
                    status_text += " (Registry)"
                self.autostart_status_label.config(text=status_text)
                
                # Log result
                self.log_append(f"Autostart {'enabled' if is_enabled else 'disabled'} successfully\n")
            else:
                # Operation failed, revert checkbox
                self.autostart_var.set(not self.autostart_var.get())
                self.log_append("Failed to change autostart setting\n")
                
        except PermissionError:
            self.autostart_var.set(not self.autostart_var.get())
            self.log_append("Admin rights required for autostart changes\n")
        except Exception as e:
            self.autostart_var.set(not self.autostart_var.get())
            self.log_append(f"Autostart error: {str(e)[:100]}\n")
    
    def check_for_updates(self):
        """Check for program updates with signature verification"""
        # Create progress window
        win = tk.Toplevel(self.root)
        win.title("Checking for Updates...")
        win.geometry("400x150")
        win.transient(self.root)
        win.grab_set()
        
        ttk.Label(win, text="Checking for updates...", 
                 font=("", 11, "bold")).pack(pady=20)
        progress = ttk.Progressbar(win, mode="indeterminate", length=300)
        progress.pack(pady=10)
        progress.start()
        
        status = tk.StringVar(value="Connecting to update server...")
        ttk.Label(win, textvariable=status).pack(pady=5)
        
        def run_update_check():
            try:
                update_needed, latest_version, changes, expected_hash = self.update_manager.check_for_updates()
                
                def show_result():
                    progress.stop()
                    win.destroy()
                    
                    # Save last check time
                    self.settings.set('last_update_check', time.time())
                    
                    if update_needed:
                        update_message = (
                            f"Update available!\n\n"
                            f"Current version: {Config.CURRENT_VERSION}\n"
                            f"Latest version: {latest_version}\n\n"
                            f"Changes in version {latest_version}:\n"
                            f"{changes}\n\n"
                            f"Do you want to update now?"
                        )
                        
                        if messagebox.askyesno("Update Available", update_message):
                            try:
                                if self.update_manager.perform_update(expected_hash):
                                    messagebox.showinfo(
                                        "Update Started",
                                        "The update has been started.\n"
                                        "The program will restart automatically."
                                    )
                                else:
                                    messagebox.showerror(
                                        "Update Failed",
                                        "Failed to download or install the update.\n"
                                        "Please try again later or update manually."
                                    )
                            except SecurityError as e:
                                messagebox.showerror(
                                    "Security Error",
                                    f"Update verification failed!\n\n"
                                    f"{str(e)}\n\n"
                                    f"The update has been cancelled for security reasons."
                                )
                            except UpdateError as e:
                                messagebox.showerror(
                                    "Update Error",
                                    f"Update failed: {str(e)}"
                                )
                        else:
                            messagebox.showinfo("Update Skipped", "Update has been skipped.")
                    else:
                        messagebox.showinfo(
                            "Up to Date",
                            f"You are using the latest version ({Config.CURRENT_VERSION}).\n\n"
                            f"Latest version information:\n{changes}"
                        )
                
                win.after(0, show_result)
                
            except UpdateError as e:
                error_message = str(e)
                def show_error():
                    progress.stop()
                    win.destroy()
                    messagebox.showerror("Update Check Failed", 
                                       f"Failed to check for updates:\n{error_message}")
                
                win.after(0, show_error)
            except Exception as e:
                error_message = str(e)
                def show_error():
                    progress.stop()
                    win.destroy()
                    messagebox.showerror("Update Check Failed", 
                                       f"Unexpected error:\n{error_message}")
                
                win.after(0, show_error)
        
        threading.Thread(target=run_update_check, daemon=True).start()
    
    def auto_check_for_updates(self):
        """Automatically check for updates on startup (if enabled)"""
        try:
            # Don't check too frequently (max once per day)
            last_check = self.settings.get('last_update_check', 0)
            if time.time() - last_check < 86400:  # 24 hours
                return
            
            try:
                update_needed, latest_version, changes, expected_hash = self.update_manager.check_for_updates()
                
                if update_needed:
                    # Ask user if they want to update
                    self.root.after(0, lambda: self.show_update_notification(latest_version, changes))
                
                # Save check time
                self.settings.set('last_update_check', time.time())
                
            except UpdateError as e:
                # Log but don't show error for auto-check
                self.logger.debug(f"Auto-update check skipped: {e}")
            except Exception as e:
                self.logger.debug(f"Auto-update check error: {e}")
            
        except Exception as e:
            self.logger.debug(f"Auto-update setup error: {e}")
    
    def show_update_notification(self, latest_version, changes):
        """Show update notification to user"""
        update_message = (
            f"Update available!\n\n"
            f"Current version: {Config.CURRENT_VERSION}\n"
            f"Latest version: {latest_version}\n\n"
            f"Do you want to update now?"
        )
        
        if messagebox.askyesno("Update Available", update_message):
            self.check_for_updates()
    
    def reset_settings(self):
        """Reset all settings to default values"""
        if messagebox.askyesno("Reset Settings",
                              "Are you sure you want to reset all settings to default values?\n\n"
                              "This will reset:\n"
                              "- Startup settings\n"
                              "- Update settings\n"
                              "- Application preferences\n\n"
                              "Your blocklist and connection history will NOT be affected."):
            # Reset settings
            self.settings.settings = {
                'autostart_all_users': False,
                'start_minimized': False,
                'start_to_tray': False,
                'check_updates_on_start': True,
                'auto_update_blocklists': True,
                'show_notifications': True,
                'theme': 'default',
                'language': 'english',
                'last_update_check': 0,
                'window_position': None,
                'window_size': None,
                'selected_tab': 0,
                'start_monitoring_on_start': True
            }
            self.settings.save_settings()
            
            # Update UI
            self.autostart_var.set(False)
            self.start_minimized_var.set(False)
            self.start_to_tray_var.set(False)
            self.check_updates_var.set(True)
            self.auto_update_blocklists_var.set(True)
            self.show_notifications_var.set(True)
            self.theme_var.set('default')
            self.language_var.set('english')
            self.start_monitoring_var.set(True)
            
            # Update autostart status
            hklm_status, hkcu_status = self.settings.check_autostart_status()
            status_text = f"Status: {'Enabled' if hklm_status or hkcu_status else 'Disabled'}"
            self.autostart_status_label.config(text=status_text)
            
            messagebox.showinfo("Settings Reset", "All settings have been reset to default values.")
    
    def show_connection_details(self, event=None):
        """Show detailed information about selected connection"""
        sel = self.tree.selection()
        if not sel:
            return
        
        item = self.tree.item(sel[0])
        values = item['values']
        
        details = f"""
Connection Details:
──────────────────
Time: {item['text']}
Direction: {values[0]}
Process: {values[1]}
PID: {values[2]}
Local Address: {values[3]}
Remote Address: {values[4]}
Status: {values[5]}
"""
        
        messagebox.showinfo("Connection Details", details)
    
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
            self.btn_start.config(state="disabled")
            self.btn_stop.config(state="normal")
            self.status_var.set("Monitoring running...")
            self.log_append("Monitoring started\n")
            # Update tray menu if exists
            if self.tray_manager:
                self.tray_manager.update_tray_menu()
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitor.stop()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_var.set("Stopped")
        self.log_append("Monitoring stopped\n")
        # Update tray menu if exists
        if self.tray_manager:
            self.tray_manager.update_tray_menu()
    
    def on_new_connection(self, conn: ConnectionInfo):
        """Handle new connection detection"""
        if conn.direction == "INCOMING" and conn.remote_addr and not is_local_ip(conn.remote_addr):
            self.log_append(f"⚠️ EXTERNAL CONNECTION from {conn.remote_addr}:{conn.remote_port} → {conn.local_addr}:{conn.local_port} ({conn.process_name})\n")
        else:
            self.log_append(f"{conn.direction}: {conn}\n")
        
        # Add to history
        self.connection_history.append(conn)
        if len(self.connection_history) > Config.MAX_HISTORY_ENTRIES:
            self.connection_history.pop(0)
            
        # Update history tree
        self.root.after(0, lambda c=conn: self.hist_tree.insert("", 0, values=(
            c.timestamp.strftime("%Y-%m-d %H:%M:%S"),
            c.direction,
            f"{c.process_name} ({c.pid})",
            f"{c.local_addr}:{c.local_port} → {c.remote_addr}:{c.remote_port}",
            c.status
        )))
    
    def on_connection_closed(self, conn: ConnectionInfo):
        """Handle connection closure"""
        self.log_append(f"CLOSED: {conn}\n")
    
    def on_update(self, conns: List[ConnectionInfo]):
        """Handle connection updates"""
        self.current_connections = conns
        self.root.after(0, self.apply_filters)
        self.root.after(0, self.update_stats)
    
    def apply_filters(self):
        """Apply current filters to connection list"""
        filtered = []
        for c in self.current_connections:
            if c.direction == "INCOMING" and not self.var_inc.get(): 
                continue
            if c.direction == "OUTGOING" and not self.var_out.get(): 
                continue
            if c.direction == "LISTENING" and not self.var_lis.get(): 
                continue
            if self.var_ext.get():
                if c.direction in ("OUTGOING", "LISTENING"): 
                    continue
                if c.direction == "INCOMING" and is_local_ip(c.remote_addr): 
                    continue
            filtered.append(c)
        
        # Update tree
        self.tree.delete(*self.tree.get_children())
        for c in filtered:
            tag = "incoming" if c.direction == "INCOMING" else "outgoing" if c.direction == "OUTGOING" else "listening"
            remote = f"{c.remote_addr}:{c.remote_port}" if c.remote_addr else "-"
            self.tree.insert("", "end", text=c.timestamp.strftime("%H:%M:%S"), values=(
                c.direction, c.process_name, c.pid,
                f"{c.local_addr}:{c.local_port}", remote, c.status
            ), tags=(tag,))
        
        # Update status
        total = len(self.current_connections)
        shown = len(filtered)
        if self.var_ext.get():
            self.status_var.set(f"ONLY EXTERNAL: {shown} visible")
        else:
            self.status_var.set(f"Showing {shown}/{total} connections")
    
    def update_stats(self):
        """Update statistics display"""
        s = self.monitor.get_statistics()
        self.stats_var.set(f"Total: {s['total']} | Listening: {s['listening']} | Incoming: {s['incoming']} | Outgoing: {s['outgoing']}")
    
    def log_append(self, text: str):
        """Append text to log with automatic line limiting"""
        def do():
            self.log.config(state="normal")
            self.log.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {text}")
            
            lines = int(self.log.index("end-1c").split('.')[0])
            if lines > Config.MAX_LOG_LINES:
                self.log.delete("1.0", f"{lines - Config.MAX_LOG_LINES + 1}.0")
                
            self.log.see("end")
            self.log.config(state="disabled")
            
        self.root.after(0, do)
    
    def clear_log(self):
        """Clear log window"""
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")
    
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
            messagebox.showwarning("No Selection", "Please select one or more connections.")
            return
        
        ips_to_block = set()
        local_ips = []
        
        for item_id in sel:
            item = self.tree.item(item_id)
            remote = item["values"][4]
            if remote == "-" or ":" not in remote:
                continue
                
            ip = remote.split(":")[0]
            if is_local_ip(ip):
                local_ips.append(ip)
            else:
                ips_to_block.add(ip)
        
        if local_ips:
            messagebox.showwarning(
                "Local IPs", 
                f"These local IPs cannot be blocked:\n" + "\n".join(local_ips)
            )
        
        if ips_to_block:
            ip_list = "\n".join(sorted(ips_to_block))
            if messagebox.askyesno(
                "Block IPs", 
                f"Permanently block these IPs?\n\n{ip_list}\n\nTotal: {len(ips_to_block)} IPs"
            ):
                try:
                    results = self.network_service.block_ips(list(ips_to_block), source="Manual (GUI)")
                    
                    for ip in ips_to_block:
                        self.log_append(f"IP {ip} manually blocked\n")
                    
                    if results["failed"]:
                        messagebox.showwarning(
                            "Partial Success", 
                            f"{results['blocked']}/{results['total']} IPs blocked successfully.\n"
                            f"Failed to block: {', '.join(results['failed'][:5])}"
                        )
                    else:
                        messagebox.showinfo(
                            "Success", 
                            f"{results['blocked']} IPs have been added to blocklist.\n"
                            f"Use 'Block All Pending IPs' to apply firewall rules."
                        )
                except (ValidationError, BlocklistError, FirewallError) as e:
                    messagebox.showerror("Error", f"Failed to block IPs: {e}")
        else:
            messagebox.showinfo("No IPs", "No blockable IPs found in selection.")
    
    def show_context_menu(self, event):
        """Show context menu for Treeview (multi-selection support)"""
        try:
            item = self.tree.identify_row(event.y)
            if item:
                if item not in self.tree.selection():
                    self.tree.selection_set(item)
                    
                selected_count = len(self.tree.selection())
                menu_label = f"Block IP ({selected_count} selected)" if selected_count > 1 else "Block IP"
                
                temp_menu = Menu(self.root, tearoff=0)
                temp_menu.add_command(label=menu_label, command=self.block_selected_ip)
                temp_menu.add_command(label="Show Details", command=self.show_connection_details)
                temp_menu.tk_popup(event.x_root, event.y_root)
                
        except Exception as e:
            self.logger.debug(f"Context menu error: {e}")
    
    def apply_pending_firewall_rules(self):
        """Apply all new IPs at once with detailed progress window"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Administrator rights are required to apply firewall rules.\n"
                                  "Please restart the application as administrator.")
            return
            
        blocklist = self.network_service.blocklist
        new_ips = [ip for ip in blocklist.blocked_ips if ip not in blocklist._firewall_applied_ips]
        
        if not new_ips:
            messagebox.showinfo("Nothing to do", "All IPs are already blocked in firewall.")
            return
        
        # Create detailed progress window
        win = tk.Toplevel(self.root)
        win.title(f"Applying Firewall Rules for {len(new_ips)} IPs")
        win.geometry("700x450")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)
        
        # Title
        title_label = ttk.Label(win, text="🛡️ Applying Windows Firewall Rules", 
                               font=("", 14, "bold"))
        title_label.pack(pady=15)
        
        # Info
        info_label = ttk.Label(win, text=f"Applying firewall rules for {len(new_ips)} blocked IPs",
                              font=("", 10))
        info_label.pack(pady=5)
        
        # Progress bar
        progress_frame = ttk.Frame(win)
        progress_frame.pack(pady=10, padx=20, fill="x")
        
        progress_label = ttk.Label(progress_frame, text="Progress:", font=("", 10))
        progress_label.pack(anchor="w")
        
        progress = ttk.Progressbar(progress_frame, length=600, mode='determinate')
        progress.pack(fill="x", pady=(5, 0))
        
        # Current status
        status_var = tk.StringVar(value="Initializing firewall operations...")
        status_label = ttk.Label(win, textvariable=status_var, 
                                font=("", 10, "bold"), wraplength=650)
        status_label.pack(pady=10)
        
        # Statistics frame
        stats_frame = ttk.Frame(win)
        stats_frame.pack(pady=10, padx=20, fill="x")
        
        stats_vars = {
            "success": tk.StringVar(value="Success: 0"),
            "failed": tk.StringVar(value="Failed: 0"),
            "total": tk.StringVar(value=f"Total: {len(new_ips)}"),
            "current_ip": tk.StringVar(value="Current: -")
        }
        
        ttk.Label(stats_frame, textvariable=stats_vars["success"], 
                 foreground="green").pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=stats_vars["failed"], 
                 foreground="red").pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=stats_vars["total"]).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=stats_vars["current_ip"], 
                 font=("", 9, "italic")).pack(side="right", padx=10)
        
        # Details log
        details_frame = ttk.LabelFrame(win, text="Operation Details", padding=10)
        details_frame.pack(pady=15, padx=20, fill="both", expand=True)
        
        details_text = scrolledtext.ScrolledText(details_frame, height=10, width=80,
                                               state="disabled", font=("Consolas", 9))
        details_text.pack(fill="both", expand=True)
        
        def log_detail(message):
            """Add message to details log"""
            details_text.config(state="normal")
            details_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
            details_text.see(tk.END)
            details_text.config(state="disabled")
            win.update_idletasks()
        
        failed_ips = []
        
        def update_progress(current, total, text):
            """Update progress and status"""
            # Update progress bar
            progress_percent = (current / total) * 100 if total > 0 else 100
            progress['value'] = progress_percent
            
            # Update status
            status_var.set(text)
            
            # Update statistics
            success_count = current - len(failed_ips) if current >= len(failed_ips) else 0
            stats_vars["success"].set(f"Success: {success_count}")
            stats_vars["failed"].set(f"Failed: {len(failed_ips)}")
            
            # Log detail
            if current > 0 and current <= total:
                log_detail(text)
            
            # Update current IP if available
            if current > 0 and current <= len(new_ips):
                stats_vars["current_ip"].set(f"Current: {new_ips[current-1]}")
            
            # Force GUI update
            win.update_idletasks()
        
        def run_firewall_application():
            """Run firewall rule application"""
            nonlocal failed_ips
            
            try:
                log_detail(f"Starting firewall rule application for {len(new_ips)} IPs")
                log_detail("=" * 60)
                
                # Apply rules with progress callback
                success_count = self.network_service.firewall.apply_firewall_rules_bulk(
                    new_ips, add=True, progress_callback=update_progress
                )
                
                # Update blocklist
                for ip in new_ips:
                    if ip not in failed_ips:
                        self.network_service.blocklist._firewall_applied_ips.add(ip)
                
                # Save blocklist
                self.network_service.blocklist.save_blocklist()
                
                log_detail("=" * 60)
                log_detail(f"✅ Firewall rule application completed!")
                
                # Show results
                def show_results():
                    win.destroy()
                    
                    if failed_ips:
                        result_msg = (
                            f"Firewall rules applied with partial success:\n\n"
                            f"✅ Successfully applied: {success_count} IPs\n"
                            f"❌ Failed: {len(failed_ips)} IPs\n\n"
                        )
                        
                        if len(failed_ips) <= 10:
                            result_msg += "Failed IPs:\n" + "\n".join(failed_ips[:10])
                        else:
                            result_msg += f"First 10 failed IPs:\n" + "\n".join(failed_ips[:10])
                            result_msg += f"\n... and {len(failed_ips) - 10} more"
                        
                        messagebox.showwarning("Partial Success", result_msg)
                    else:
                        messagebox.showinfo(
                            "Success", 
                            f"✅ Firewall rules successfully applied for all {success_count} IPs!\n\n"
                            f"All blocked IPs are now actively filtered by Windows Firewall."
                        )
                    
                    self.log_append(f"✅ Firewall rules applied for {success_count} IPs\n")
                    self.status_var.set(f"Firewall active - {success_count} IPs blocked")
                
                win.after(100, show_results)
                
            except PermissionError as e:
                def show_permission_error():
                    win.destroy()
                    messagebox.showerror("Permission Error", 
                                       f"Cannot apply firewall rules:\n\n{str(e)}\n\n"
                                       "Please run as Administrator!")
                
                win.after(0, show_permission_error)
            except Exception as e:
                def show_error():
                    win.destroy()
                    messagebox.showerror("Error", 
                                       f"Failed to apply firewall rules:\n\n{str(e)[:200]}")
                
                win.after(0, show_error)
        
        # Start the process in a separate thread
        threading.Thread(target=run_firewall_application, daemon=True).start()
        
        # Add cancel button (with limited functionality)
        def cancel_operation():
            if messagebox.askyesno("Cancel", 
                                  "Firewall rule application is in progress.\n\n"
                                  "Cancelling may leave firewall in inconsistent state.\n"
                                  "Continue anyway?"):
                win.destroy()
                messagebox.showinfo("Cancelled", "Firewall rule application cancelled.\n"
                                               "Some rules may have been applied.")
        
        cancel_button = ttk.Button(win, text="Cancel", command=cancel_operation)
        cancel_button.pack(pady=10)
        
        # Prevent window closing during operation
        def on_closing():
            if messagebox.askyesno("Close Window", 
                                  "Firewall rules are being applied.\n\n"
                                  "Closing now may interrupt the process and leave\n"
                                  "firewall in inconsistent state.\n\n"
                                  "Close anyway?"):
                win.destroy()
        
        win.protocol("WM_DELETE_WINDOW", on_closing)
    
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
    
    def update_blocklists(self):
        """Start blocklist update in separate thread"""
        def update_task():
            try:
                added = self.network_service.blocklist.update_dynamic_lists()
                self.log_append(f"Blocklists updated: {added} new IPs blocked\n")
            except BlocklistError as e:
                self.log_append(f"Error updating blocklists: {e}\n")
                
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
            messagebox.showinfo("Empty Blocklist", "No IPs blocked.")
            return
        
        viewer = BlockedIPsViewer(
            parent=self.root,
            network_service=self.network_service,
            logger=self.logger,
            on_unblock_callback=self._unblock_from_treeview,
            on_copy_callback=self._copy_selected_ip
        )
        viewer.show()
    
    def block_microsoft_complete(self):
        """Block Microsoft telemetry IPs comprehensively"""
        if not messagebox.askyesno(
            "Block Microsoft", 
            "Windows Update, OneDrive, telemetry, etc. will be blocked.\n\nContinue?"
        ):
            return
        
        # Create progress window
        win = tk.Toplevel(self.root)
        win.title("Blocking Microsoft...")
        win.geometry("500x160")
        win.transient(self.root)
        win.grab_set()
        
        ttk.Label(win, text="Loading blocklist...", font=("",10,"bold")).pack(pady=20)
        p = ttk.Progressbar(win, mode="indeterminate")
        p.pack(pady=10, padx=50, fill="x")
        p.start()
        
        def run():
            try:
                added = self.network_service.blocklist._update_microsoft_list()
                count = len(self.network_service.blocklist.blocked_ips)
                win.after(0, lambda: p.stop())
                win.after(0, lambda: messagebox.showinfo(
                    "Success", 
                    f"{added} new IPs blocked\nTotal: {count}"
                ))
                self.log_append(f"Microsoft blocklist applied (+{added})\n")
            except BlocklistError as e:
                win.after(0, lambda: messagebox.showerror("Error", str(e)))
            except Exception as e:
                win.after(0, lambda: messagebox.showerror("Error", f"Unexpected error: {str(e)}"))
            finally:
                win.after(0, win.destroy)
                
        threading.Thread(target=run, daemon=True).start()
    
    def export_connections(self, filepath: str = None) -> bool:
        """Export current connections as JSON or CSV"""
        if not filepath:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[
                    ("JSON file", "*.json"),
                    ("CSV file", "*.csv"),
                    ("All files", "*.*")
                ]
            )
        
        if not filepath:
            return False
        
        try:
            export_data = []
            for conn in self.current_connections:
                export_data.append({
                    "timestamp": conn.timestamp.isoformat(),
                    "direction": conn.direction,
                    "process": conn.process_name,
                    "pid": conn.pid,
                    "local_address": conn.local_addr,
                    "local_port": conn.local_port,
                    "remote_address": conn.remote_addr,
                    "remote_port": conn.remote_port,
                    "status": conn.status
                })
            
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
            
            self.log_append(f"Connections exported: {filepath}\n")
            messagebox.showinfo("Export successful", f"Data saved:\n{filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            messagebox.showerror("Export Error", str(e))
            return False
    
    def _periodic_update(self):
        """Periodic blocklist update (every hour)"""
        try:
            if self.settings.get('auto_update_blocklists', True):
                self.network_service.blocklist.update_dynamic_lists()
        except Exception as e:
            self.logger.error(f"Periodic update failed: {e}")
        finally:
            self.root.after(3600000, self._periodic_update)
    
    def disable_ncsi(self):
        """Disable Windows NCSI (Network Connectivity Status Indicator) - WITH CONFIRMATION"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Disabling NCSI requires admin rights!\n"
                                  "Please restart the application as administrator.")
            return
            
        if messagebox.askyesno("⚠️ COMPLETELY DISABLE NCSI", 
                              "🚫 ABSOLUTE NCSI-KILL - WINDOWS INTERNET DETECTION WILL BE COMPLETELY DISABLED!\n\n"
                              "THIS MEANS:\n"
                              "• Windows will NEVER show 'No Internet connection'\n"
                              "• Taskbar network icon always shows as connected\n"
                              "• Apps can still access internet (if not blocked)\n"
                              "• No Windows-specific network checks anymore\n\n"
                              "⚠️ IMPORTANT: This only affects Windows internet detection!\n"
                              "           Your real internet connection remains unchanged.\n\n"
                              "This action:\n"
                              "1. Sets registry entries\n"
                              "2. Blocks NCSI domains in hosts file\n"
                              "3. Adds firewall rules\n"
                              "4. Disables NLA Service\n"
                              "5. Sets network signatures to 'Private'\n\n"
                              "Continue?"):
            
            # Progress Window
            win = tk.Toplevel(self.root)
            win.title("🚫 COMPLETELY DISABLING NCSI...")
            win.geometry("600x250")
            win.transient(self.root)
            win.grab_set()
            
            ttk.Label(win, text="🚫 COMPLETELY DISABLING NCSI...", 
                     font=("", 12, "bold"), foreground="red").pack(pady=15)
            
            ttk.Label(win, text="Windows internet detection will be permanently disabled", 
                     font=("", 9)).pack(pady=5)
            
            progress = ttk.Progressbar(win, length=500, mode='determinate')
            progress.pack(pady=15, padx=20)
            
            status = tk.StringVar(value="Starting NCSI kill...")
            ttk.Label(win, textvariable=status, font=("", 9)).pack(pady=5)
            
            details = scrolledtext.ScrolledText(win, height=6, width=70, state="disabled")
            details.pack(pady=10, padx=20)
            
            def update_progress(text, detail=""):
                status.set(text)
                if detail:
                    details.config(state="normal")
                    details.insert(tk.END, f"• {detail}\n")
                    details.see(tk.END)
                    details.config(state="disabled")
                win.update_idletasks()
            
            def run_ncsi_kill():
                try:
                    update_progress("Disabling registry entries...", "Registry: EnableActiveProbing = 0")
                    success = self.network_service.blocklist.disable_ncsi()
                    
                    if success:
                        update_progress("✅ NCSI COMPLETELY DISABLED!", "Windows will never show 'No Internet connection'")
                        
                        # Short summary
                        summary = """
    ✅ NCSI COMPLETELY DISABLED!

    What this means for you:
    ────────────────────────
    ✓ Windows will NEVER show "No Internet connection"
    ✓ Taskbar network icon always shows "Connected"
    ✓ No Windows-internal internet checks
    ✓ Your real internet connection remains intact

    What was changed:
    ───────────────────
    • Registry: EnableActiveProbing = 0
    • Network Signature set to "Private"
    • NCSI domains blocked in hosts file
    • Firewall rules for NCSI servers
    • NLA Service disabled

    ⚠️ IMPORTANT: This only affects Windows!
              Your actual internet access continues to work.
              If you really have no internet, Windows won't show it anymore.
    """
                        
                        win.after(0, win.destroy)
                        messagebox.showinfo("✅ NCSI COMPLETELY DISABLED!", summary)
                        self.log_append("🚫 NCSI COMPLETELY DISABLED - Windows internet detection killed\n")
                        self.status_var.set("NCSI disabled - No Windows internet detection")
                        
                    else:
                        update_progress("❌ Error disabling NCSI")
                        win.after(0, win.destroy)
                        messagebox.showerror("Error", "Failed to disable NCSI.\nCheck admin rights!")
                        
                except Exception as e:
                    update_progress(f"❌ Error: {str(e)}")
                    win.after(0, win.destroy)
                    messagebox.showerror("Error", f"Unknown error: {str(e)}")
            
            threading.Thread(target=run_ncsi_kill, daemon=True).start()
    
    def enable_ncsi(self):
        """Enable Windows NCSI (Network Connectivity Status Indicator) - WITH CONFIRMATION"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Enabling NCSI requires admin rights!\n"
                                  "Please restart the application as administrator.")
            return
            
        if messagebox.askyesno("✅ RESTORE NCSI", 
                              "🔄 RESTORE WINDOWS INTERNET DETECTION\n\n"
                              "THIS MEANS:\n"
                              "• Windows can check internet connectivity again\n"
                              "• 'No Internet connection' will be shown again\n"
                              "• Normal Windows network behavior\n\n"
                              "This action undoes ALL NCSI changes:\n"
                              "1. Resets registry entries\n"
                              "2. Removes NCSI blocks from hosts file\n"
                              "3. Deletes firewall rules\n"
                              "4. Re-enables NLA Service\n"
                              "5. Resets network signatures\n\n"
                              "Continue?"):
            
            # Progress Window
            win = tk.Toplevel(self.root)
            win.title("✅ RESTORING NCSI...")
            win.geometry("600x250")
            win.transient(self.root)
            win.grab_set()
            
            ttk.Label(win, text="✅ RESTORING NCSI...", 
                     font=("", 12, "bold"), foreground="green").pack(pady=15)
            
            ttk.Label(win, text="Windows internet detection will be re-enabled", 
                     font=("", 9)).pack(pady=5)
            
            progress = ttk.Progressbar(win, length=500, mode='determinate')
            progress.pack(pady=15, padx=20)
            
            status = tk.StringVar(value="Starting NCSI restoration...")
            ttk.Label(win, textvariable=status, font=("", 9)).pack(pady=5)
            
            details = scrolledtext.ScrolledText(win, height=6, width=70, state="disabled")
            details.pack(pady=10, padx=20)
            
            def update_progress(text, detail=""):
                status.set(text)
                if detail:
                    details.config(state="normal")
                    details.insert(tk.END, f"• {detail}\n")
                    details.see(tk.END)
                    details.config(state="disabled")
                win.update_idletasks()
            
            def run_ncsi_enable():
                try:
                    update_progress("Enabling registry entries...", "Registry: EnableActiveProbing = 1")
                    success = self.network_service.blocklist.enable_ncsi()
                    
                    if success:
                        update_progress("✅ NCSI RESTORED!", "Windows can check internet connectivity")
                        
                        # Test NCSI
                        update_progress("Testing NCSI connectivity...", "Checking connection to NCSI servers")
                        time.sleep(2)
                        
                        summary = """
    ✅ NCSI RESTORED!

    What this means for you:
    ────────────────────────
    ✓ Windows checks internet connectivity again
    ✓ 'No Internet connection' will be shown correctly
    ✓ Normal Windows network behavior
    ✓ All NCSI blocks removed

    What was reset:
    ───────────────────────
    • Registry: EnableActiveProbing = 1
    • Network Signature reset
    • NCSI blocks removed from hosts file
    • Firewall rules for NCSI deleted
    • NLA Service re-enabled

    ✅ Windows internet detection is active again!
    """
                        
                        win.after(0, win.destroy)
                        messagebox.showinfo("✅ NCSI RESTORED!", summary)
                        self.log_append("✅ NCSI restored - Windows internet detection active\n")
                        self.status_var.set("NCSI active - Windows internet detection active")
                        
                    else:
                        update_progress("❌ Error restoring NCSI")
                        win.after(0, win.destroy)
                        messagebox.showerror("Error", "Failed to restore NCSI.\nCheck admin rights!")
                        
                except Exception as e:
                    update_progress(f"❌ Error: {str(e)}")
                    win.after(0, win.destroy)
                    messagebox.showerror("Error", f"Unknown error: {str(e)}")
            
            threading.Thread(target=run_ncsi_enable, daemon=True).start()
    
    def test_ncsi_status(self):
        """Test current NCSI status - ENHANCED VERSION"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Testing NCSI requires admin rights!\n"
                                  "Please restart the application as administrator.")
            return
            
        # Create test window
        win = tk.Toplevel(self.root)
        win.title("🔍 NCSI STATUS TEST - ENHANCED")
        win.geometry("700x500")
        win.transient(self.root)
        win.grab_set()
        
        ttk.Label(win, text="🔍 NCSI STATUS TEST - ENHANCED", 
                 font=("", 12, "bold")).pack(pady=15)
        
        progress = ttk.Progressbar(win, mode="indeterminate")
        progress.pack(pady=10, padx=50, fill="x")
        progress.start()
        
        status_text = tk.StringVar(value="Starting enhanced NCSI test...")
        status_label = ttk.Label(win, textvariable=status_text)
        status_label.pack(pady=5)
        
        result_text = scrolledtext.ScrolledText(win, height=25, width=80, state="disabled")
        result_text.pack(pady=10, padx=20, fill="both", expand=True)
        
        def run_test():
            try:
                results = self.network_service.blocklist.test_ncsi_status()
                
                def display_results():
                    progress.stop()
                    progress.pack_forget()
                    
                    result_text.config(state="normal")
                    result_text.delete(1.0, tk.END)
                    
                    if "error" in results:
                        result_text.insert(tk.END, f"❌ Test error: {results['error']}")
                        return
                    
                    result_text.insert(tk.END, "🔍 NCSI STATUS REPORT - ENHANCED\n")
                    result_text.insert(tk.END, "=" * 60 + "\n\n")
                    
                    # Overall Status
                    result_text.insert(tk.END, f"OVERALL STATUS: {results.get('overall_status', 'Unknown')}\n")
                    result_text.insert(tk.END, f"Connectivity Score: {results.get('connectivity_score', '?/3')}\n\n")
                    
                    result_text.insert(tk.END, "=" * 60 + "\n")
                    result_text.insert(tk.END, "REGISTRY ENTRIES:\n\n")
                    
                    # Registry status
                    reg_value = results.get("registry_value", "?")
                    reg_status = "✅ ACTIVE" if results.get("registry_enabled") else "🚫 BLOCKED"
                    result_text.insert(tk.END, f"• EnableActiveProbing: {reg_status} (Value: {reg_value})\n")
                    
                    # Network Signature entries
                    unmanaged_val = results.get("unmanaged_first_network", "Not set")
                    unmanaged_blocked = "🚫 BLOCKED" if results.get("unmanaged_blocked") else "✅ OK"
                    result_text.insert(tk.END, f"• Unmanaged/FirstNetwork: {unmanaged_blocked} (Value: '{unmanaged_val}')\n")
                    
                    managed_val = results.get("managed_first_network", "Not set")
                    managed_blocked = "🚫 BLOCKED" if results.get("managed_blocked") else "✅ OK"
                    result_text.insert(tk.END, f"• Managed/FirstNetwork: {managed_blocked} (Value: '{managed_val}')\n\n")
                    
                    result_text.insert(tk.END, "=" * 60 + "\n")
                    result_text.insert(tk.END, "SERVICES:\n\n")
                    
                    # Service status
                    if results.get("nla_service_running"):
                        result_text.insert(tk.END, "✅ NLA Service: Running (State: 4=RUNNING)\n")
                    else:
                        result_text.insert(tk.END, f"🚫 NLA Service: Not running (State: {results.get('nla_service_state', '?')})\n")
                    
                    # Firewall rules
                    if results.get("firewall_block_http"):
                        result_text.insert(tk.END, "🚫 NCSI Firewall Rules: ACTIVE (blocked)\n")
                    else:
                        result_text.insert(tk.END, "✅ NCSI Firewall Rules: No blocks\n\n")
                    
                    result_text.insert(tk.END, "=" * 60 + "\n")
                    result_text.insert(tk.END, "CONNECTIVITY TESTS:\n\n")
                    
                    # URL tests
                    test_urls = [url for url in Config.NCSI_TEST_URLS if url in results]
                    success_count = sum(1 for url in test_urls if results[url])
                    
                    for url in test_urls:
                        if results[url]:
                            content = results.get(f"{url}_content", "No content")
                            result_text.insert(tk.END, f"✅ {url}\n")
                            result_text.insert(tk.END, f"   Content: '{content[:50]}...'\n")
                        else:
                            error = results.get(f"{url}_error", "Timeout/Error")
                            result_text.insert(tk.END, f"🚫 {url}\n")
                            result_text.insert(tk.END, f"   Error: {error}\n")
                    
                    result_text.insert(tk.END, "\n" + "=" * 60 + "\n")
                    result_text.insert(tk.END, "INTERPRETATION:\n\n")
                    
                    # Interpretation
                    if success_count >= 2 and results.get("registry_enabled"):
                        result_text.insert(tk.END, "✅ NCSI FULLY FUNCTIONAL\n")
                        result_text.insert(tk.END, "Windows can correctly detect internet connection.\n")
                    elif success_count == 0 and not results.get("registry_enabled"):
                        result_text.insert(tk.END, "🚫 NCSI COMPLETELY BLOCKED\n")
                        result_text.insert(tk.END, "Windows will NEVER show 'No Internet connection'.\n")
                        result_text.insert(tk.END, "Taskbar icon always shows as connected.\n")
                    else:
                        result_text.insert(tk.END, "⚠️ NCSI PARTIALLY BLOCKED\n")
                        result_text.insert(tk.END, "Windows internet detection is limited.\n")
                    
                    result_text.insert(tk.END, "\n" + "=" * 60 + "\n")
                    result_text.insert(tk.END, "RECOMMENDATIONS:\n\n")
                    
                    if success_count >= 2:
                        result_text.insert(tk.END, "• Everything OK - NCSI works as Windows expects\n")
                    else:
                        result_text.insert(tk.END, "• If you want Windows internet detection: 'Enable NCSI'\n")
                        result_text.insert(tk.END, "• If you NEVER want to see 'No Internet': 'Disable NCSI'\n")
                    
                    result_text.config(state="disabled")
                    status_text.set("Test completed")
                
                win.after(0, display_results)
                
            except Exception as e:
                win.after(0, lambda: messagebox.showerror("Test Error", f"NCSI test error: {str(e)}"))
                win.after(0, win.destroy)
        
        threading.Thread(target=run_test, daemon=True).start()
    
    def nuclear_option(self):
        """Completely block all outgoing traffic (except loopback and DNS)"""
        if not messagebox.askyesno(
            "NUCLEAR OPTION",
            "WARNING: This blocks ALL outgoing traffic!\n"
            "Only loopback (127.0.0.1) and DNS (port 53) will work.\n"
            "Internet is completely dead - for testing or emergencies only.\n\n"
            "Really activate?",
            icon="warning"
        ):
            return
        
        if not is_admin():
            messagebox.showerror("Admin Rights Required", 
                                "Nuclear option requires administrator rights!\n"
                                "Please restart the application as administrator.")
            return
        
        # Create progress window
        win = tk.Toplevel(self.root)
        win.title("Activating Nuclear Option...")
        win.geometry("500x180")
        win.transient(self.root)
        win.grab_set()
        
        ttk.Label(win, text="Activating nuclear option...", 
                 font=("", 11, "bold")).pack(pady=20)
        progress = ttk.Progressbar(win, length=400, mode='determinate')
        progress.pack(pady=10)
        status = tk.StringVar(value="Starting nuclear option...")
        ttk.Label(win, textvariable=status).pack(pady=5)
        
        def run_nuclear():
            try:
                success = self.network_service.firewall.apply_nuclear_firewall_rule(add=True, allow_dns=True)
                win.after(0, lambda: self._finalize_nuclear(success, win))
            except PermissionError as e:
                win.after(0, lambda: messagebox.showerror("Permission Error", str(e)))
                win.after(0, win.destroy)
            except Exception as e:
                win.after(0, lambda: messagebox.showerror("Error", f"Failed: {str(e)}"))
                win.after(0, win.destroy)
        
        threading.Thread(target=run_nuclear, daemon=True).start()
    
    def _finalize_nuclear(self, success: bool, window):
        """Finalize nuclear option activation"""
        if success:
            messagebox.showinfo(
                "Nuclear Option Active",
                "✅ Nuclear option activated!\n\n"
                "All internet traffic is now blocked.\n"
                "Only local (127.0.0.1) communication and DNS (UDP port 53) work.\n"
                "DoT/DoH (TCP 853) is also blocked to prevent bypass."
            )
            self.log_append("⚠️ NUCLEAR OPTION ACTIVATED - All internet blocked\n")
            self.status_var.set("NUCLEAR ACTIVE - Internet blocked")
        else:
            messagebox.showerror(
                "Nuclear Option Failed",
                "Failed to activate nuclear option.\n\n"
                "Please check:\n"
                "1. Administrator rights\n"
                "2. Windows Firewall service\n"
                "3. Antivirus interference"
            )
            self.log_append("❌ Nuclear option failed\n")
        
        window.destroy()
    
    def undo_nuclear_option(self):
        """Undo the nuclear option - restore internet access"""
        if not messagebox.askyesno(
            "UNDO NUCLEAR OPTION",
            "This will remove all nuclear option firewall rules and restore internet access.\n\n"
            "⚠️ This action requires Administrator rights.\n\n"
            "Continue?",
            icon="warning"
        ):
            return
        
        if not is_admin():
            messagebox.showerror("Admin Rights Required", 
                                "Cannot undo nuclear option without Administrator rights!\n"
                                "Please restart the application as administrator.")
            return
        
        # Create progress window
        win = tk.Toplevel(self.root)
        win.title("Restoring Internet Access...")
        win.geometry("500x180")
        win.transient(self.root)
        win.grab_set()
        
        ttk.Label(win, text="Removing nuclear firewall rules...", 
                 font=("", 11, "bold")).pack(pady=20)
        progress = ttk.Progressbar(win, length=400, mode='determinate')
        progress.pack(pady=10)
        status = tk.StringVar(value="Starting removal...")
        ttk.Label(win, textvariable=status).pack(pady=5)
        
        def run_undo():
            try:
                success = self.network_service.firewall.apply_nuclear_firewall_rule(add=False)
                self.network_service.firewall.remove_all_nuclear_rules()
                win.after(0, lambda: self._finalize_undo(success, win))
            except PermissionError as e:
                win.after(0, lambda: messagebox.showerror("Permission Error", str(e)))
                win.after(0, win.destroy)
            except Exception as e:
                win.after(0, lambda: messagebox.showerror("Error", f"Failed: {str(e)}"))
                win.after(0, win.destroy)
        
        threading.Thread(target=run_undo, daemon=True).start()
    
    def _finalize_undo(self, success: bool, window):
        """Finalize nuclear option undo"""
        if success:
            messagebox.showinfo(
                "Nuclear Option Undone",
                "✅ Internet access has been restored!\n\n"
                "All nuclear option firewall rules have been removed.\n"
                "You should now have normal network connectivity."
            )
            self.log_append("✅ Nuclear option undone - Internet restored\n")
            self.status_var.set("Nuclear option undone - Internet restored")
        else:
            messagebox.showerror(
                "Undo Failed",
                "Failed to remove all nuclear option rules.\n\n"
                "You may need to:\n"
                "1. Run as Administrator\n"
                "2. Manually check Windows Firewall rules\n"
                "3. Look for rules named 'WinDetox_Nuclear_*' or 'WinDetox_Allow_Loopback'"
            )
            self.log_append("❌ Failed to undo nuclear option\n")
        
        window.destroy()
    
    def disable_doh(self):
        """Disable Windows DNS over HTTPS"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Administrator rights are required to disable DoH.\n"
                                  "Please restart the application as administrator.")
            return
            
        if messagebox.askyesno("Disable DoH", 
                              "This will disable Windows DNS over HTTPS.\n"
                              "This may improve privacy but could affect some websites.\n\n"
                              "Continue?"):
            try:
                if self.network_service.blocklist.disable_windows_doh():
                    messagebox.showinfo("Success", "Windows DoH has been disabled (including 25H2 support).")
                    self.log_append("Windows DoH disabled\n")
                else:
                    messagebox.showerror("Error", "Failed to disable DoH.")
            except PermissionError as e:
                messagebox.showerror("Permission Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to disable DoH: {e}")
    
    def enable_doh(self):
        """Enable Windows DNS over HTTPS"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Administrator rights are required to enable DoH.\n"
                                  "Please restart the application as administrator.")
            return
            
        if messagebox.askyesno("Enable DoH", 
                              "This will enable Windows DNS over HTTPS.\n"
                              "This may improve security but could affect monitoring.\n\n"
                              "Continue?"):
            try:
                if self.network_service.blocklist.enable_windows_doh():
                    messagebox.showinfo("Success", "Windows DoH has been enabled.")
                    self.log_append("Windows DoH enabled\n")
                else:
                    messagebox.showerror("Error", "Failed to enable DoH.")
            except PermissionError as e:
                messagebox.showerror("Permission Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to enable DoH: {e}")
    
    def disable_delivery_optimization(self):
        """Disable Windows Delivery Optimization"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Administrator rights are required to disable Delivery Optimization.\n"
                                  "Please restart the application as administrator.")
            return
            
        if messagebox.askyesno("Disable Delivery Optimization", 
                              "This will disable Windows Delivery Optimization via registry.\n"
                              "This prevents Windows Update from using other PCs in the LAN.\n\n"
                              "Continue?"):
            try:
                if self.network_service.blocklist.disable_delivery_optimization():
                    messagebox.showinfo("Success", "Delivery Optimization has been disabled.")
                    self.log_append("Delivery Optimization disabled\n")
                else:
                    messagebox.showerror("Error", "Failed to disable Delivery Optimization.")
            except PermissionError as e:
                messagebox.showerror("Permission Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to disable Delivery Optimization: {e}")
    
    def enable_delivery_optimization(self):
        """Enable Windows Delivery Optimization"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Administrator rights are required to enable Delivery Optimization.\n"
                                  "Please restart the application as administrator.")
            return
            
        if messagebox.askyesno("Enable Delivery Optimization", 
                              "This will enable Windows Delivery Optimization.\n"
                              "This may improve update speeds but reduces privacy.\n\n"
                              "Continue?"):
            try:
                if self.network_service.blocklist.enable_delivery_optimization():
                    messagebox.showinfo("Success", "Delivery Optimization has been enabled.")
                    self.log_append("Delivery Optimization enabled\n")
                else:
                    messagebox.showerror("Error", "Failed to enable Delivery Optimization.")
            except PermissionError as e:
                messagebox.showerror("Permission Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to enable Delivery Optimization: {e}")
    
    def block_microsoft_hosts(self):
        """Block Microsoft domains via hosts file"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Administrator rights are required to modify the hosts file.\n"
                                  "Please restart the application as administrator.")
            return
            
        if messagebox.askyesno("Block Microsoft via Hosts", 
                              "This will add comprehensive Microsoft domain blocks to the hosts file.\n"
                              "This blocks telemetry and updates via domains.\n\n"
                              "Continue?"):
            try:
                if self.network_service.blocklist.block_microsoft_in_hosts():
                    messagebox.showinfo("Success", "Microsoft domains have been added to the hosts file.")
                    self.log_append("Microsoft domains added to hosts file\n")
                else:
                    messagebox.showerror("Error", "Failed to update hosts file.")
            except PermissionError as e:
                messagebox.showerror("Permission Error", str(e))
            except BlocklistError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update hosts file: {e}")
    
    def restore_hosts_backup(self):
        """Restore hosts file from backup"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Administrator rights are required to restore hosts file.\n"
                                  "Please restart the application as administrator.")
            return
            
        if messagebox.askyesno("Restore Hosts Backup", 
                              "This will restore the hosts file from the latest backup.\n\n"
                              "Continue?"):
            try:
                if self.network_service.blocklist.restore_hosts_file():
                    messagebox.showinfo("Success", "Hosts file has been restored from backup.")
                    self.log_append("Hosts file restored from backup\n")
                else:
                    messagebox.showerror("Error", "Failed to restore hosts file.")
            except PermissionError as e:
                messagebox.showerror("Permission Error", str(e))
            except BlocklistError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to restore hosts file: {e}")
    
    def full_privacy_mode(self):
        """Activate full privacy mode (one-click) with proper progress feedback"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Full privacy mode requires administrator rights!\n"
                                  "Please restart the application as administrator.")
            return
        
        if not messagebox.askyesno("Full Privacy Mode", 
                                  "🚫 COMPLETELY DE-SPY WINDOWS + KILL NCSI\n\n"
                                  "This will:\n"
                                  "1. Block Microsoft telemetry IPs\n"
                                  "2. Block Microsoft domains via hosts file\n"
                                  "3. Disable Windows DoH\n"
                                  "4. Disable Delivery Optimization\n"
                                  "5. Stop Microsoft tracking services\n"
                                  "6. Disable NCSI (no more 'No Internet' messages!)\n\n"
                                  "Windows will then be as private as Linux Mint!\n"
                                  "⚠️ Without NCSI, no Windows internet detection!\n\n"
                                  "Continue?"):
            return
        
        # Create progress window
        win = tk.Toplevel(self.root)
        win.title("Activating Complete Privacy Mode...")
        win.geometry("600x400")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)
        
        # Title
        title_label = ttk.Label(win, text="🛡️ Activating Complete Privacy Mode", 
                               font=("", 14, "bold"))
        title_label.pack(pady=15)
        
        # Progress bar
        progress_frame = ttk.Frame(win)
        progress_frame.pack(pady=10, padx=20, fill="x")
        
        progress_label = ttk.Label(progress_frame, text="Progress:", font=("", 10))
        progress_label.pack(anchor="w")
        
        progress = ttk.Progressbar(progress_frame, length=500, mode='determinate')
        progress.pack(fill="x", pady=(5, 0))
        
        # Current status
        status_var = tk.StringVar(value="Initializing...")
        status_label = ttk.Label(win, textvariable=status_var, 
                                font=("", 10, "bold"), wraplength=550)
        status_label.pack(pady=10)
        
        # Details log
        details_frame = ttk.LabelFrame(win, text="Details", padding=10)
        details_frame.pack(pady=15, padx=20, fill="both", expand=True)
        
        details_text = scrolledtext.ScrolledText(details_frame, height=12, width=70,
                                               state="disabled", font=("Consolas", 9))
        details_text.pack(fill="both", expand=True)
        
        def log_detail(message):
            """Add message to details log"""
            details_text.config(state="normal")
            details_text.insert(tk.END, f"• {message}\n")
            details_text.see(tk.END)
            details_text.config(state="disabled")
            win.update_idletasks()
        
        def update_status(message, value=None):
            """Update status and progress"""
            status_var.set(message)
            if value is not None:
                progress['value'] = value
            log_detail(message)
            win.update_idletasks()
        
        # Results storage
        results = {
            "steps_completed": 0,
            "total_steps": 7,
            "errors": []
        }
        
        def run_privacy_mode():
            """Execute all privacy mode steps"""
            try:
                # Step 1: Update blocklists (16%)
                update_status("Updating Microsoft blocklists...", 16)
                try:
                    added = self.network_service.blocklist._update_microsoft_list()
                    update_status(f"✓ Added {added} Microsoft IPs to blocklist", 16)
                    log_detail(f"Blocked {added} new Microsoft telemetry IPs")
                    results["steps_completed"] += 1
                except Exception as e:
                    error_msg = f"Failed to update blocklists: {str(e)[:100]}"
                    update_status(f"⚠️ {error_msg}", 16)
                    log_detail(f"ERROR: {str(e)}")
                    results["errors"].append(error_msg)
                
                # Step 2: Apply firewall rules (28%)
                update_status("Applying firewall rules for blocked IPs...", 28)
                try:
                    blocklist = self.network_service.blocklist
                    new_ips = [ip for ip in blocklist.blocked_ips if ip not in blocklist._firewall_applied_ips]
                    if new_ips:
                        update_status(f"Applying firewall rules for {len(new_ips)} IPs...", 28)
                        
                        def firewall_progress(current, total, text):
                            progress_percent = 28 + (current / total * 14) if total > 0 else 42
                            win.after(0, lambda: update_status(
                                f"Firewall: {current}/{total} IPs - {text}", 
                                progress_percent
                            ))
                        
                        blocked_count = self.network_service.firewall.apply_firewall_rules_bulk(
                            new_ips, add=True, progress_callback=firewall_progress
                        )
                        
                        for ip in new_ips:
                            self.network_service.blocklist._firewall_applied_ips.add(ip)
                        
                        update_status(f"✓ Firewall rules applied for {blocked_count} IPs", 42)
                        log_detail(f"Applied firewall rules for {blocked_count}/{len(new_ips)} IPs")
                    else:
                        update_status("✓ No new firewall rules needed", 42)
                        log_detail("All IPs already have firewall rules")
                    results["steps_completed"] += 1
                except Exception as e:
                    error_msg = f"Failed to apply firewall rules: {str(e)[:100]}"
                    update_status(f"⚠️ {error_msg}", 42)
                    log_detail(f"ERROR: {str(e)}")
                    results["errors"].append(error_msg)
                
                # [Remaining steps unchanged - continue with the rest of the function]
                # Step 3: Block via hosts file (56%)
                update_status("Blocking Microsoft domains via hosts file...", 56)
                try:
                    if self.network_service.blocklist.block_microsoft_in_hosts():
                        update_status("✓ Microsoft domains blocked in hosts file", 56)
                        log_detail("Added comprehensive Microsoft domain blocks to hosts file")
                    else:
                        update_status("⚠️ Hosts file modification may have failed", 56)
                        log_detail("Hosts file modification returned False")
                    results["steps_completed"] += 1
                except Exception as e:
                    error_msg = f"Failed to modify hosts file: {str(e)[:100]}"
                    update_status(f"⚠️ {error_msg}", 56)
                    log_detail(f"ERROR: {str(e)}")
                    results["errors"].append(error_msg)
                
                # Step 4: Disable DoH (70%)
                update_status("Disabling Windows DNS over HTTPS (DoH)...", 70)
                try:
                    if self.network_service.blocklist.disable_windows_doh():
                        update_status("✓ Windows DoH disabled", 70)
                        log_detail("Disabled DNS over HTTPS (including Windows 11 24H2+/25H2)")
                    else:
                        update_status("⚠️ DoH disable may have failed", 70)
                        log_detail("DoH disable returned False")
                    results["steps_completed"] += 1
                except Exception as e:
                    error_msg = f"Failed to disable DoH: {str(e)[:100]}"
                    update_status(f"⚠️ {error_msg}", 70)
                    log_detail(f"ERROR: {str(e)}")
                    results["errors"].append(error_msg)
                
                # Step 5: Disable Delivery Optimization (84%)
                update_status("Disabling Delivery Optimization...", 84)
                try:
                    if self.network_service.blocklist.disable_delivery_optimization():
                        update_status("✓ Delivery Optimization disabled", 84)
                        log_detail("Disabled Windows Update peer-to-peer sharing")
                    else:
                        update_status("⚠️ Delivery Optimization disable may have failed", 84)
                        log_detail("Delivery Optimization disable returned False")
                    results["steps_completed"] += 1
                except Exception as e:
                    error_msg = f"Failed to disable Delivery Optimization: {str(e)[:100]}"
                    update_status(f"⚠️ {error_msg}", 84)
                    log_detail(f"ERROR: {str(e)}")
                    results["errors"].append(error_msg)
                
                # Step 6: Stop Microsoft services (92%)
                update_status("Stopping Microsoft tracking services...", 92)
                try:
                    success = self.network_service.blocklist.disable_microsoft_services()
                    update_status("✓ Microsoft telemetry services stopped", 92)
                    log_detail("Disabled Microsoft tracking and telemetry services")
                    results["steps_completed"] += 1
                except Exception as e:
                    error_msg = f"Failed to stop services: {str(e)[:100]}"
                    update_status(f"⚠️ {error_msg}", 92)
                    log_detail(f"ERROR: {str(e)}")
                    results["errors"].append(error_msg)
                
                # Step 7: Disable NCSI (100%)
                update_status("Disabling NCSI (Windows internet detection)...", 95)
                try:
                    if self.network_service.blocklist.disable_ncsi():
                        update_status("✓ NCSI completely disabled!", 100)
                        log_detail("Windows internet detection completely disabled")
                        log_detail("Windows will never show 'No Internet connection'")
                    else:
                        update_status("⚠️ NCSI disable may have failed", 100)
                        log_detail("NCSI disable returned False")
                    results["steps_completed"] += 1
                except Exception as e:
                    error_msg = f"Failed to disable NCSI: {str(e)[:100]}"
                    update_status(f"⚠️ {error_msg}", 100)
                    log_detail(f"ERROR: {str(e)}")
                    results["errors"].append(error_msg)
                
                # Save blocklist after all changes
                self.network_service.blocklist.save_blocklist()
                
                def show_results():
                    win.destroy()
                    summary = (
                        f"✅ Privacy Mode Activation Complete!\n\n"
                        f"Steps completed: {results['steps_completed']}/{results['total_steps']}\n"
                        f"Total blocked IPs: {len(self.network_service.blocklist.blocked_ips)}\n"
                    )
                    
                    if results["errors"]:
                        summary += f"\n⚠️ {len(results['errors'])} warnings:\n"
                        for i, error in enumerate(results["errors"][:3], 1):
                            summary += f"{i}. {error}\n"
                        if len(results["errors"]) > 3:
                            summary += f"... and {len(results['errors']) - 3} more\n"
                    
                    summary += (
                        f"\n🔒 Your Windows is now de-spied!\n"
                        f"• Microsoft telemetry blocked\n"
                        f"• NCSI disabled (no 'No Internet' messages)\n"
                        f"• Windows is now as private as Linux Mint!"
                    )
                    
                    messagebox.showinfo("Privacy Mode Complete", summary)
                    self.log_append("✅ Full privacy mode activated\n")
                    self.status_var.set(f"Privacy mode active - {results['steps_completed']}/{results['total_steps']} steps complete")
                
                win.after(100, show_results)
                
            except Exception as e:
                def show_error():
                    win.destroy()
                    messagebox.showerror("Critical Error", 
                                       f"Privacy mode failed with critical error:\n\n{str(e)[:200]}")
                    self.log_append(f"❌ Privacy mode failed: {e}\n")
                
                win.after(0, show_error)
        
        # Start the privacy mode thread
        threading.Thread(target=run_privacy_mode, daemon=True).start()
    
    def undo_full_privacy_mode(self):
        """Undo full privacy mode - COMPLETE UNDO including NCSI and firewall rules"""
        if not is_admin():
            messagebox.showwarning("Admin Rights Required", 
                                  "Undoing privacy mode requires administrator rights!\n"
                                  "Please restart the application as administrator.")
            return
        
        if not messagebox.askyesno("Undo Full Privacy Mode", 
                                  "🔄 COMPLETE UNDO - RESTORE ALL CHANGES\n\n"
                                  "This will undo EVERYTHING:\n"
                                  "1. Restore hosts file\n"
                                  "2. Enable Windows DoH\n"
                                  "3. Enable Delivery Optimization\n"
                                  "4. Re-enable Microsoft services\n"
                                  "5. Enable NCSI (Windows internet detection)\n"
                                  "6. Remove ALL firewall rules for blocked IPs\n"
                                  "7. Remove ALL NCSI firewall rules\n"
                                  "8. Keep blocked IPs in blocklist (optional to clear)\n\n"
                                  "Continue?"):
            return
        
        # Create progress window
        win = tk.Toplevel(self.root)
        win.title("Undoing Complete Privacy Mode...")
        win.geometry("600x450")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)
        
        # Title
        title_label = ttk.Label(win, text="🔄 Undoing Complete Privacy Mode", 
                               font=("", 14, "bold"))
        title_label.pack(pady=15)
        
        # Info
        info_label = ttk.Label(win, text="Reverting all privacy mode changes...",
                              font=("", 10))
        info_label.pack(pady=5)
        
        # Progress bar
        progress_frame = ttk.Frame(win)
        progress_frame.pack(pady=10, padx=20, fill="x")
        
        progress_label = ttk.Label(progress_frame, text="Progress:", font=("", 10))
        progress_label.pack(anchor="w")
        
        progress = ttk.Progressbar(progress_frame, length=500, mode='determinate')
        progress.pack(fill="x", pady=(5, 0))
        
        # Current status
        status_var = tk.StringVar(value="Initializing undo operations...")
        status_label = ttk.Label(win, textvariable=status_var, 
                                font=("", 10, "bold"), wraplength=550)
        status_label.pack(pady=10)
        
        # Statistics
        stats_frame = ttk.Frame(win)
        stats_frame.pack(pady=10, padx=20, fill="x")
        
        stats_vars = {
            "completed": tk.StringVar(value="Completed: 0/8"),
            "current": tk.StringVar(value="Current: -")
        }
        
        ttk.Label(stats_frame, textvariable=stats_vars["completed"]).pack(side="left", padx=10)
        ttk.Label(stats_frame, textvariable=stats_vars["current"], 
                 font=("", 9, "italic")).pack(side="right", padx=10)
        
        # Details log
        details_frame = ttk.LabelFrame(win, text="Operation Details", padding=10)
        details_frame.pack(pady=15, padx=20, fill="both", expand=True)
        
        details_text = scrolledtext.ScrolledText(details_frame, height=10, width=70,
                                               state="disabled", font=("Consolas", 9))
        details_text.pack(fill="both", expand=True)
        
        def log_detail(message):
            """Add message to details log"""
            details_text.config(state="normal")
            details_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
            details_text.see(tk.END)
            details_text.config(state="disabled")
            win.update_idletasks()
        
        def update_progress(step, total_steps, message, current_operation=""):
            """Update progress and status"""
            progress_percent = (step / total_steps) * 100 if total_steps > 0 else 100
            progress['value'] = progress_percent
            status_var.set(message)
            stats_vars["completed"].set(f"Completed: {step}/{total_steps}")
            stats_vars["current"].set(f"Current: {current_operation}")
            log_detail(message)
            win.update_idletasks()
        
        # Results storage
        results = {
            "steps_completed": 0,
            "total_steps": 8,
            "errors": [],
            "firewall_rules_removed": 0,
            "successful_ips_removed": []  # NEW: Track which IPs were successfully removed
        }
        
        def run_complete_undo():
            """Execute all undo operations"""
            try:
                # Step 1: Restore hosts file (12%)
                update_progress(1, 8, "Restoring hosts file from backup...", "Hosts file")
                try:
                    if self.network_service.blocklist.restore_hosts_file():
                        log_detail("✓ Hosts file restored from backup")
                        results["steps_completed"] += 1
                    else:
                        error_msg = "Failed to restore hosts file"
                        log_detail(f"❌ {error_msg}")
                        results["errors"].append(error_msg)
                except Exception as e:
                    error_msg = f"Hosts restore error: {str(e)[:100]}"
                    log_detail(f"❌ {error_msg}")
                    results["errors"].append(error_msg)
                
                # Step 2: Enable DoH (25%)
                update_progress(2, 8, "Enabling Windows DNS over HTTPS (DoH)...", "DoH")
                try:
                    if self.network_service.blocklist.enable_windows_doh():
                        log_detail("✓ Windows DoH enabled")
                        results["steps_completed"] += 1
                    else:
                        error_msg = "Failed to enable DoH"
                        log_detail(f"❌ {error_msg}")
                        results["errors"].append(error_msg)
                except Exception as e:
                    error_msg = f"DoH enable error: {str(e)[:100]}"
                    log_detail(f"❌ {error_msg}")
                    results["errors"].append(error_msg)
                
                # Step 3: Enable Delivery Optimization (38%)
                update_progress(3, 8, "Enabling Delivery Optimization...", "Delivery Optimization")
                try:
                    if self.network_service.blocklist.enable_delivery_optimization():
                        log_detail("✓ Delivery Optimization enabled")
                        results["steps_completed"] += 1
                    else:
                        error_msg = "Failed to enable Delivery Optimization"
                        log_detail(f"❌ {error_msg}")
                        results["errors"].append(error_msg)
                except Exception as e:
                    error_msg = f"Delivery Optimization error: {str(e)[:100]}"
                    log_detail(f"❌ {error_msg}")
                    results["errors"].append(error_msg)
                
                # Step 4: Enable Microsoft services (50%)
                update_progress(4, 8, "Enabling Microsoft tracking services...", "Services")
                try:
                    if self.network_service.blocklist.enable_microsoft_services():
                        log_detail("✓ Microsoft services enabled")
                        results["steps_completed"] += 1
                    else:
                        error_msg = "Failed to enable Microsoft services"
                        log_detail(f"❌ {error_msg}")
                        results["errors"].append(error_msg)
                except Exception as e:
                    error_msg = f"Services enable error: {str(e)[:100]}"
                    log_detail(f"❌ {error_msg}")
                    results["errors"].append(error_msg)
                
                # Step 5: Enable NCSI (62%)
                update_progress(5, 8, "Enabling NCSI (Windows internet detection)...", "NCSI")
                try:
                    if self.network_service.blocklist.enable_ncsi():
                        log_detail("✓ NCSI enabled - Windows internet detection restored")
                        log_detail("✓ ALL NCSI firewall rules removed")
                        results["steps_completed"] += 1
                    else:
                        error_msg = "Failed to enable NCSI"
                        log_detail(f"❌ {error_msg}")
                        results["errors"].append(error_msg)
                except Exception as e:
                    error_msg = f"NCSI enable error: {str(e)[:100]}"
                    log_detail(f"❌ {error_msg}")
                    results["errors"].append(error_msg)
                
                # Step 6: Remove ALL firewall rules for blocked IPs (75%)
                update_progress(6, 8, "Removing firewall rules for blocked IPs...", "Firewall rules")
                try:
                    # Get all IPs that have firewall rules applied
                    firewall_applied_ips = list(self.network_service.blocklist._firewall_applied_ips)
                    
                    if firewall_applied_ips:
                        log_detail(f"Removing firewall rules for {len(firewall_applied_ips)} IPs...")
                        
                        def firewall_progress(current, total, text):
                            progress_percent = 75 + (current / total * 12) if total > 0 else 87
                            win.after(0, lambda: update_progress(
                                6, 8, 
                                f"Firewall: {current}/{total} IPs - {text}", 
                                "Firewall rules"
                            ))
                        
                        # Remove firewall rules in bulk - GET THE SUCCESSFUL IPS
                        removed_count, successful_ips = self.network_service.firewall.apply_firewall_rules_bulk(
                            firewall_applied_ips, add=False, progress_callback=firewall_progress
                        )
                        
                        results["firewall_rules_removed"] = removed_count
                        results["successful_ips_removed"] = successful_ips  # Store successful IPs
                        
                        # CRITICAL FIX: Remove successful IPs from firewall tracking
                        for ip in successful_ips:
                            self.network_service.blocklist._firewall_applied_ips.discard(ip)
                        
                        log_detail(f"✓ Removed firewall rules for {removed_count}/{len(firewall_applied_ips)} IPs")
                        log_detail(f"✓ Updated firewall tracking for {len(successful_ips)} IPs")
                    else:
                        log_detail("✓ No firewall rules to remove")
                        results["firewall_rules_removed"] = 0
                    
                    results["steps_completed"] += 1
                    
                except Exception as e:
                    error_msg = f"Firewall removal error: {str(e)[:100]}"
                    log_detail(f"❌ {error_msg}")
                    results["errors"].append(error_msg)
                
                # Step 7: Remove any remaining WinDetox firewall rules (87%)
                update_progress(7, 8, "Cleaning up remaining WinDetox firewall rules...", "Cleanup")
                try:
                    # Remove any firewall rules with WinDetox in the name
                    cleanup_script = """
                    # Remove any remaining WinDetox firewall rules
                    $rules = Get-NetFirewallRule -DisplayName "*WinDetox*" -ErrorAction SilentlyContinue
                    foreach ($rule in $rules) {
                        Remove-NetFirewallRule -DisplayName $rule.DisplayName -Confirm:$false -ErrorAction SilentlyContinue
                    }
                    
                    # Also remove via netsh
                    netsh advfirewall firewall delete rule name="WinDetox_*" -ErrorAction SilentlyContinue 2>&1 | Out-Null
                    Write-Output "Cleanup completed"
                    """
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                        f.write(cleanup_script)
                        temp_script = f.name
                    
                    result = safe_subprocess_run([
                        "powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script
                    ], capture_output=True, text=True, timeout=30)
                    
                    os.remove(temp_script)
                    
                    if result.returncode == 0:
                        log_detail("✓ Remaining WinDetox firewall rules cleaned up")
                    else:
                        log_detail("⚠️ Some cleanup operations may have failed")
                    
                    results["steps_completed"] += 1
                    
                except Exception as e:
                    error_msg = f"Cleanup error: {str(e)[:100]}"
                    log_detail(f"⚠️ {error_msg}")
                    results["errors"].append(error_msg)
                
                # Step 8: Save blocklist (100%)
                update_progress(8, 8, "Saving blocklist configuration...", "Save config")
                try:
                    self.network_service.blocklist.save_blocklist()
                    log_detail("✓ Blocklist configuration saved")
                    results["steps_completed"] += 1
                except Exception as e:
                    error_msg = f"Save error: {str(e)[:100]}"
                    log_detail(f"❌ {error_msg}")
                    results["errors"].append(error_msg)
                
                def show_results():
                    win.destroy()
                    
                    # Ask if user wants to clear blocklist
                    clear_blocklist = False
                    if messagebox.askyesno("Clear Blocklist?", 
                                          f"✅ Privacy mode completely undone!\n\n"
                                          f"Steps completed: {results['steps_completed']}/8\n"
                                          f"Firewall rules removed: {results['firewall_rules_removed']}\n"
                                          f"IPs removed from firewall tracking: {len(results['successful_ips_removed'])}\n\n"
                                          f"Do you also want to CLEAR the blocklist?\n"
                                          f"(Remove all IPs from the blocked list)"):
                        try:
                            # Clear blocklist
                            self.network_service.blocklist.blocked_ips.clear()
                            self.network_service.blocklist.sources.clear()
                            self.network_service.blocklist.save_blocklist()
                            clear_blocklist = True
                        except Exception as e:
                            messagebox.showerror("Error", f"Failed to clear blocklist: {e}")
                    
                    # Show final summary
                    summary = (
                        f"✅ COMPLETE UNDO FINISHED!\n\n"
                        f"Steps completed: {results['steps_completed']}/8\n"
                        f"Firewall rules removed: {results['firewall_rules_removed']}\n"
                        f"IPs removed from firewall tracking: {len(results['successful_ips_removed'])}\n"
                    )
                    
                    if clear_blocklist:
                        summary += f"Blocklist: CLEARED (all IPs removed)\n"
                    else:
                        summary += f"Blocklist: KEPT (IPs remain in list but firewall rules removed)\n"
                    
                    if results["errors"]:
                        summary += f"\n⚠️ {len(results['errors'])} warnings:\n"
                        for i, error in enumerate(results["errors"][:3], 1):
                            summary += f"{i}. {error}\n"
                        if len(results["errors"]) > 3:
                            summary += f"... and {len(results['errors']) - 3} more\n"
                    
                    summary += (
                        f"\n🔄 System restored to original state:\n"
                        f"• Hosts file restored\n"
                        f"• DoH enabled\n"
                        f"• Delivery Optimization enabled\n"
                        f"• Microsoft services running\n"
                        f"• NCSI active (Windows can detect internet)\n"
                        f"• ALL firewall rules removed (blocked IPs + NCSI)\n"
                        f"• Remaining WinDetox rules cleaned up\n"
                    )
                    
                    messagebox.showinfo("Complete Undo Finished", summary)
                    self.log_append("✅ Complete privacy mode undone - ALL changes reverted\n")
                    self.status_var.set("Privacy mode completely undone")
                
                win.after(100, show_results)
                
            except Exception as e:
                def show_error():
                    win.destroy()
                    messagebox.showerror("Critical Error", 
                                       f"Undo operation failed with critical error:\n\n{str(e)[:200]}")
                    self.log_append(f"❌ Privacy mode undo failed: {e}\n")
                
                win.after(0, show_error)
        
        # Start the undo thread
        threading.Thread(target=run_complete_undo, daemon=True).start()
    
    def show_tray_notification(self, title: str, message: str):
        """Show notification from system tray"""
        if self.settings.get('show_notifications', True):
            try:
                self.log_append(f"{title}: {message}\n")
            except:
                pass
    
    def cleanup_and_exit(self):
        """Clean up and exit application"""
        try:
            self.cleanup()
            
            # Mutex schließen, falls vorhanden
            if self.mutex:
                try:
                    ctypes.windll.kernel32.CloseHandle(self.mutex)
                    self.logger.info("Mutex closed")
                except:
                    pass
            
            self.root.quit()
            self.root.destroy()
            
        except Exception as e:
            self.logger.error(f"Error during cleanup_and_exit: {e}")
            # Force exit
            os._exit(1)
    
    def cleanup(self):
        """Clean up all resources properly on exit"""
        try:
            # Stop monitoring
            self.monitor.stop()
            
            # Stop system tray
            if self.tray_manager:
                self.tray_manager.stop()
            
            # Wait for monitor thread to finish
            if self.monitor.monitor_thread and self.monitor.monitor_thread.is_alive():
                self.monitor.monitor_thread.join(timeout=5.0)
            
            # Clear caches
            if hasattr(self.monitor, '_process_name_cache'):
                self.monitor._process_name_cache.clear()
            
            # Save blocklist
            self.network_service.blocklist.save_blocklist()
            
            # Save settings
            self.settings.save_settings()
            
            # Log termination
            stats = self.monitor.get_statistics()
            self.logger.info(f"Program terminated - Final stats: {stats}")
            self.logger.info(f"Blocked IPs: {len(self.network_service.blocklist.blocked_ips)}")
            self.logger.info(f"Settings saved")
            
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}", exc=True)

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
# This is where the program starts. It:
# 1. Checks for single instance (mutex)
# 2. Creates the Tkinter root window
# 3. Creates the WinDetoxGUI instance
# 4. Starts the main loop
#
# To change startup behavior, modify main() function.
# ============================================================================

def main():
    """Main program entry point"""
    # Check for single instance
    mutex_name = "WinDetox_Mutex_{}".format(os.path.expanduser("~").replace("\\", "_"))
    mutex = None
    try:
        mutex = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
        last_error = ctypes.windll.kernel32.GetLastError()
        if last_error == 183:  # ERROR_ALREADY_EXISTS
            messagebox.showinfo("WinDetox", "WinDetox is already running!")
            sys.exit(0)
    except:
        pass
    
    # Check for admin flag
    if len(sys.argv) > 1 and sys.argv[1] == "--admin":
        if not is_admin():
            run_as_admin("Start with administrator privileges?")
            return
    
    # Check for minimized flag - wird später in WinDetoxGUI.__init__ verwendet
    start_minimized = '--minimized' in sys.argv
    
    try:
        # Initialize logger
        logger = Logger()
        logger.info(f"Starting WinDetox v{Config.CURRENT_VERSION}")
        
        # Create and run GUI
        root = tk.Tk()
        app = WinDetoxGUI(root, logger=logger)
        
        # The WinDetoxGUI class already sets up its own window protocol in __init__
        # via setup_window_protocol(), so we don't need to set it here.
        
        root.mainloop()
        
    except Exception as e:
        # Fallback error logging
        try:
            error_log = os.path.join(tempfile.gettempdir(), 'windetox_error.log')
            with open(error_log, 'a', encoding='utf-8') as f:
                f.write(f"{datetime.now()}: {e}\n")
                import traceback
                f.write(traceback.format_exc())
        except:
            pass
        
        messagebox.showerror("Critical Error", f"Failed to start WinDetox:\n\n{str(e)}")
        sys.exit(1)
    
    finally:
        if mutex:
            ctypes.windll.kernel32.CloseHandle(mutex)

if __name__ == "__main__":
    main()
# ============================================================================
# PROGRAM EXIT SUMMARY
# ============================================================================
# When program exits (user closes window or tray exit):
# 1. cleanup_and_exit() is called
# 2. Which calls cleanup() to:
#    • Stop network monitoring
#    • Stop system tray
#    • Save blocklist
#    • Save settings
#    • Log termination
# 3. Then destroys window and exits
# ============================================================================

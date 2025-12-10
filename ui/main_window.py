"""
main_window.py - Main GUI Window for WinDetox
Corrected version with proper imports and indentation
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Menu, filedialog
import os
import sys
import threading
import time
import atexit
import ctypes
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

# Import required modules (CORRECTED PATHS)
from core.logger import Logger
from core.config import Config
from core.utils import is_admin, run_as_admin, is_local_ip, safe_subprocess_run
from core.exceptions import (
    WinDetoxError, SecurityError, ValidationError, FirewallError, 
    BlocklistError, UpdateError, PermissionError, DetailedError
)
from managers.settings_manager import SettingsManager
from managers.update_manager import UpdateManager
from network.network_service import NetworkService
from network.network_monitor import NetworkMonitor, ConnectionInfo
from network.blocklist_manager import BlocklistManager
from network.firewall_manager import FirewallManager
from ui.system_tray import SystemTrayManager


class WinDetoxGUI:
    """
    MAIN GUI CLASS - COORDINATES EVERYTHING
    
    This class is extended by the following modules:
    - ui/tabs/connections_tab.py
    - ui/tabs/blocklist_tab.py  
    - ui/tabs/settings_tab.py
    - ui/dialogs/progress_dialog.py
    """
    
    def __init__(self, root: tk.Tk, 
                 logger: Logger = None,
                 network_service: NetworkService = None,
                 settings_manager: SettingsManager = None,
                 update_manager: UpdateManager = None):
        """
        INITIALIZATION - SETS UP ALL COMPONENTS
        """
        
        self.root = root
        self.root.title(f"{Config.WINDOW_TITLE} v{Config.CURRENT_VERSION}")
        self.root.geometry(Config.WINDOW_GEOMETRY)
        self.mutex = None
        
        # Initialize logger FIRST (before other operations)
        self.logger = logger or Logger()
        
        # Icon setup
        try:
            if getattr(sys, 'frozen', False):
                base_path = os.path.dirname(sys.executable)
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))
            
            icon_paths = [
                os.path.join(base_path, 'icon.ico'),
                os.path.join(os.path.dirname(base_path), 'icon.ico'),
                os.path.join(os.getcwd(), 'icon.ico'),
                'icon.ico'
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
        self.start_minimized = '--minimized' in sys.argv
        
        # System tray manager
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
        
        # IMPORTANT: Initialize system tray with delay
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
        
        self._pending_tree_updates: List[ConnectionInfo] = []
        self._update_scheduled = False
        
        # Cleanup on exit
        atexit.register(self.cleanup)
    
    def setup_gui(self):
        """
        GUI CONSTRUCTION - WHERE ALL WIDGETS ARE CREATED
        
        This method will be implemented in the full version.
        The actual GUI will be imported from tab modules.
        """
        # This method will be extended by imports from tab modules
        pass
    
    # More methods will be imported from modules
    # See: ui/tabs/connections_tab.py, ui/tabs/blocklist_tab.py, etc.

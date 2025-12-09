"""
System Tray Manager Module for WinDetox
Version: 1.0
Description: Manages system tray icon and functionality
"""

import threading
import os
import sys
import tkinter as tk
import time
from typing import Optional, Callable

# System Tray Icon
import pystray
from PIL import Image, ImageDraw

from core.logger import Logger


class SystemTrayManager:
    """Manages system tray icon and functionality"""
    
    def __init__(self, root, gui_instance):
        self.root = root
        self.gui = gui_instance
        self.icon = None
        self.tray_thread = None
        self.running = False
        self.tray_menu = None
        self._stop_event = threading.Event()
        self._is_exiting = False  # Flag to prevent multiple exit calls
    
    def _get_icon_path(self):
        """Get absolute path to icon.ico - works for both script and frozen exe"""
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            base_path = os.path.dirname(sys.executable)
        else:
            # Running as Python script
            base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Try multiple possible locations
        possible_paths = [
            os.path.join(base_path, 'icon.ico'),
            os.path.join(os.path.dirname(base_path), 'icon.ico'),
            os.path.join(os.getcwd(), 'icon.ico'),
            'icon.ico'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                self.gui.logger.debug(f"Found icon at: {path}")
                return path
        
        self.gui.logger.debug("No icon.ico found in any location")
        return None
    
    def create_tray_icon(self):
        """Create system tray icon with proper icon loading"""
        try:
            # Get absolute path to icon
            icon_path = self._get_icon_path()
            
            if icon_path and os.path.exists(icon_path):
                try:
                    # Open and convert .ico to PIL Image
                    image = Image.open(icon_path)
                    
                    # Resize to appropriate tray icon size
                    image.thumbnail((64, 64), Image.Resampling.LANCZOS)
                    
                    # Convert to RGBA for transparency
                    if image.mode != 'RGBA':
                        image = image.convert('RGBA')
                    
                    self.gui.logger.info(f"Successfully loaded icon from: {icon_path}")
                    
                except Exception as e:
                    self.gui.logger.warning(f"Failed to load icon from {icon_path}: {e}")
                    image = self._create_fallback_icon()
            else:
                self.gui.logger.info("Using fallback icon (no icon.ico found)")
                image = self._create_fallback_icon()
            
            # Create menu
            self.update_tray_menu()
            
            # Create icon with all positional arguments
            self.icon = pystray.Icon(
                "windetox",
                image,
                "WinDetox",
                self.tray_menu
            )
            
            # Hide window if start minimized is enabled
            if self.gui.settings.get('start_minimized', False):
                self.root.withdraw()
            
            self.running = True
            
            # Run icon in separate thread
            self.tray_thread = threading.Thread(target=self._run_tray, daemon=True)
            self.tray_thread.start()
            
            self.gui.logger.info("System tray icon created")
            return True
            
        except Exception as e:
            self.gui.logger.error(f"Failed to create system tray icon: {e}")
            
            # Simple fallback without menu parameter issues
            try:
                image = self._create_fallback_icon()
                self.update_tray_menu()
                
                # Simple fallback without complex parameters
                self.icon = pystray.Icon("windetox", image, "WinDetox", self.tray_menu)
                
                # Run in separate thread
                self.tray_thread = threading.Thread(target=self._run_tray, daemon=True)
                self.tray_thread.start()
                
                return True
            except Exception as e2:
                self.gui.logger.error(f"Even fallback tray icon failed: {e2}")
                return False
    
    def _create_fallback_icon(self):
        """Create a simple fallback icon when icon.ico is not available"""
        image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        
        # Draw shield icon
        draw.ellipse([12, 12, 52, 52], outline='blue', width=3, fill='lightblue')
        draw.line([32, 20, 32, 44], fill='blue', width=3)
        draw.line([20, 32, 44, 32], fill='blue', width=3)
        draw.line([25, 27, 39, 41], fill='red', width=2)
        
        return image
    
    def _run_tray(self):
        """Run tray icon with proper error handling and clean shutdown"""
        try:
            if self.icon:
                self.icon.run()
        except Exception as e:
            if not self._is_exiting:  # Only log if not exiting normally
                self.gui.logger.error(f"Tray icon thread error: {e}")
        finally:
            self.running = False

    def update_or_create_tray_icon(self):
        """Update existing tray icon or create new one"""
        if self.icon and hasattr(self.icon, 'visible') and self.icon.visible:
            # Icon already exists and is visible
            return True
        
        # Try to create new icon
        return self.create_tray_icon()
    
    def update_tray_menu(self):
        """Update tray menu based on current monitoring status"""
        is_monitoring = self.gui.monitor.is_running
        
        # Create dynamic menu
        self.tray_menu = pystray.Menu(
            pystray.MenuItem("Show Window", self.show_window),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Start Monitoring", self.start_monitoring, 
                           enabled=not is_monitoring),
            pystray.MenuItem("Stop Monitoring", self.stop_monitoring,
                           enabled=is_monitoring),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self.exit_application)
        )
        
        # Update icon if it exists
        if self.icon:
            self.icon.menu = self.tray_menu
    
    def show_window(self, icon=None, item=None):
        """Show main window from system tray"""
        # Tkinter operations must be in the main thread
        self.root.after(0, self._show_window_callback)

    def _show_window_callback(self):
        """Callback to show window from main thread"""
        try:
            self.root.deiconify()  # Make window visible
            self.root.state('normal')  # Normal mode (not minimized)
            self.root.lift()  # Bring to front
            self.root.focus_force()  # Set focus
        except Exception as e:
            self.gui.logger.error(f"Error showing window: {e}")
    
    def start_monitoring(self, icon=None, item=None):
        """Start monitoring from system tray"""
        self.root.after(0, self._start_monitoring_callback)
    
    def _start_monitoring_callback(self):
        """Callback to start monitoring from main thread"""
        self.gui.start_monitoring()
        self.update_tray_menu()
    
    def stop_monitoring(self, icon=None, item=None):
        """Stop monitoring from system tray"""
        self.root.after(0, self._stop_monitoring_callback)
    
    def _stop_monitoring_callback(self):
        """Callback to stop monitoring from main thread"""
        self.gui.stop_monitoring()
        self.update_tray_menu()
    
    def exit_application(self, icon=None, item=None):
        """Exit application from system tray - SINGLE ENTRY POINT"""
        if self._is_exiting:
            return  # Prevent multiple exit calls
            
        self._is_exiting = True
        self.gui.logger.info("Exit requested from system tray")
        
        # Schedule cleanup in main thread
        self.root.after(0, self._exit_callback)
    
    def _exit_callback(self):
        """Callback to exit from main thread"""
        try:
            # Stop the tray icon first
            self.stop()
            
            # Then call the GUI cleanup
            self.gui.cleanup_and_exit()
        except Exception as e:
            self.gui.logger.error(f"Error during exit: {e}")
            # Force exit if something goes wrong
            os._exit(1)
    
    def stop(self):
        """Stop system tray icon - CRITICAL: Proper cleanup to prevent hanging icons"""
        self.running = False
        
        if self.icon:
            try:
                # First make icon invisible
                if hasattr(self.icon, 'visible'):
                    self.icon.visible = False
                
                # Stop the icon - this triggers the tray thread to exit
                self.icon.stop()
                
                # Give it a moment to clean up
                time.sleep(0.1)
                
                # Remove the icon reference
                self.icon = None
                
                self.gui.logger.info("System tray icon stopped and cleaned up")
                
            except Exception as e:
                self.gui.logger.error(f"Error stopping tray icon: {e}")
        
        # Wait for tray thread to finish
        if self.tray_thread and self.tray_thread.is_alive():
            try:
                # Give the thread time to exit gracefully
                self.tray_thread.join(timeout=2.0)
                
                if self.tray_thread.is_alive():
                    self.gui.logger.warning("Tray thread did not exit gracefully")
            except Exception as e:
                self.gui.logger.error(f"Error joining tray thread: {e}")

# settings_manager.py
"""
Settings management for WinDetox
"""
import os
import json
import sys
import winreg
import subprocess
import tempfile
from typing import Any, Tuple
from core.config import Config
from core.utils import is_admin
from core.exceptions import BlocklistError, PermissionError

class SettingsManager:
    """Manages application settings"""
    
    def __init__(self, settings_file: str = None, gui_instance=None):
        self.settings_file = settings_file or Config.SETTINGS_FILE
        self.gui = gui_instance
        self._ensure_settings_directory()
        self.settings = {
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
        self.load_settings()
    
    def _ensure_settings_directory(self):
        """Ensure the settings directory exists"""
        settings_dir = os.path.dirname(self.settings_file)
        if not os.path.exists(settings_dir):
            os.makedirs(settings_dir, exist_ok=True)
    
    def load_settings(self):
        """Load settings from JSON file"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    self.settings.update(loaded)
            except Exception as e:
                raise BlocklistError(f"Failed to load settings: {e}")
    
    def save_settings(self):
        """Save settings to JSON file"""
        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2, default=str)
        except Exception as e:
            raise BlocklistError(f"Failed to save settings: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a setting value"""
        return self.settings.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set a setting value"""
        self.settings[key] = value
        self.save_settings()
    
    def set_autostart_all_users(self, enable: bool) -> bool:
        """Enable or disable autostart for all users (requires admin)"""
        if not is_admin():
            raise PermissionError("Admin rights required to set autostart for all users")
        
        try:
            if enable:
                # Primary method: schtasks (most reliable)
                try:
                    self._create_schtasks_autostart()
                    if self.gui:
                        self.gui.logger.info("Autostart via schtasks created successfully")
                except Exception as e:
                    if self.gui:
                        self.gui.logger.error(f"schtasks failed: {e}")
                    # Fallback: Registry method
                    self._set_registry_autostart(True)
            else:
                # Disable both methods
                try:
                    self._remove_schtasks_autostart()
                except:
                    pass
                self._set_registry_autostart(False)
            
            self.set('autostart_all_users', enable)
            return True
            
        except Exception as e:
            if self.gui:
                self.gui.logger.error(f"Failed to set autostart: {e}")
            return False

    def _create_schtasks_autostart(self):
        """Create scheduled task using schtasks.exe (most reliable method)"""
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
            args = '--minimized --admin'
        else:
            exe_path = sys.executable
            script_path = os.path.abspath(sys.argv[0])
            args = f'"{script_path}" --minimized --admin'
        
        # Build schtasks command
        cmd = [
            'schtasks.exe', '/create', '/f',
            '/tn', 'WinDetox_Autostart',
            '/tr', f'"{exe_path}" {args}',
            '/sc', 'onlogon',
            '/rl', 'HIGHEST',
            '/delay', '0000:30'
        ]
        
        # Execute without visible window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=15
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            raise Exception(f"schtasks failed: {error_msg}")

    def _remove_schtasks_autostart(self):
        """Remove scheduled task using schtasks.exe"""
        cmd = ['schtasks.exe', '/delete', '/tn', 'WinDetox_Autostart', '/f']
        
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=10
        )

    def _set_registry_autostart(self, enable: bool):
        """Set/remove Registry entry (fallback method)"""
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
            command = f'"{exe_path}" --minimized --admin'
        else:
            exe_path = sys.executable
            script_path = os.path.abspath(sys.argv[0])
            command = f'"{exe_path}" "{script_path}" --minimized --admin'
        
        if enable:
            # Set in HKLM (all users)
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    Config.AUTOSTART_REGISTRY_PATH,
                    0, winreg.KEY_ALL_ACCESS
                )
                winreg.SetValueEx(key, Config.AUTOSTART_REGISTRY_NAME, 0, 
                                winreg.REG_SZ, command)
                winreg.CloseKey(key)
            except Exception:
                pass
            
            # Set in HKCU (current user)
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    Config.AUTOSTART_REGISTRY_PATH,
                    0, winreg.KEY_ALL_ACCESS
                )
                winreg.SetValueEx(key, Config.AUTOSTART_REGISTRY_NAME, 0, 
                                winreg.REG_SZ, command)
                winreg.CloseKey(key)
            except Exception:
                pass
        else:
            # Remove from HKLM
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    Config.AUTOSTART_REGISTRY_PATH,
                    0, winreg.KEY_ALL_ACCESS
                )
                winreg.DeleteValue(key, Config.AUTOSTART_REGISTRY_NAME)
                winreg.CloseKey(key)
            except WindowsError:
                pass
            
            # Remove from HKCU
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    Config.AUTOSTART_REGISTRY_PATH,
                    0, winreg.KEY_ALL_ACCESS
                )
                winreg.DeleteValue(key, Config.AUTOSTART_REGISTRY_NAME)
                winreg.CloseKey(key)
            except WindowsError:
                pass

    def _check_schtasks_exists(self) -> bool:
        """Check if schtasks autostart exists"""
        cmd = ['schtasks.exe', '/query', '/tn', 'WinDetox_Autostart']
        
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=5
        )
        
        return result.returncode == 0

    def _check_registry_exists(self) -> Tuple[bool, bool]:
        """Check if registry autostart exists (HKLM, HKCU)"""
        hklm_exists = False
        hkcu_exists = False
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                Config.AUTOSTART_REGISTRY_PATH,
                0, winreg.KEY_READ
            )
            try:
                winreg.QueryValueEx(key, Config.AUTOSTART_REGISTRY_NAME)
                hklm_exists = True
            except WindowsError:
                hklm_exists = False
            finally:
                winreg.CloseKey(key)
        except:
            hklm_exists = False
        
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                Config.AUTOSTART_REGISTRY_PATH,
                0, winreg.KEY_READ
            )
            try:
                winreg.QueryValueEx(key, Config.AUTOSTART_REGISTRY_NAME)
                hkcu_exists = True
            except WindowsError:
                hkcu_exists = False
            finally:
                winreg.CloseKey(key)
        except:
            hkcu_exists = False
        
        return hklm_exists, hkcu_exists
    
    def check_autostart_status(self) -> Tuple[bool, bool]:
        """
        Check if autostart is enabled
        Returns: (schtasks_exists, registry_exists)
        """
        schtasks_exists = self._check_schtasks_exists()
        registry_hklm, registry_hkcu = self._check_registry_exists()
        registry_exists = registry_hklm or registry_hkcu
        
        return schtasks_exists, registry_exists

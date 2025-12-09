# utils.py
"""
Utility functions for WinDetox
"""
import os
import sys
import ctypes
import ipaddress
import re
import subprocess
import hashlib
import time
import tempfile
import shutil
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime
from tkinter import messagebox
import tkinter as tk

# Import from our modules
from core.exceptions import ValidationError, FirewallError, SecurityError, PermissionError
from core.config import Config

# WICHTIG: Logger wird lazy importiert, um zirkuläre Abhängigkeiten zu vermeiden
def _get_logger():
    """Lazy import of Logger to avoid circular dependencies"""
    from core.logger import Logger
    return Logger()

def is_admin() -> bool:
    """Check if the program is running as administrator"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def run_as_admin(confirm_message: str = None) -> bool:
    """Restart the program with administrator privileges with proper cleanup"""
    if is_admin():
        return True
    
    if confirm_message is None:
        confirm_message = (
            "This operation requires administrator privileges.\n\n"
            "The application will restart with elevated permissions.\n\n"
            "Continue?"
        )
    
    if messagebox.askyesno("Administrator Rights Required", confirm_message):
        try:
            # Get the current executable path
            if getattr(sys, 'frozen', False):
                # Running as compiled executable
                exe_path = sys.executable
            else:
                # Running as script
                exe_path = sys.executable
                script_path = os.path.abspath(sys.argv[0])
                exe_path = f'"{exe_path}" "{script_path}"'
            
            # Close current instance before starting new one
            root = tk.Tk()
            root.withdraw()
            root.quit()
            root.destroy()
            
            # Restart with admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            
            # Exit current instance
            os._exit(0)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restart as administrator: {e}")
            return False
    return False


def is_local_ip(ip: str) -> bool:
    """Check if IP address is in local range using ipaddress for performance"""
    if not ip or ip in ('', '0.0.0.0', '::1', '::'):
        return True
    
    if ':' in ip:  # IPv6
        return True
    
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in network for network in Config.LOCAL_NETWORKS)
    except ValueError:
        return True


def get_hosts_backup_path() -> str:
    """Get safe backup path for hosts file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize filename
    safe_timestamp = re.sub(r'[^a-zA-Z0-9_]', '', timestamp)
    filename = f"hosts_backup_{safe_timestamp}"
    return os.path.join(Config.HOSTS_BACKUP_DIR, filename)


def safe_subprocess_run(cmd: List[str], max_retries: int = 1, retry_delay: float = 0.5, **kwargs) -> subprocess.CompletedProcess:
    """Safely run subprocess commands with validation, timeout, and retry logic"""
    
    # Validate command
    if not cmd or not isinstance(cmd, list):
        raise ValidationError("Command must be a non-empty list")
    
    # Ensure all arguments are strings
    try:
        cmd = [str(arg) for arg in cmd]
    except Exception as e:
        raise ValidationError(f"Cannot convert command to strings: {e}")
    
    # Validate executable
    executable = cmd[0]
    allowed_executables = [
        'netsh', 'netsh.exe',
        'ipconfig', 'ipconfig.exe',
        'powershell', 'powershell.exe',
        'sc', 'sc.exe',
        'net', 'net.exe',
        'reg', 'reg.exe'
    ]
    
    if not any(executable.lower().endswith(allowed) for allowed in allowed_executables):
        raise ValidationError(f"Executable not allowed: {executable}")
    
    # Set safe defaults
    if 'timeout' not in kwargs:
        kwargs['timeout'] = 30  # Default 30 seconds
    
    if 'creationflags' not in kwargs:
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    
    if 'encoding' not in kwargs:
        kwargs['encoding'] = 'utf-8'
        kwargs['errors'] = 'ignore'
    
    # Security: Never use shell=True
    if kwargs.get('shell', False):
        raise ValidationError("shell=True is not allowed for security reasons")
    
    # Retry logic
    last_exception = None
    for attempt in range(max_retries):
        try:
            result = subprocess.run(cmd, **kwargs)
            
            # Log command execution for audit (lazy import)
            if result.returncode != 0:
                try:
                    logger = _get_logger()
                    logger.debug(f"Command {executable} returned code {result.returncode}")
                except:
                    pass  # Ignore logging errors
            
            return result
            
        except subprocess.TimeoutExpired as e:
            last_exception = e
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            else:
                raise FirewallError(f"Command timeout after {max_retries} attempts: {executable}")
        
        except PermissionError as e:
            # Don't retry permission errors
            raise PermissionError(f"Permission denied for command: {executable}")
        
        except FileNotFoundError as e:
            # Don't retry if executable not found
            raise FirewallError(f"Executable not found: {executable}")
        
        except Exception as e:
            last_exception = e
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            else:
                raise FirewallError(f"Failed to execute command after {max_retries} attempts: {e}")
    
    # Should never reach here, but just in case
    if last_exception:
        raise FirewallError(f"Command failed: {last_exception}")
    
    raise FirewallError("Unknown error in safe_subprocess_run")


def verify_file_signature(filepath: str, expected_hash: str) -> bool:
    """Verify file SHA256 signature"""
    try:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        
        actual_hash = sha256.hexdigest()
        return actual_hash == expected_hash.lower()
    except Exception as e:
        raise SecurityError(f"Failed to verify file signature: {e}")

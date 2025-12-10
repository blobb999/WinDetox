"""
Logger Module for WinDetox
Version: 1.0
Description: Thread-safe logging with rotation support
"""

import os
import logging
import threading
import tempfile
from datetime import datetime
from typing import Optional
import shutil

# Import from existing modules
from core.config import Config


class Logger:
    """Logger class with dependency injection support"""
    
    def __init__(self, log_file: str = None, level: int = logging.DEBUG):
        self.log_file = log_file or Config.LOG_FILE
        self.level = level
        self._lock = threading.RLock()  # Für Thread-Sicherheit
        self._ensure_log_directory()
        self._setup_logger()
    
    def _ensure_log_directory(self):
        """Ensure the log directory exists"""
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    def _setup_logger(self):
        """Setup logger configuration"""
        with self._lock:
            self.logger = logging.getLogger("WinDetox")
            self.logger.setLevel(self.level)
            self.logger.handlers.clear()

            # File handler
            try:
                fh = logging.FileHandler(self.log_file, encoding='utf-8')
                fh.setLevel(logging.DEBUG)
                fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                self.logger.addHandler(fh)
            except Exception as e:
                # Fallback to temporary directory if AppData fails
                temp_log = os.path.join(tempfile.gettempdir(), 'windetox.log')
                fh = logging.FileHandler(temp_log, encoding='utf-8')
                fh.setLevel(logging.DEBUG)
                fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                self.logger.addHandler(fh)

            # Console handler
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
            self.logger.addHandler(ch)
    
    def debug(self, msg):    
        with self._lock:
            self.logger.debug(msg)
    
    def info(self, msg):     
        with self._lock:
            self.logger.info(msg)
    
    def warning(self, msg):  
        with self._lock:
            self.logger.warning(msg)
    
    def error(self, msg, exc=False): 
        with self._lock:
            self.logger.error(msg, exc_info=exc)
    
    def critical(self, msg): 
        with self._lock:
            self.logger.critical(msg)


class RotatingLogger(Logger):
    """Logger with log rotation support"""
    
    def __init__(self, log_file: Optional[str] = None, max_size_mb: int = 10):
        super().__init__(log_file)
        self.max_size_mb = max_size_mb
        self._check_rotate()
    
    def _check_rotate(self):
        """Check if log needs rotation"""
        with self._lock:
            try:
                if os.path.exists(self.log_file):
                    size_mb = os.path.getsize(self.log_file) / (1024 * 1024)
                    if size_mb > self.max_size_mb:
                        self._rotate_log()
            except Exception as e:
                self.logger.debug(f"Log rotation check failed: {e}")
    
    def _rotate_log(self):
        """Rotate log file"""
        with self._lock:
            try:
                # Keep last 5 logs
                for i in range(4, -1, -1):
                    old = f"{self.log_file}.{i}" if i > 0 else self.log_file
                    new = f"{self.log_file}.{i+1}"
                    if os.path.exists(old):
                        if i == 4:
                            # Delete the oldest log
                            os.remove(old)
                        else:
                            # Move to next number
                            shutil.move(old, new)
                
                # Recreate the file handler after rotation
                self._recreate_file_handler()
            except Exception as e:
                self.logger.error(f"Log rotation failed: {e}")
    
    def _recreate_file_handler(self):
        """Recreate file handler after rotation"""
        with self._lock:
            try:
                # Remove existing file handler
                for handler in self.logger.handlers[:]:
                    if isinstance(handler, logging.FileHandler):
                        self.logger.removeHandler(handler)
                        handler.close()
                
                # Add new file handler
                file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
                file_handler.setLevel(logging.DEBUG)
                file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                file_handler.setFormatter(file_format)
                self.logger.addHandler(file_handler)
            except Exception as e:
                self.logger.error(f"Failed to recreate file handler: {e}")
    
    # Überschreibe die Log-Methoden um Rotation zu prüfen
    def debug(self, msg):
        self._check_rotate()
        super().debug(msg)
    
    def info(self, msg):
        self._check_rotate()
        super().info(msg)
    
    def warning(self, msg):
        self._check_rotate()
        super().warning(msg)
    
    def error(self, msg, exc=False):
        self._check_rotate()
        super().error(msg, exc)
    
    def critical(self, msg):
        self._check_rotate()
        super().critical(msg)

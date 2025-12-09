"""
Network Monitor Module for WinDetox
Version: 1.0
Description: Monitors network connections using psutil
"""

import threading
import time
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Callable
import socket
import psutil
from dataclasses import dataclass

from core.config import Config
from core.logger import Logger
from core.utils import is_local_ip


@dataclass
class ConnectionInfo:
    """Data class for network connection information"""
    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    direction: str
    timestamp: datetime

    def get_key(self) -> str:
        """Generate unique key for connection"""
        return f"{self.local_addr}:{self.local_port}-{self.remote_addr}:{self.remote_port}-{self.status}"

    def __str__(self) -> str:
        """String representation of connection"""
        arrow = "→" if self.direction == 'OUTGOING' else "←" if self.direction == 'INCOMING' else "•"
        return f"[{self.direction}] {self.process_name} ({self.pid}) {self.local_addr}:{self.local_port} {arrow} {self.remote_addr}:{self.remote_port} [{self.status}]"


class NetworkMonitor:
    """Main network monitoring class"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self.known_connections: Dict[str, ConnectionInfo] = {}
        self.listening_ports: Set[int] = set()
        self.lock = threading.RLock()
        self.is_running = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Process name caching for performance
        self._process_name_cache: Dict[int, Tuple[str, float]] = {}
        self._cache_timeout = 30.0

        # Callbacks for GUI updates
        self.on_new_connection = None
        self.on_connection_closed = None
        self.on_update = None
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name with caching"""
        if not pid:
            return "System"
        
        current_time = time.time()
        if pid in self._process_name_cache:
            cached_name, cache_time = self._process_name_cache[pid]
            if current_time - cache_time < self._cache_timeout:
                return cached_name
        
        try:
            process = psutil.Process(pid)
            name = process.name()
            self._process_name_cache[pid] = (name, current_time)
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"
        except Exception:
            return "Error"
    
    def _cleanup_cache(self):
        """Clean up expired cache entries"""
        current_time = time.time()
        expired = [
            pid for pid, (_, cache_time) in self._process_name_cache.items()
            if current_time - cache_time > self._cache_timeout
        ]
        for pid in expired:
            del self._process_name_cache[pid]
    
    def start(self) -> bool:
        """Start network monitoring"""
        with self.lock:
            if self.is_running: 
                return False
            self.is_running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.logger.info("Network Monitor started")
            return True
    
    def stop(self):
        """Stop network monitoring"""
        with self.lock:
            if not self.is_running: 
                return
            self.is_running = False
            self.logger.info("Network Monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_running:
            try:
                self._scan_connections()
                time.sleep(Config.SCAN_INTERVAL)
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}", exc=True)
                time.sleep(Config.SCAN_INTERVAL)
    
    def _scan_connections(self):
        """Scan current network connections"""
        try:
            current = {}
            listening_now = set()
            
            for conn in psutil.net_connections(kind='inet'):
                try:
                    if hasattr(conn, 'family') and conn.family != socket.AF_INET:
                        continue
                    
                    process_name = self._get_process_name(conn.pid)
                    
                    local_addr = conn.laddr.ip if conn.laddr else "0.0.0.0"
                    local_port = conn.laddr.port if conn.laddr else 0
                    remote_addr = conn.raddr.ip if conn.raddr else ""
                    remote_port = conn.raddr.port if conn.raddr else 0
                    status = conn.status
                    
                    direction = "LISTENING" if status in Config.LISTEN_STATES else \
                                "INCOMING" if remote_addr and (local_port in self.listening_ports or local_port in listening_now) else \
                                "OUTGOING" if remote_addr else "UNKNOWN"
                    
                    info = ConnectionInfo(
                        pid=conn.pid or 0,
                        process_name=process_name,
                        local_addr=local_addr,
                        local_port=local_port,
                        remote_addr=remote_addr,
                        remote_port=remote_port,
                        status=status,
                        direction=direction,
                        timestamp=datetime.now()
                    )
                    
                    key = info.get_key()
                    current[key] = info
                    if status in Config.LISTEN_STATES:
                        listening_now.add(local_port)
                    
                except Exception as e:
                    self.logger.debug(f"Connection error: {e}")
                    continue
            
            with self.lock:
                # Detect new connections
                for key, info in current.items():
                    if key not in self.known_connections:
                        self.known_connections[key] = info
                        if self.on_new_connection:
                            self.on_new_connection(info)
                
                # Detect closed connections
                closed = set(self.known_connections.keys()) - set(current.keys())
                for key in closed:
                    info = self.known_connections[key]
                    if self.on_connection_closed:
                        self.on_connection_closed(info)
                    del self.known_connections[key]
                
                # Update listening ports
                self.listening_ports = listening_now
                if self.on_update:
                    self.on_update(list(current.values()))
        
        except Exception as e:
            self.logger.error(f"Scan error: {e}", exc=True)
    
    def get_statistics(self) -> Dict:
        """Get connection statistics"""
        with self.lock:
            stats = {
                'total': len(self.known_connections), 
                'listening': 0, 
                'incoming': 0, 
                'outgoing': 0
            }
            for c in self.known_connections.values():
                if c.direction == 'LISTENING': 
                    stats['listening'] += 1
                elif c.direction == 'INCOMING': 
                    stats['incoming'] += 1
                elif c.direction == 'OUTGOING': 
                    stats['outgoing'] += 1
            return stats

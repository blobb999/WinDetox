# ip_info_cache.py
"""
IP Information Cache for fast IP lookups
"""
import json
import os
import sys
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, List
import ipaddress

from core.config import Config


class IPInfoCache:
    """Cache for IP information (ISP, ASN, Location, etc.)"""
    
    def __init__(self, cache_file: str = None):
        # Dynamischer Pfad: Wenn wir in einer Binary sind oder refraktoriert
        if cache_file:
            self.cache_file = cache_file
        else:
            # Prüfe, ob wir in einer Binary/EXE sind
            if getattr(sys, 'frozen', False):
                # Wir sind in einer PyInstaller-Binary
                base_dir = os.path.dirname(sys.executable)
            else:
                # Normales Python-Skript
                base_dir = os.path.dirname(__file__)
            
            # Prüfe, ob wir im network-Ordner sind (refraktoriert)
            if os.path.basename(base_dir) == 'network':
                # Gehe ein Level hoch zum Projekt-Root
                base_dir = os.path.dirname(base_dir)
            
            self.cache_file = os.path.join(base_dir, 'ip_info_cache.db')
        
        print(f"DEBUG: Using cache file: {self.cache_file}")  # DEBUG-Ausgabe
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for cache"""
        try:
            # Stelle sicher, dass das Verzeichnis existiert
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            
            conn = sqlite3.connect(self.cache_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_info (
                    ip TEXT PRIMARY KEY,
                    isp TEXT,
                    asn TEXT,
                    org TEXT,
                    country TEXT,
                    city TEXT,
                    is_cloud BOOLEAN,
                    is_cdn BOOLEAN,
                    is_microsoft BOOLEAN,
                    last_updated TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_ip ON ip_info(ip)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_cloud ON ip_info(is_cloud)
            ''')
            
            conn.commit()
            conn.close()
            print(f"DEBUG: Database initialized at {self.cache_file}")  # DEBUG-Ausgabe
            
        except Exception as e:
            print(f"ERROR: Failed to initialize database: {e}")
            # Fallback: temporäre Datei
            import tempfile
            temp_dir = tempfile.gettempdir()
            self.cache_file = os.path.join(temp_dir, 'windetox_ip_cache.db')
            print(f"DEBUG: Using fallback cache file: {self.cache_file}")
            # Rekursiver Aufruf mit Fallback-Pfad
            self._init_database()
    
    def get(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get cached IP information"""
        try:
            # Validate IP first
            ipaddress.ip_address(ip)
            
            conn = sqlite3.connect(self.cache_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT isp, asn, org, country, city, is_cloud, is_cdn, is_microsoft 
                FROM ip_info 
                WHERE ip = ? AND last_updated > ?
            ''', (ip, datetime.now() - timedelta(seconds=Config.IP_INFO_CACHE_TIME)))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'isp': row[0],
                    'asn': row[1],
                    'org': row[2],
                    'country': row[3],
                    'city': row[4],
                    'is_cloud': bool(row[5]),
                    'is_cdn': bool(row[6]),
                    'is_microsoft': bool(row[7])
                }
        except Exception:
            pass
        return None
    
    def set(self, ip: str, info: Dict[str, Any]):
        """Cache IP information"""
        try:
            # Validate IP first
            ipaddress.ip_address(ip)
            
            conn = sqlite3.connect(self.cache_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO ip_info 
                (ip, isp, asn, org, country, city, is_cloud, is_cdn, is_microsoft, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip,
                info.get('isp'),
                info.get('asn'),
                info.get('org'),
                info.get('country'),
                info.get('city'),
                info.get('is_cloud', False),
                info.get('is_cdn', False),
                info.get('is_microsoft', False),
                datetime.now()
            ))
            
            conn.commit()
            conn.close()
        except Exception:
            pass
    
    def clear_old_entries(self, max_age_days: int = 30):
        """Clear entries older than max_age_days"""
        try:
            conn = sqlite3.connect(self.cache_file)
            cursor = conn.cursor()
            
            cutoff = datetime.now() - timedelta(days=max_age_days)
            cursor.execute('DELETE FROM ip_info WHERE last_updated < ?', (cutoff,))
            
            conn.commit()
            conn.close()
        except Exception:
            pass


class IPAnalyzer:
    """Analyze IP addresses for additional information"""
    
    # Known cloud and CDN IP ranges
    CLOUD_RANGES = {
        'Microsoft': [
            '13.64.0.0/11', '13.96.0.0/13', '13.104.0.0/14', '20.33.0.0/16',
            '20.34.0.0/16', '20.36.0.0/14', '20.40.0.0/13', '20.48.0.0/12',
            '20.64.0.0/10', '20.128.0.0/16', '20.135.0.0/16', '20.136.0.0/14',
            '20.140.0.0/15', '20.160.0.0/11', '20.192.0.0/10', '40.64.0.0/10',
            '52.96.0.0/12', '104.40.0.0/13', '104.146.0.0/16', '131.253.0.0/16',
            '134.170.0.0/16', '157.54.0.0/15', '157.56.0.0/14', '157.60.0.0/16'
        ],
        'Amazon AWS': [
            '18.0.0.0/15', '52.0.0.0/15', '54.0.0.0/16', '107.20.0.0/14',
            '35.176.0.0/13', '52.95.0.0/20', '54.231.0.0/16', '54.240.0.0/12'
        ],
        'Google Cloud': [
            '8.34.0.0/19', '8.35.0.0/19', '23.236.0.0/19', '23.251.0.0/19',
            '35.184.0.0/13', '35.192.0.0/12', '35.208.0.0/12', '35.224.0.0/12',
            '104.154.0.0/15', '104.196.0.0/14', '107.167.0.0/16', '107.178.0.0/15'
        ],
        'Cloudflare': [
            '104.16.0.0/12', '162.158.0.0/15', '172.64.0.0/13', '173.245.48.0/20',
            '188.114.96.0/20', '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'
        ],
        'Akamai': [
            '23.0.0.0/12', '23.32.0.0/11', '23.192.0.0/11', '72.246.0.0/15',
            '96.16.0.0/15', '104.64.0.0/10', '184.24.0.0/13', '184.84.0.0/14'
        ]
    }
    
    # CDN detection patterns in hostnames
    CDN_PATTERNS = [
        'akamai', 'cloudfront', 'fastly', 'cloudflare', 'cdn', 'edgecast',
        'stackpath', 'limelight', 'highwinds', 'incapdns', 'azureedge',
        'googleusercontent', 'amazonaws', 'rackspace', 'voxcdn'
    ]
    
    def __init__(self, cache: IPInfoCache = None):
        self.cache = cache or IPInfoCache()
        # Compile networks for faster lookup
        self._compiled_networks = self._compile_networks()
    
    def _compile_networks(self):
        """Compile all networks for fast lookup"""
        compiled = {}
        for provider, ranges in self.CLOUD_RANGES.items():
            compiled[provider] = [ipaddress.ip_network(r) for r in ranges]
        return compiled
    
    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze IP and return comprehensive information"""
        # First check cache
        cached = self.cache.get(ip)
        if cached:
            return cached
        
        # Basic info structure
        info = {
            'isp': None,
            'asn': None,
            'org': None,
            'country': None,
            'city': None,
            'is_cloud': False,
            'is_cdn': False,
            'is_microsoft': False,
            'provider': None
        }
        
        try:
            ip_addr = ipaddress.ip_address(ip)
            
            # Check against known ranges
            for provider, networks in self._compiled_networks.items():
                for network in networks:
                    if ip_addr in network:
                        info['is_cloud'] = True
                        info['provider'] = provider
                        if provider == 'Microsoft':
                            info['is_microsoft'] = True
                        if provider in ['Cloudflare', 'Akamai']:
                            info['is_cdn'] = True
                        break
                if info['provider']:
                    break
            
            # Try to get more info from external API (non-blocking, async)
            # This would be implemented separately
            
            # Cache the result
            self.cache.set(ip, info)
            
        except Exception:
            pass
        
        return info
    
    def is_cloud_ip(self, ip: str) -> bool:
        """Quick check if IP belongs to cloud provider"""
        info = self.analyze_ip(ip)
        return info.get('is_cloud', False)
    
    def is_microsoft_ip(self, ip: str) -> bool:
        """Quick check if IP belongs to Microsoft"""
        info = self.analyze_ip(ip)
        return info.get('is_microsoft', False)
    
    def is_cdn_ip(self, ip: str) -> bool:
        """Quick check if IP belongs to CDN"""
        info = self.analyze_ip(ip)
        return info.get('is_cdn', False)
    
    def get_provider_info(self, ip: str) -> str:
        """Get provider information as string"""
        info = self.analyze_ip(ip)
        if info['provider']:
            return f"{info['provider']}"
        elif info['is_cloud']:
            return "Cloud Provider"
        elif info['is_cdn']:
            return "CDN"
        else:
            return "Unknown ISP"

    def batch_analyze(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Analyze multiple IPs in batch for better performance"""
        results = {}
        
        # Group IPs by first octet for more efficient range checking
        ip_groups = {}
        for ip in ips:
            try:
                first_octet = ip.split('.')[0]
                ip_groups.setdefault(first_octet, []).append(ip)
            except:
                pass
        
        # Process each group
        for first_octet, ip_list in ip_groups.items():
            for ip in ip_list:
                # Check cache first
                cached = self.cache.get(ip)
                if cached:
                    results[ip] = cached
                    continue
                
                # Quick cloud detection
                info = self._quick_cloud_detect(ip)
                if info['is_cloud']:
                    results[ip] = info
                    self.cache.set(ip, info)
                else:
                    # Mark for later detailed analysis if needed
                    results[ip] = {'needs_detailed': True}
        
        return results

    def _quick_cloud_detect(self, ip: str) -> Dict[str, Any]:
        """Quick cloud detection without full analysis"""
        info = {
            'isp': None,
            'is_cloud': False,
            'is_cdn': False,
            'is_microsoft': False,
            'provider': None
        }
        
        try:
            ip_addr = ipaddress.ip_address(ip)
            
            # Quick checks based on first octet
            first_octet = int(ip.split('.')[0])
            
            # Microsoft ranges (common)
            if first_octet in [13, 20, 40, 52, 104, 131, 134, 157]:
                info['is_cloud'] = True
                info['is_microsoft'] = True
                info['provider'] = 'Microsoft'
            # Common cloud ranges
            elif first_octet in [18, 35, 54, 107]:
                info['is_cloud'] = True
                info['provider'] = 'AWS'
            elif first_octet in [8, 23, 34, 104, 172]:
                info['is_cloud'] = True
                info['provider'] = 'Cloud/CDN'
            
        except:
            pass
        
        return info

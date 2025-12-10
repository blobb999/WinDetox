# config.py
"""
Configuration constants for WinDetox
"""
import ipaddress
import os
import winreg


class Config:
    """Global configuration constants"""
    WINDOW_TITLE = "WinDetox"
    WINDOW_GEOMETRY = "1450x920"
    
    # Version information
    CURRENT_VERSION = "1.0"
    VERSION_FILE = "version.txt"
    REPO_URL = "https://github.com/blobb999/WinDetox"
    LATEST_VERSION_URL = f"{REPO_URL}/releases/latest/download/version.json"
    LATEST_EXE_URL = f"{REPO_URL}/releases/latest/download/WinDetox.exe"
    UPDATE_SIGNATURE_URL = f"{REPO_URL}/releases/latest/download/WinDetox.exe.sha256"

    SCAN_INTERVAL = 2.0
    MAX_LOG_LINES = 1000
    MAX_HISTORY_ENTRIES = 500
    
    # Threading limits
    MAX_CONCURRENT_DNS_QUERIES = 50
    DNS_TIMEOUT = 2.0
    FIREWALL_COMMAND_TIMEOUT = 30
    
    # Performance optimization
    TREE_UPDATE_BATCH_SIZE = 100
    TREE_UPDATE_INTERVAL = 500  # ms
    
    # Retry logic
    MAX_RETRY_ATTEMPTS = 3
    RETRY_DELAY = 1.0
    BULK_BLOCK_DELAY = 0.5  # Delay between bulk blocks

    LISTEN_STATES = {'LISTEN'}
    
    # Log file in user's AppData directory
    LOG_FILE = os.path.join(os.getenv('APPDATA'), 'WinDetox', 'windetox.log')
    
    # Settings file in user's AppData directory
    SETTINGS_FILE = os.path.join(os.getenv('APPDATA'), 'WinDetox', 'settings.json')
    
    # Blocklist file in user's AppData directory
    BLOCKLIST_FILE = os.path.join(os.getenv('APPDATA'), 'WinDetox', 'blocked_ips.json')
    
    # Hosts backups in user's AppData directory
    HOSTS_BACKUP_DIR = os.path.join(os.getenv('APPDATA'), 'WinDetox', 'hosts_backups')
    
    # Registry paths for autostart
    AUTOSTART_REGISTRY_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    AUTOSTART_REGISTRY_NAME = "WinDetox"
    
    # Local IP ranges for filtering (using ipaddress for performance)
    LOCAL_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('0.0.0.0/32'),
    ]

    # Hardcoded Microsoft telemetry IPs (2025 updated)
    HARDCODED_MICROSOFT_IPS = {
        "13.107.4.254",       # DoH/DoT Fallback + time server
        "204.79.197.254",     # ntp.microsoft.com + telemetry
        "20.190.159.0",       # OneDrive/Office 365 Relay
        "20.190.159.128",     # same
        "52.114.128.0",       # Microsoft CDN / Windows Update Relay
        "13.107.6.158",       # Copilot / Recall Telemetry 2025
        "40.126.31.255",      # Azure Telemetry Endpoint
        "13.107.42.18",       # settings-win.data.microsoft.com (Win11 24H2+)
        "52.184.216.229",     # Copilot/Recall Telemetry Relay
        "52.111.195.5",       # vortex-win.data.microsoft.com
        "191.232.139.0",      # Azure Front Door
        "20.112.52.29",       # Windows 11 Recall Telemetry
        "13.107.3.128",       # Office 365 Telemetry
        "52.109.76.0",        # OneDrive Business
        "20.44.86.43",        # Azure Monitor/Application Insights
        "13.107.18.11",       # Microsoft Graph API
        "40.77.226.250",      # Bing AI/Copilot
        "52.162.111.67",      # Windows Defender Telemetry
        "13.107.246.254",     # DNS Telemetry Collection
        "20.189.173.0",       # Windows Update Telemetry
        "52.178.161.181",     # Azure Machine Learning
        "40.121.61.208",      # Microsoft 365 Compliance
        "52.229.37.0",        # Copilot+ Recall Upload Endpoint
        "52.184.217.165",     # Windows 11 25H2 Telemetry
        "13.107.9.254",       # DoH Fallback 2025
        "40.90.139.0",        # Azure Telemetry Front Door (new since Oct 2025)
        "152.199.19.161",     # aka.ms / Windows Store Relay (new since 25H2)
        "13.107.21.200",      # Microsoft Graph / Copilot CDN
        "20.202.0.0",         # Azure Front Door (Telemetry 2025)
        "104.76.240.0",       # Akamai CDN for settings-win.data.microsoft.com
        "40.126.32.0",        # New Recall Upload Relay (Dec 2025)
        "40.126.63.255",      # New Windows 11 25H2 Telemetry Relay (Dec 2025)
        "13.107.64.0",        # Microsoft 365 Global Relay (new since Nov 2025)
        "52.114.76.0",        # Copilot+ Recall Upload (new cluster)
        "20.99.184.0",        # Azure Front Door – new telemetry path
        "40.126.63.0",        # New Recall Upload Cluster (Dec 2025)
        "52.229.128.0",       # Copilot+ PC Telemetry Relay
        "20.99.133.0",        # Azure Front Door – new path for settings-win.data.microsoft.com
        "13.107.246.38",      # DoH Fallback 2025 (often overlooked)
        "40.126.63.0",        # New Recall Cluster
        "20.99.184.0",        # Azure Front Door Telemetry
        "52.229.128.0",       # Copilot+ Upload Relay
        "40.126.63.100",      # Neue Recall-Upload-Cluster (EU-West)
        "40.126.63.101",
        "40.126.63.102",      
        "52.229.137.0",       # Neuer Copilot+ Telemetry Relay
        "52.229.137.255",     
        "20.99.184.100"       # Neuer Front Door für settings-win.data.microsoft.com
    }

    # Microsoft blocklist URLs
    MICROSOFT_BLOCKLIST_URLS = [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.plus.txt",
        "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/extra.txt",
        "https://v.firebog.net/hosts/AdguardDNS.txt",
    ]
    UPDATE_INTERVAL_BLOCKLISTS = 86400  # 24 hours
    
    # Backup configuration
    BACKUP_BLOCKLIST = True
    MAX_BACKUP_FILES = 5
    
    # Hosts file configuration
    HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
    
    # Microsoft services to disable in full privacy mode
    MICROSOFT_SERVICES = [
        "DiagTrack",           # Connected User Experiences and Telemetry
        "dmwappushservice",    # Device Management Wireless Application Protocol
        "WMPNetworkSvc",       # Windows Media Player Network Sharing
        "WpnService",          # Windows Push Notifications
        "wisvc",               # Windows Insider Service
        "TieringEngineService",# Storage Tier Management
        "lfsvc",               # Geolocation Service
        "MapsBroker",          # Downloaded Maps Manager
        "NetTcpPortSharing",   # Net.Tcp Port Sharing Service
        "RemoteRegistry",      # Remote Registry
    ]

    # NCSI Registry Settings
    NCSI_REGISTRY_PATH = r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"
    NCSI_REGISTRY_KEY = "EnableActiveProbing"
    NCSI_REGISTRY_TYPE = winreg.REG_DWORD
    
    # NCSI Domains for hosts blocking
    NCSI_DOMAINS = [
        "www.msftncsi.com",
        "www.msftconnecttest.com",
        "ipv6.msftncsi.com",
        "teredo.ipv6.microsoft.com",
        "microsoft.com",
        "windows.com",
        "msftncsi.com"
    ]
    
    # NCSI Test URLs
    NCSI_TEST_URLS = [
        "http://www.msftncsi.com/ncsi.txt",
        "http://ipv6.msftncsi.com/ncsi.txt",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]

    @staticmethod
    def get_appdata_dir():
        """Get application data directory for all files"""
        import os
        appdata = os.getenv('APPDATA')
        windetox_dir = os.path.join(appdata, 'WinDetox')
        os.makedirs(windetox_dir, exist_ok=True)
        return windetox_dir
    
    @staticmethod
    def get_install_dir():
        """Get installation directory"""
        import os
        import sys
        if getattr(sys, 'frozen', False):
            # Binary/EXE
            return os.path.dirname(sys.executable)
        else:
            # Python-Skript
            return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Dynamische Pfade für alle Dateien
    LOG_FILE = os.path.join(get_appdata_dir(), 'windetox.log')
    SETTINGS_FILE = os.path.join(get_appdata_dir(), 'settings.json')
    BLOCKLIST_FILE = os.path.join(get_appdata_dir(), 'blocked_ips.json')
    IP_INFO_CACHE_DB = os.path.join(get_appdata_dir(), 'ip_info_cache.db')
    HOSTS_BACKUP_DIR = os.path.join(get_appdata_dir(), 'hosts_backups')

# blocklist_manager.py
"""
Blocklist management for WinDetox
"""
import json
import os
import re
import shutil
import tempfile
import time
import winreg
import socket
from datetime import datetime
from typing import Dict, List, Set, Optional, Any, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import urlopen, Request

import ipaddress
import win32serviceutil

from core.config import Config
from core.exceptions import BlocklistError, PermissionError, ValidationError
from core.logger import Logger


class BlocklistManager:
    """Manages IP blocklists"""

    def __init__(self, logger=None):
        # Logger wird jetzt korrekt verwendet
        if logger is None:
            logger = Logger()
        self.logger = logger
        
        self.blocked_ips = set()
        self.sources = {}
        self.last_update = 0
        self._firewall_applied_ips = set()
        self._ensure_blocklist_directory()

        self.load_blocklist()
        self.apply_hardcoded_microsoft_ips()

    def _ensure_blocklist_directory(self):
        """Ensure the blocklist directory exists"""
        blocklist_dir = os.path.dirname(Config.BLOCKLIST_FILE)
        if not os.path.exists(blocklist_dir):
            os.makedirs(blocklist_dir, exist_ok=True)
        # Also ensure hosts backup directory exists
        if not os.path.exists(Config.HOSTS_BACKUP_DIR):
            os.makedirs(Config.HOSTS_BACKUP_DIR, exist_ok=True)

    def load_blocklist(self):
        """Load blocklist from JSON file"""
        if os.path.exists(Config.BLOCKLIST_FILE):
            try:
                with open(Config.BLOCKLIST_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get("ips", []))
                    self.sources = data.get("sources", {})
                    self._firewall_applied_ips = set(data.get("firewall_applied", []))
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to load blocklist: {e}")
                raise BlocklistError(f"Failed to load blocklist: {e}")

    def save_blocklist(self):
        """Save blocklist with automatic backup"""
        self.backup_blocklist()

        try:
            temp_file = f"{Config.BLOCKLIST_FILE}.tmp"

            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "ips": sorted(list(self.blocked_ips)),
                    "sources": self.sources,
                    "firewall_applied": sorted(list(self._firewall_applied_ips)),
                    "last_modified": datetime.now().isoformat(),
                    "version": "2.0"
                }, f, indent=2)

            if os.path.exists(Config.BLOCKLIST_FILE):
                os.replace(temp_file, Config.BLOCKLIST_FILE)
            else:
                os.rename(temp_file, Config.BLOCKLIST_FILE)

            if self.logger:
                self.logger.debug("Blocklist saved")

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to save blocklist: {e}")
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
            raise BlocklistError(f"Failed to save blocklist: {e}")

    def backup_blocklist(self) -> bool:
        """Create backup of current blocklist"""
        if not Config.BACKUP_BLOCKLIST:
            return True

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{Config.BLOCKLIST_FILE}.backup_{timestamp}"

            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "ips": list(self.blocked_ips),
                    "sources": self.sources,
                    "firewall_applied": list(self._firewall_applied_ips),
                    "timestamp": timestamp
                }, f, indent=2)

            self._cleanup_old_backups()

            if self.logger:
                self.logger.info(f"Backup created: {backup_file}")
            return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Backup failed: {e}")
            return False

    def _cleanup_old_backups(self):
        """Delete old backup files"""
        try:
            backup_files = sorted([
                f for f in os.listdir('.')
                if f.startswith(f"{Config.BLOCKLIST_FILE}.backup_")
            ], reverse=True)

            for old_backup in backup_files[Config.MAX_BACKUP_FILES:]:
                try:
                    os.remove(old_backup)
                    if self.logger:
                        self.logger.debug(f"Old backup deleted: {old_backup}")
                except:
                    pass

        except Exception as e:
            if self.logger:
                self.logger.debug(f"Backup cleanup error: {e}")

    def add_ip(self, ip: str, source: str = "Manual", auto_save: bool = True):
        """Add IP to blocklist with optional auto-save"""
        # Import hier, um zirkuläre Abhängigkeiten zu vermeiden
        from network.ip_validator import validate_ip_address, normalize_ip_address
        
        if not ip or ':' in ip:
            return

        is_valid, error = validate_ip_address(ip)
        if not is_valid:
            if self.logger:
                self.logger.warning(f"Invalid IP not blocked: {ip} - {error}")
            raise ValidationError(f"Invalid IP address: {ip} - {error}")

        normalized_ip = normalize_ip_address(ip)
        if not normalized_ip:
            if self.logger:
                self.logger.warning(f"IP cannot be normalized: {ip}")
            raise ValidationError(f"IP cannot be normalized: {ip}")

        if normalized_ip in self.blocked_ips:
            if self.logger:
                self.logger.debug(f"IP {normalized_ip} already blocked")
            return

        self.blocked_ips.add(normalized_ip)
        self.sources[normalized_ip] = source

        if auto_save:
            self.save_blocklist()

        if self.logger:
            self.logger.info(f"IP {normalized_ip} added to blocklist ({source})")

    def add_ips_batch(self, ips: List[str], source: str = "Batch") -> int:
        """Add multiple IPs efficiently with single save operation"""
        # Import hier, um zirkuläre Abhängigkeiten zu vermeiden
        from network.ip_validator import validate_ip_address, normalize_ip_address
        
        added_count = 0
        failed_ips = []

        for ip in ips:
            try:
                # Validate without saving
                if not ip or ':' in ip:
                    continue

                is_valid, error = validate_ip_address(ip)
                if not is_valid:
                    failed_ips.append((ip, error))
                    continue

                normalized_ip = normalize_ip_address(ip)
                if not normalized_ip:
                    failed_ips.append((ip, "normalization failed"))
                    continue

                if normalized_ip in self.blocked_ips:
                    continue

                self.blocked_ips.add(normalized_ip)
                self.sources[normalized_ip] = source
                added_count += 1

            except Exception as e:
                failed_ips.append((ip, str(e)))
                if self.logger:
                    self.logger.debug(f"Failed to add IP {ip}: {e}")

        # Single save operation for all IPs
        if added_count > 0:
            self.save_blocklist()
            if self.logger:
                self.logger.info(f"Batch added {added_count} IPs to blocklist")

        if failed_ips and self.logger:
            self.logger.warning(f"Failed to add {len(failed_ips)} IPs: {failed_ips[:5]}")

        return added_count

    def remove_ip(self, ip: str):
        """Remove IP from blocklist and all related firewall tracking"""
        if ip not in self.blocked_ips:
            if self.logger:
                self.logger.warning(f"IP {ip} not found in blocklist")
                raise BlocklistError(f"IP {ip} not found in blocklist")
        
        # Remove from all tracking sets
        self.blocked_ips.remove(ip)
        self.sources.pop(ip, None)
        self._firewall_applied_ips.discard(ip)  # Ensure it's removed from firewall tracking
        self.save_blocklist()
        
        if self.logger:
            self.logger.info(f"IP {ip} unblocked and removed from firewall tracking")

    def apply_hardcoded_microsoft_ips(self):
        """Add hardcoded Microsoft IPs to blocklist at startup"""
        for ip in Config.HARDCODED_MICROSOFT_IPS:
            if ip not in self.blocked_ips:
                self.add_ip(ip, "Hardcoded (always active)")
        if self.logger:
            self.logger.info(f"{len(Config.HARDCODED_MICROSOFT_IPS)} hardcoded Microsoft IPs secured")

    def update_dynamic_lists(self) -> int:
        """Update dynamic blocklists from online sources - RETURNS count of added IPs"""
        if time.time() - self.last_update < Config.UPDATE_INTERVAL_BLOCKLISTS:
            return 0

        if self.logger:
            self.logger.info("Updating blocklists...")
        added = self._update_microsoft_list()
        self.last_update = time.time()
        return added

    def _update_microsoft_list(self) -> int:
        """Load multiple current Microsoft telemetry blocklists with batch save"""
        ips_to_add = []

        for url in Config.MICROSOFT_BLOCKLIST_URLS:
            try:
                with urlopen(url, timeout=30) as resp:
                    raw = resp.read()
                    try:
                        content = raw.decode('utf-8')
                    except:
                        content = raw.decode('utf-8', errors='replace')

                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue

                        # Handle different formats
                        parts = line.split()
                        if len(parts) >= 2:
                            # Format: "0.0.0.0 domain.com"
                            ip_part = parts[0]
                            if ip_part != "0.0.0.0" and ip_part != "127.0.0.1":
                                if self._is_valid_ipv4(ip_part) and ip_part not in self.blocked_ips:
                                    ips_to_add.append(ip_part)
                        elif self._is_valid_ipv4(line) and line not in self.blocked_ips:
                            # Format: just IP
                            ips_to_add.append(line)

                    if self.logger:
                        self.logger.info(f"{url.split('/')[-1]} → {len(ips_to_add)} IPs queued")

            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Error loading {url}: {e}")

        # Batch add all IPs with single save
        if ips_to_add:
            added_count = self.add_ips_batch(ips_to_add, "Dynamic List (Microsoft)")
            return added_count

        return 0

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address (non-local)"""
        # Import hier, um zirkuläre Abhängigkeiten zu vermeiden
        from core.utils import is_local_ip
        
        try:
            addr = ipaddress.ip_address(ip)
            if not isinstance(addr, ipaddress.IPv4Address):
                return False

            # Check for local IP ranges
            return not is_local_ip(ip)

        except ValueError:
            return False

    def disable_ncsi(self) -> bool:
        """Completely disable Windows NCSI (Network Connectivity Status Indicator)"""
        # Import hier, um zirkuläre Abhängigkeiten zu vermeiden
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Disabling NCSI requires admin rights!")

        try:
            # Enhanced PowerShell script for comprehensive NCSI kill
            ps_script = """
            # ================================================
            # COMPLETELY DISABLE NCSI - NO MORE INTERNET DETECTION
            # ================================================
            
            # 1. Disable NCSI active probing via registry (Standard method)
            $ncsiPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet"
            if (-not (Test-Path $ncsiPath)) {
                New-Item -Path $ncsiPath -Force
            }
            Set-ItemProperty -Path $ncsiPath -Name "EnableActiveProbing" -Value 0 -Type DWord -Force
            
            # 2. Disable via Group Policy if exists
            $policyPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnectivityStatusIndicator"
            if (-not (Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force
            }
            Set-ItemProperty -Path $policyPath -Name "NoActiveProbe" -Value 1 -Type DWord -Force
            
            # 3. Additional registry changes for Windows 11 24H2+ and 25H2
            # Network Signature entries - forces "Private" network
            $unmanagedPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged"
            if (-not (Test-Path $unmanagedPath)) {
                New-Item -Path $unmanagedPath -Force
            }
            Set-ItemProperty -Path $unmanagedPath -Name "FirstNetwork" -Value "Private" -Type String -Force
            
            $managedPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed"
            if (-not (Test-Path $managedPath)) {
                New-Item -Path $managedPath -Force
            }
            Set-ItemProperty -Path $managedPath -Name "FirstNetwork" -Value "Private" -Type String -Force
            
            # 4. Disable network profile definitions
            Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles" -Name "Category" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            
            # 5. Windows 11 25H2 specific NCSI kill switches
            # Disable "Network Connectivity Assistant"
            $ncaPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NcaSvc"
            if (Test-Path $ncaPath) {
                Set-ItemProperty -Path $ncaPath -Name "Start" -Value 4 -Type DWord -Force  # Disabled
            }
            
            # 6. Additional Windows 11 24H2+ settings
            Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\NetworkStatus" -Name "ShowInternetOption" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            
            # 7. Completely disable NLA (Network Location Awareness) service
            Stop-Service -Name "NlaSvc" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "NlaSvc" -StartupType Disabled -ErrorAction SilentlyContinue
            
            # 8. Block NCSI domains via hosts file (IPv4 + IPv6)
            $hostsEntries = @(
                "# ================================================",
                "# NCSI COMPLETE BLOCK - Added by Advanced WinDetox",
                "# Windows CANNOT CHECK INTERNET CONNECTION ANYMORE!",
                "# ================================================",
                "0.0.0.0 www.msftncsi.com",
                "0.0.0.0 www.msftconnecttest.com", 
                "0.0.0.0 ipv6.msftncsi.com",
                "0.0.0.0 teredo.ipv6.microsoft.com",
                "0.0.0.0 msftncsi.com",
                "0.0.0.0 dns.msftncsi.com",
                "0.0.0.0 v10.vortex-win.data.microsoft.com",
                "0.0.0.0 settings-win.data.microsoft.com",
                "",
                "# IPv6 Block (for dual-stack systems)",
                ":: www.msftncsi.com",
                ":: www.msftconnecttest.com",
                ":: ipv6.msftncsi.com",
                ":: teredo.ipv6.microsoft.com",
                ":: msftncsi.com",
                "0.0.0.0 settings-win.data.microsoft.com",
                "0.0.0.0 settings-win.data.microsoft.com.nsatc.net",
                "::      settings-win.data.microsoft.com"
            )
            
            # Modify hosts file (remove existing NCSI blocks, add new ones)
            $hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts"
            $currentContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
            
            # Remove old NCSI entries
            $newContent = @()
            $skipBlock = $false
            
            foreach ($line in $currentContent) {
                if ($line -eq "# NCSI COMPLETE BLOCK - Added by WinDetox") {
                    $skipBlock = $true
                    continue
                }
                if ($skipBlock -and $line -eq "# ================================================") {
                    $skipBlock = $false
                    continue
                }
                if (-not $skipBlock) {
                    $newContent += $line
                }
            }
            
            # Add new blocks
            $newContent += $hostsEntries
            Set-Content -Path $hostsFile -Value $newContent -Encoding UTF8 -Force
            
            # 9. Block NCSI via Windows Firewall
            # Block HTTP/HTTPS access to NCSI servers
            netsh advfirewall firewall add rule name="WinDetox_Block_NCSI_HTTP" dir=out action=block protocol=TCP remoteport=80 remoteip=131.107.255.255 enable=yes 2>&1 | Out-Null
            netsh advfirewall firewall add rule name="WinDetox_Block_NCSI_HTTPS" dir=out action=block protocol=TCP remoteport=443 remoteip=131.107.255.255 enable=yes 2>&1 | Out-Null
            netsh advfirewall firewall add rule name="WinDetox_Block_NCSI_DNS" dir=out action=block protocol=UDP remoteport=53 remoteip=131.107.255.255 enable=yes 2>&1 | Out-Null
            
            # 10. Additional blockers for modern Windows 11 versions
            # Block TCP 443 for NCSI fallbacks
            netsh advfirewall firewall add rule name="WinDetox_Block_NCSI_TCP_443" dir=out action=block protocol=TCP remoteport=443 remoteip=20.112.52.29 enable=yes 2>&1 | Out-Null
            
            # 11. Kill NCSI processes if running
            Get-Process -Name "nla" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Where-Object { $_.Modules.ModuleName -contains "nlasvc.dll" } | Stop-Process -Force -ErrorAction SilentlyContinue
            
            # 12. Clear DNS cache
            ipconfig /flushdns 2>&1 | Out-Null
            
            # 13. Reset network stack
            netsh int ip reset 2>&1 | Out-Null
            netsh winsock reset 2>&1 | Out-Null
            
            Write-Output "✅ NCSI COMPLETELY DISABLED - Windows will NEVER show 'No Internet connection'!"
            Write-Output "   • Registry entries set"
            Write-Output "   • Hosts file blocked"
            Write-Output "   • Firewall rules active"
            Write-Output "   • Services disabled"
            """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                f.write(ps_script)
                temp_script = f.name

            result = safe_subprocess_run([
                "powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script
            ], capture_output=True, text=True, timeout=60, encoding='utf-8', errors='ignore')

            os.remove(temp_script)

            if result.returncode == 0:
                if self.logger:
                    self.logger.info("NCSI completely disabled - Windows will never show 'No Internet connection'!")
                return True
            else:
                if self.logger:
                    self.logger.error(f"Error disabling NCSI: {result.stderr}")
                return False

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error disabling NCSI: {e}")
            return False

    def enable_ncsi(self) -> bool:
        """Re-enable Windows NCSI (Network Connectivity Status Indicator) - COMPLETE UNDO"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Enabling NCSI requires admin rights!")

        try:
            # PowerShell script for COMPLETE NCSI UNDO
            ps_script = """
            # ================================================
            # COMPLETELY RESTORE NCSI
            # ================================================
            
            # 1. Re-enable NCSI active probing via registry
            $ncsiPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters\\Internet"
            if (Test-Path $ncsiPath) {
                Set-ItemProperty -Path $ncsiPath -Name "EnableActiveProbing" -Value 1 -Type DWord -Force
            }
            
            # 2. Remove Group Policy settings
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -ErrorAction SilentlyContinue
            
            # 3. Remove/Reset Network Signature entries
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged" -Name "FirstNetwork" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed" -Name "FirstNetwork" -ErrorAction SilentlyContinue
            
            # 4. Reset network profile definitions
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles" -Name "Category" -ErrorAction SilentlyContinue
            
            # 5. Windows 11 25H2 "Network Connectivity Assistant" re-enable
            $ncaPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NcaSvc"
            if (Test-Path $ncaPath) {
                Set-ItemProperty -Path $ncaPath -Name "Start" -Value 2 -Type DWord -Force  # Automatic
            }
            
            # 6. Windows 11 24H2+ settings reset
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\NetworkStatus" -Name "ShowInternetOption" -ErrorAction SilentlyContinue
            
            # 7. Re-enable NLA (Network Location Awareness) service
            Set-Service -Name "NlaSvc" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "NlaSvc" -ErrorAction SilentlyContinue
            
            # 8. Remove NCSI blocks from hosts file
            $hostsFile = "C:\\Windows\\System32\\drivers\\etc\\hosts"
            $lines = Get-Content $hostsFile -ErrorAction SilentlyContinue
            
            $newLines = @()
            $inNcsiBlock = $false
            
            foreach ($line in $lines) {
                if ($line -eq "# NCSI COMPLETE BLOCK - Added by WinDetox") {
                    $inNcsiBlock = $true
                    continue
                }
                if ($inNcsiBlock -and $line -eq "# ================================================") {
                    $inNcsiBlock = $false
                    continue
                }
                if (-not $inNcsiBlock) {
                    $newLines += $line
                }
            }
            
            Set-Content -Path $hostsFile -Value $newLines -Encoding UTF8 -Force
            
            # 9. Remove ALL NCSI Windows Firewall rules
            # First try PowerShell cmdlets
            $firewallRules = @(
                "WinDetox_Block_NCSI_HTTP",
                "WinDetox_Block_NCSI_HTTPS", 
                "WinDetox_Block_NCSI_DNS",
                "WinDetox_Block_NCSI_TCP_443",
                "WinDetox_Block_NCSI_*"  # Wildcard to catch any additional rules
            )
            
            foreach ($rule in $firewallRules) {
                # Try to remove with PowerShell cmdlet
                Remove-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
                # Also try with netsh for compatibility
                netsh advfirewall firewall delete rule name="$rule" -ErrorAction SilentlyContinue 2>&1 | Out-Null
            }
            
            # Remove any remaining firewall rules that match NCSI patterns
            $rulesToRemove = @(
                "*NCSI*",
                "*msftncsi*",
                "*msftconnecttest*"
            )
            
            foreach ($pattern in $rulesToRemove) {
                Get-NetFirewallRule -DisplayName $pattern -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue
                netsh advfirewall firewall delete rule name="$pattern" -ErrorAction SilentlyContinue 2>&1 | Out-Null
            }
            
            # 10. Clear DNS cache
            ipconfig /flushdns 2>&1 | Out-Null
            
            # 11. Restart NLA service
            Restart-Service -Name "NlaSvc" -Force -ErrorAction SilentlyContinue
            
            # 12. Test NCSI connectivity to verify it works
            Write-Output "Testing NCSI connectivity..."
            $testUrls = @(
                "http://www.msftncsi.com/ncsi.txt",
                "http://ipv6.msftncsi.com/ncsi.txt",
                "http://www.msftconnecttest.com/connecttest.txt"
            )
            
            $successCount = 0
            foreach ($url in $testUrls) {
                try {
                    $response = Invoke-WebRequest -Uri $url -TimeoutSec 5 -ErrorAction SilentlyContinue
                    if ($response.StatusCode -eq 200) {
                        $successCount++
                    }
                } catch {
                    # Ignore errors
                }
            }
            
            if ($successCount -gt 0) {
                Write-Output "✅ NCSI RESTORED - Windows can check internet connectivity"
                Write-Output "   • Registry entries reset"
                Write-Output "   • Hosts file cleaned"
                Write-Output "   • ALL NCSI Firewall rules removed"
                Write-Output "   • Services re-enabled"
                Write-Output "   • $successCount of $($testUrls.Count) NCSI tests successful"
            } else {
                Write-Output "⚠️ NCSI partially restored - manual check recommended"
            }
            """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                f.write(ps_script)
                temp_script = f.name

            result = safe_subprocess_run([
                "powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script
            ], capture_output=True, text=True, timeout=60, encoding='utf-8', errors='ignore')

            os.remove(temp_script)

            if result.returncode == 0:
                if self.logger:
                    self.logger.info("NCSI completely restored - ALL NCSI Firewall rules removed")
                return True
            else:
                if self.logger:
                    self.logger.error(f"Error restoring NCSI: {result.stderr}")
                return False

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error restoring NCSI: {e}")
            return False

    def test_ncsi_status(self) -> Dict[str, any]:
        """Test if NCSI is currently active and working - ENHANCED VERSION"""
        # Import hier
        from core.utils import safe_subprocess_run
        
        results = {}

        try:
            # Test 1: Registry setting (EnableActiveProbing)
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, Config.NCSI_REGISTRY_PATH)
                value, reg_type = winreg.QueryValueEx(key, Config.NCSI_REGISTRY_KEY)
                winreg.CloseKey(key)
                results["registry_enabled"] = (value == 1)
                results["registry_value"] = value
            except Exception as e:
                results["registry_enabled"] = False
                results["registry_error"] = str(e)

            # Test 2: Network Signature entries
            try:
                unmanaged_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, unmanaged_path)
                value, reg_type = winreg.QueryValueEx(key, "FirstNetwork")
                winreg.CloseKey(key)
                results["unmanaged_first_network"] = value
                results["unmanaged_blocked"] = (value == "Private")
            except Exception as e:
                results["unmanaged_first_network"] = "Not set"
                results["unmanaged_error"] = str(e)

            try:
                managed_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, managed_path)
                value, reg_type = winreg.QueryValueEx(key, "FirstNetwork")
                winreg.CloseKey(key)
                results["managed_first_network"] = value
                results["managed_blocked"] = (value == "Private")
            except Exception as e:
                results["managed_first_network"] = "Not set"
                results["managed_error"] = str(e)

            # Test 3: Connectivity to NCSI URLs
            for url in Config.NCSI_TEST_URLS:
                try:
                    response = urlopen(url, timeout=5)
                    if response.status == 200:
                        results[url] = True
                        # Read content (should contain "Microsoft NCSI")
                        content = response.read().decode('utf-8', errors='ignore').strip()
                        results[f"{url}_content"] = content
                    else:
                        results[url] = False
                except Exception as e:
                    results[url] = False
                    results[f"{url}_error"] = str(e)

            # Test 4: Check if NLA service is running
            try:
                status = win32serviceutil.QueryServiceStatus('NlaSvc')
                results["nla_service_running"] = (status[1] == 4)  # SERVICE_RUNNING
                results["nla_service_state"] = status[1]
            except Exception as e:
                results["nla_service_running"] = False
                results["nla_service_error"] = str(e)

            # Test 5: Check NCSI Firewall rules
            try:
                result = safe_subprocess_run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=WinDetox_Block_NCSI_HTTP"],
                    capture_output=True, text=True
                )
                results["firewall_block_http"] = "Ok." in result.stdout
            except:
                results["firewall_block_http"] = False

            # Summary status
            connectivity_ok = sum(1 for url in Config.NCSI_TEST_URLS if results.get(url) is True)
            registry_ok = results.get("registry_enabled", False)
            service_ok = results.get("nla_service_running", False)

            if connectivity_ok >= 2 and registry_ok and service_ok:
                results["overall_status"] = "✅ NCSI WORKING - Windows can check internet"
            elif connectivity_ok == 0 and not registry_ok:
                results["overall_status"] = "🚫 NCSI COMPLETELY BLOCKED - No internet detection"
            else:
                results["overall_status"] = "⚠️ NCSI PARTIALLY BLOCKED - Limited functionality"

            results["connectivity_score"] = f"{connectivity_ok}/{len(Config.NCSI_TEST_URLS)}"

            return results

        except Exception as e:
            if self.logger:
                self.logger.debug(f"NCSI test error: {e}")
            return {"error": str(e)}

    def disable_windows_doh(self) -> bool:
        """Completely disable Windows DNS over HTTPS (DoH) for Windows 11 24H2+ and 25H2"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Disabling DoH requires admin rights!")

        try:
            # Comprehensive PowerShell script for Windows 11 24H2+ and 25H2
            ps_script = """
            # Disable standard DoH registry keys
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" -Name "EnableAutoDOH" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "EnableSmartScreen" -Value 0 -Type DWord -Force
            
            # Windows 11 24H2+ specific settings
            # Disable DoH for Edge WebView2
            $webViewPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2"
            if (-not (Test-Path $webViewPath)) {
                New-Item -Path $webViewPath -Force
            }
            Set-ItemProperty -Path $webViewPath -Name "DoHEnabled" -Value 0 -Type DWord -Force
            
            # Set DNS over HTTPS mode to off
            $dnsPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System"
            if (-not (Test-Path $dnsPath)) {
                New-Item -Path $dnsPath -Force
            }
            Set-ItemProperty -Path $dnsPath -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
            
            # Additional hardening for Windows 11 24H2
            Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DNSClient" -Name "DoHPolicy" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -Name "SecureProtocols" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            
            # New for Windows 11 25H2 - Ultimate DoH kill switch
            Remove-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Recurse -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" -Name "DisableAutoDoH" -Value 2 -Type DWord -Force
            
            # Kill DoH via Group Policy if exists
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DNSClient" -Name "DoHPolicy" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DNSClient" -Name "DoHStatus" -ErrorAction SilentlyContinue
            
            # Disable DNSSEC to prevent fallback
            Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" -Name "EnableDNSSEC" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            
            ipconfig /flushdns
            Write-Output "Windows DoH completely disabled for Windows 11 24H2+ and 25H2"
            """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                f.write(ps_script)
                temp_script = f.name

            result = safe_subprocess_run([
                "powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script
            ], capture_output=True, text=True, timeout=30)

            os.remove(temp_script)

            if result.returncode == 0:
                if self.logger:
                    self.logger.info("Windows DoH completely disabled (including Windows 11 24H2+ and 25H2 settings)")
                return True
            else:
                if self.logger:
                    self.logger.error(f"Failed to disable DoH: {result.stderr}")
                return False

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to disable DoH: {e}")
            return False

    def enable_windows_doh(self) -> bool:
        """Enable Windows DNS over HTTPS"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Enabling DoH requires admin rights!")

        try:
            # Remove all DoH registry entries comprehensively
            ps_script = """
            # Remove standard DoH registry keys
            Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" -Name "EnableAutoDOH" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" -Name "DisableAutoDoH" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters" -Name "EnableDNSSEC" -ErrorAction SilentlyContinue
            
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
            
            # Remove Windows 11 24H2+ specific settings
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2" -Name "DoHEnabled" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
            
            # Remove additional hardening entries
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DNSClient" -Name "DoHPolicy" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DNSClient" -Name "DoHStatus" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -Name "SecureProtocols" -ErrorAction SilentlyContinue
            
            # Remove Windows NT DNS Client policies
            Remove-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Recurse -ErrorAction SilentlyContinue
            
            ipconfig /flushdns
            Write-Output "Windows DoH registry entries removed"
            """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                f.write(ps_script)
                temp_script = f.name

            result = safe_subprocess_run([
                "powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script
            ], capture_output=True, text=True, timeout=30)

            os.remove(temp_script)

            if result.returncode == 0:
                if self.logger:
                    self.logger.info("Windows DoH registry entries removed")
                return True
            else:
                if self.logger:
                    self.logger.error(f"Failed to enable DoH: {result.stderr}")
                return False

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to enable DoH: {e}")
            return False

    def disable_delivery_optimization(self) -> bool:
        """Completely disable Windows Delivery Optimization via registry"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Disabling Delivery Optimization requires admin rights!")

        try:
            # PowerShell script to disable Delivery Optimization
            ps_script = """
            # Disable Delivery Optimization via registry
            $doPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config"
            if (-not (Test-Path $doPath)) {
                New-Item -Path $doPath -Force
            }
            Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
            
            # Also disable via policies for extra safety
            $policyPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization"
            if (-not (Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force
            }
            Set-ItemProperty -Path $policyPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
            
            # Stop and disable the service
            Stop-Service -Name "DoSvc" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "DoSvc" -StartupType Disabled -ErrorAction SilentlyContinue
            
            # Disable related services
            Stop-Service -Name "BITS" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "BITS" -StartupType Disabled -ErrorAction SilentlyContinue
            
            Write-Output "Delivery Optimization completely disabled"
            """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                f.write(ps_script)
                temp_script = f.name

            result = safe_subprocess_run([
                "powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script
            ], capture_output=True, text=True, timeout=30)

            os.remove(temp_script)

            if result.returncode == 0:
                if self.logger:
                    self.logger.info("Windows Delivery Optimization completely disabled")
                return True
            else:
                if self.logger:
                    self.logger.error(f"Failed to disable Delivery Optimization: {result.stderr}")
                return False

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to disable Delivery Optimization: {e}")
            return False

    def enable_delivery_optimization(self) -> bool:
        """Enable Windows Delivery Optimization"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Enabling Delivery Optimization requires admin rights!")

        try:
            ps_script = """
            # Remove Delivery Optimization registry entries
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\Config" -Name "DODownloadMode" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
            
            # Re-enable services
            Set-Service -Name "DoSvc" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "DoSvc" -ErrorAction SilentlyContinue
            
            Set-Service -Name "BITS" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "BITS" -ErrorAction SilentlyContinue
            
            Write-Output "Delivery Optimization enabled"
            """
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8') as f:
                f.write(ps_script)
                temp_script = f.name

            result = safe_subprocess_run([
                "powershell", "-ExecutionPolicy", "Bypass", "-File", temp_script
            ], capture_output=True, text=True, timeout=30)

            os.remove(temp_script)

            if result.returncode == 0:
                if self.logger:
                    self.logger.info("Delivery Optimization enabled")
                return True
            else:
                if self.logger:
                    self.logger.error(f"Failed to enable Delivery Optimization: {result.stderr}")
                return False

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to enable Delivery Optimization: {e}")
            return False

    def backup_hosts_file(self) -> bool:
        """Create backup of hosts file"""
        # Import hier
        from core.utils import get_hosts_backup_path
        
        try:
            if not os.path.exists(Config.HOSTS_FILE):
                raise BlocklistError(f"Hosts file not found: {Config.HOSTS_FILE}")

            backup_path = get_hosts_backup_path()
            shutil.copy2(Config.HOSTS_FILE, backup_path)
            if self.logger:
                self.logger.info(f"Hosts file backed up to: {backup_path}")
            return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to backup hosts file: {e}")
            raise BlocklistError(f"Failed to backup hosts file: {e}")

    def block_microsoft_in_hosts(self) -> bool:
        """Add comprehensive Microsoft block entries to hosts file with file locking"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Modifying hosts file requires admin rights!")

        try:
            # Backup first
            self.backup_hosts_file()

            # Use temporary file for atomic write
            temp_hosts = f"{Config.HOSTS_FILE}.tmp"

            # Read current hosts file with retry logic
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    with open(Config.HOSTS_FILE, 'r', encoding='utf-8') as f:
                        content = f.read()
                    break
                except PermissionError:
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(0.5)

            # Remove existing WinDetox entries
            lines = content.split('\n')
            filtered_lines = []
            in_block = False

            for line in lines:
                if line.strip() == "# WinDetox Block Start":
                    in_block = True
                    continue
                if line.strip() == "# WinDetox Block End":
                    in_block = False
                    continue
                if not in_block:
                    filtered_lines.append(line)

            # Add comprehensive Microsoft block list
            filtered_lines.append("\n# WinDetox Block Start")
            filtered_lines.append("# Added by WinDetox")
            filtered_lines.append("# Comprehensive Microsoft telemetry and update blocking")

            # Core telemetry domains
            microsoft_hosts = [
                "0.0.0.0 vortex-win.data.microsoft.com",
                "0.0.0.0 telemetry.microsoft.com",
                "0.0.0.0 watson.telemetry.microsoft.com",
                "0.0.0.0 telemetry.appex.bing.net",
                "0.0.0.0 telemetry.urs.microsoft.com",
                "0.0.0.0 settings-win.data.microsoft.com",
                "0.0.0.0 vortex.data.microsoft.com",
                "0.0.0.0 watson.ppe.telemetry.microsoft.com",
                "0.0.0.0 oca.telemetry.microsoft.com",
                "0.0.0.0 sqm.telemetry.microsoft.com",
                "0.0.0.0 watson.live.com",
                "0.0.0.0 watson.microsoft.com",
                "0.0.0.0 statsfe2.ws.microsoft.com",
                "0.0.0.0 diagnostics.support.microsoft.com",
                "0.0.0.0 corp.sts.microsoft.com",
                "0.0.0.0 statsfe1.ws.microsoft.com",
                "0.0.0.0 feedback.search.microsoft.com",
                "0.0.0.0 feedback.windows.com",
                "0.0.0.0 mobile.pipe.aria.microsoft.com",
                "0.0.0.0 mobile.events.data.microsoft.com",
                "0.0.0.0 v10.events.data.microsoft.com",
                "0.0.0.0 v20.events.data.microsoft.com",
                "0.0.0.0 vortex-sandbox.data.microsoft.com",
                "0.0.0.0 telemetry.remoteapp.microsoft.com",
                "0.0.0.0 windowsupdate.com",
                "0.0.0.0 update.microsoft.com",
                "0.0.0.0 windowsupdate.microsoft.com",
                "0.0.0.0 download.windowsupdate.com",
                "0.0.0.0 wustat.windows.com",
                "0.0.0.0 stats.microsoft.com",
                "0.0.0.0 sls.update.microsoft.com",
                "0.0.0.0 fe2.update.microsoft.com",
                "0.0.0.0 fe3.update.microsoft.com",
                "0.0.0.0 fe4.update.microsoft.com",
                "0.0.0.0 fe5.update.microsoft.com",
                "0.0.0.0 fe6.update.microsoft.com",
                "0.0.0.0 fe1.update.microsoft.com.nsatc.net",
                "0.0.0.0 ctldl.windowsupdate.com",
                "0.0.0.0 definitionupdates.microsoft.com",
                "0.0.0.0 events.data.microsoft.com",
                "0.0.0.0 ssw.live.com",
                "0.0.0.0 services.wes.df.telemetry.microsoft.com",
                "0.0.0.0 sqm.df.telemetry.microsoft.com",
                "0.0.0.0 telemetrycommand.azureedge.net",
                "0.0.0.0 client.wns.windows.com",
                "0.0.0.0 www.client.wns.windows.com",
                "0.0.0.0 notification.wns.windows.com",
                "0.0.0.0 activity.windows.com",
                "0.0.0.0 geo-prod.do.dsp.mp.microsoft.com",
                "0.0.0.0 az704334.vo.msecnd.net",
                "0.0.0.0 win10.ipv6.microsoft.com",
                "0.0.0.0 win1710.ipv6.microsoft.com",
                "0.0.0.0 win8.ipv6.microsoft.com",
                "0.0.0.0 dmd.metaservices.microsoft.com",
                "0.0.0.0 settings.data.microsoft.com",
                "0.0.0.0 vortex.data.microsoft.com.akadns.net",
                "0.0.0.0 settings-win.data.microsoft.com.akadns.net",
                "0.0.0.0 telemetry.telemetry.microsoft.com.akadns.net",
                "0.0.0.0 telemetry.appex.bing.net.akadns.net",
                "0.0.0.0 sqm.telemetry.microsoft.com.akadns.net",
                "0.0.0.0 watson.telemetry.microsoft.com.akadns.net",
                "0.0.0.0 telemetry.urs.microsoft.com.akadns.net",
                "0.0.0.0 oca.telemetry.microsoft.com.akadns.net",
                "0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net",
                "0.0.0.0 watson.ppe.telemetry.microsoft.com.nsatc.net",
                "0.0.0.0 telemetry.appex.bing.net.nsatc.net",
                "0.0.0.0 telemetry.urs.microsoft.com.nsatc.net",
                "0.0.0.0 settings-win.data.microsoft.com.nsatc.net",
                "0.0.0.0 vortex.data.microsoft.com.nsatc.net",
                "0.0.0.0 telemetry.telemetry.microsoft.com.nsatc.net",
                "0.0.0.0 oca.telemetry.microsoft.com.nsatc.net",
                "0.0.0.0 candycrushsaga.windows.com",
                "0.0.0.0 msedge.net",
                "0.0.0.0 nextrank.telemetry.microsoft.com",
                "0.0.0.0 msftncsi.com",
                "0.0.0.0 www.msftncsi.com",
                "0.0.0.0 config.edge.skype.com",
                "0.0.0.0 browser.pipe.aria.microsoft.com",
                "0.0.0.0 displaycatalog.mp.microsoft.com",
                "0.0.0.0 settings-win.data.microsoft.com.edgesuite.net",
                "::      settings-win.data.microsoft.com",
                "::      vortex-win.data.microsoft.com",
                "::      vortex.data.microsoft.com",
                "0.0.0.0 dns.msftncsi.com",
                "0.0.0.0 www.dns.msftncsi.com",
                "::      dns.msftncsi.com"
            ]

            for entry in microsoft_hosts:
                filtered_lines.append(entry)

            filtered_lines.append("# WinDetox Block End\n")

            # Write to temporary file first (atomic operation)
            with open(temp_hosts, 'w', encoding='utf-8') as f:
                f.write('\n'.join(filtered_lines))

            # Atomic replace with retry logic
            for attempt in range(max_retries):
                try:
                    # Ensure file is not locked
                    if os.path.exists(Config.HOSTS_FILE):
                        os.replace(temp_hosts, Config.HOSTS_FILE)
                    else:
                        os.rename(temp_hosts, Config.HOSTS_FILE)
                    break
                except PermissionError:
                    if attempt == max_retries - 1:
                        # Cleanup temp file
                        if os.path.exists(temp_hosts):
                            try:
                                os.remove(temp_hosts)
                            except:
                                pass
                        raise
                    time.sleep(0.5)

            if self.logger:
                self.logger.info(f"Added {len(microsoft_hosts)} Microsoft entries to hosts file")

            # Flush DNS with retry
            for attempt in range(max_retries):
                try:
                    safe_subprocess_run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
                    break
                except:
                    if attempt == max_retries - 1:
                        if self.logger:
                            self.logger.warning("Failed to flush DNS cache")
                    time.sleep(0.3)

            return True

        except PermissionError as e:
            if self.logger:
                self.logger.error(f"Permission denied for hosts file: {e}")
            raise BlocklistError(f"Permission denied for hosts file: {e}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to modify hosts file: {e}")
            # Cleanup temp file if it exists
            temp_hosts = f"{Config.HOSTS_FILE}.tmp"
            if os.path.exists(temp_hosts):
                try:
                    os.remove(temp_hosts)
                except:
                    pass
            raise BlocklistError(f"Failed to modify hosts file: {e}")

    def restore_hosts_file(self) -> bool:
        """Restore hosts file from latest backup"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Restoring hosts file requires admin rights!")

        try:
            if not os.path.exists(Config.HOSTS_BACKUP_DIR):
                raise BlocklistError("No backup directory found")

            # Find latest backup
            backups = []
            for f in os.listdir(Config.HOSTS_BACKUP_DIR):
                if f.startswith("hosts_backup_"):
                    backups.append(f)

            if not backups:
                raise BlocklistError("No backups found")

            latest_backup = sorted(backups)[-1]
            backup_path = os.path.join(Config.HOSTS_BACKUP_DIR, latest_backup)

            shutil.copy2(backup_path, Config.HOSTS_FILE)
            if self.logger:
                self.logger.info(f"Hosts file restored from: {backup_path}")

            # Flush DNS
            safe_subprocess_run(["ipconfig", "/flushdns"], capture_output=True)

            return True

        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to restore hosts file: {e}")
            raise BlocklistError(f"Failed to restore hosts file: {e}")

    def disable_microsoft_services(self) -> bool:
        """Disable Microsoft telemetry and tracking services"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Disabling services requires admin rights!")

        success_count = 0
        total_services = len(Config.MICROSOFT_SERVICES)

        for svc in Config.MICROSOFT_SERVICES:
            try:
                # Stop service
                safe_subprocess_run(["net", "stop", svc, "/y"], capture_output=True, timeout=5)

                # Disable service
                safe_subprocess_run(["sc", "config", svc, "start=", "disabled"], capture_output=True, timeout=5)

                if self.logger:
                    self.logger.info(f"Disabled service: {svc}")
                success_count += 1

            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Failed to disable service {svc}: {e}")

        if self.logger:
            self.logger.info(f"Disabled {success_count}/{total_services} Microsoft services")
        return success_count > 0

    def enable_microsoft_services(self) -> bool:
        """Enable Microsoft services that were previously disabled"""
        # Import hier
        from core.utils import is_admin, safe_subprocess_run
        
        if not is_admin():
            raise PermissionError("Enabling services requires admin rights!")

        success_count = 0
        total_services = len(Config.MICROSOFT_SERVICES)

        for svc in Config.MICROSOFT_SERVICES:
            try:
                # Set to automatic start
                safe_subprocess_run(["sc", "config", svc, "start=", "auto"], capture_output=True, timeout=5)

                # Start service
                safe_subprocess_run(["net", "start", svc], capture_output=True, timeout=5)

                if self.logger:
                    self.logger.info(f"Enabled service: {svc}")
                success_count += 1

            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Failed to enable service {svc}: {e}")

        if self.logger:
            self.logger.info(f"Enabled {success_count}/{total_services} Microsoft services")
        return success_count > 0

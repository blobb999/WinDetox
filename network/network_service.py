"""
Network Service Module for WinDetox
Version: 1.0
Description: Facade class for high-level network operations
"""

import ipaddress
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Import from existing modules
from core.exceptions import ValidationError, BlocklistError, FirewallError
from core.logger import Logger
from network.blocklist_manager import BlocklistManager
from network.firewall_manager import FirewallManager


class NetworkService:
    """Facade class for high-level network operations"""
    
    def __init__(self, 
                 logger: Logger = None,
                 blocklist_manager: BlocklistManager = None,
                 firewall_manager: FirewallManager = None):
        self.logger = logger or Logger()
        self.blocklist = blocklist_manager or BlocklistManager(logger=self.logger)
        self.firewall = firewall_manager or FirewallManager(logger=self.logger)
        
    def block_ips(self, ips: List[str], source: str = "Manual") -> Dict[str, Any]:
        """Block IPs with coordinated blocklist and firewall operations"""
        results = {
            "total": len(ips),
            "blocked": 0,
            "failed": [],
            "errors": []
        }
        
        for ip in ips:
            try:
                # Validate IP
                if not self._validate_ip(ip):
                    raise ValidationError(f"Invalid IP address: {ip}")
                
                # Add to blocklist
                self.blocklist.add_ip(ip, source)
                
                # Apply firewall rule if admin rights
                if self.firewall.check_admin_rights():
                    self.firewall.apply_windows_firewall_rule(ip, add=True)
                
                results["blocked"] += 1
                
            except (ValidationError, BlocklistError, FirewallError) as e:
                results["failed"].append(ip)
                results["errors"].append(str(e))
                self.logger.error(f"Failed to block IP {ip}: {e}")
        
        return results
    
    def unblock_ips(self, ips: List[str]) -> Dict[str, Any]:
        """Unblock IPs from blocklist and firewall"""
        results = {
            "total": len(ips),
            "unblocked": 0,
            "failed": [],
            "errors": []
        }
        
        for ip in ips:
            try:
                # Remove from blocklist
                self.blocklist.remove_ip(ip)
                
                # Remove firewall rule if admin rights
                if self.firewall.check_admin_rights():
                    self.firewall.apply_windows_firewall_rule(ip, add=False)
                
                results["unblocked"] += 1
                
            except (BlocklistError, FirewallError) as e:
                results["failed"].append(ip)
                results["errors"].append(str(e))
                self.logger.error(f"Failed to unblock IP {ip}: {e}")
        
        return results
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            return bool(ipaddress.ip_address(ip))
        except ValueError:
            return False
    
    def get_blocklist_stats(self) -> Dict[str, Any]:
        """Get statistics about the blocklist"""
        return {
            "total_blocked": len(self.blocklist.blocked_ips),
            "firewall_applied": len(self.blocklist._firewall_applied_ips),
            "sources": len(self.blocklist.sources)
        }
    
    def clear_blocklist(self) -> bool:
        """Clear the entire blocklist"""
        try:
            # Get all blocked IPs
            all_ips = list(self.blocklist.blocked_ips)
            
            # Remove from firewall first
            for ip in all_ips:
                if self.firewall.check_admin_rights():
                    self.firewall.apply_windows_firewall_rule(ip, add=False)
            
            # Clear blocklist
            self.blocklist.blocked_ips.clear()
            self.blocklist.sources.clear()
            self.blocklist._firewall_applied_ips.clear()
            
            # Save empty blocklist
            self.blocklist.save_blocklist()
            
            self.logger.info(f"Cleared blocklist with {len(all_ips)} IPs")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to clear blocklist: {e}")
            return False

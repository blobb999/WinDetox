# firewall_manager.py
"""
Firewall Manager - Windows Firewall operations with safe command execution
"""
import subprocess
import time
import ipaddress
import re
from typing import List, Tuple, Callable, Dict, Any, Set

from core.exceptions import (
    FirewallError, PermissionError, ValidationError, DetailedError
)
from core.utils import safe_subprocess_run, is_admin
from core.config import Config
from core.logger import Logger
from network.ip_validator import IPValidator  # NEUER IMPORT


class FirewallManager:
    """Manages Windows Firewall operations with safe command execution"""
    
    def __init__(self, logger: Logger = None):
        self.logger = logger or Logger()
        self._already_blocked_in_firewall = set() 
        self.ip_validator = IPValidator()  # IP Validator Instanz erstellen
    
    def check_admin_rights(self) -> bool:
        """Check if program is running with admin rights"""
        return is_admin()
    
    def _escape_firewall_parameter(self, param: str) -> str:
        """Escape Windows command parameters with strict validation"""
        if not param:
            raise ValidationError("Parameter cannot be empty")
        
        # Maximum length check
        if len(param) > 255:
            raise ValidationError(f"Parameter too long: {len(param)} chars (max 255)")
        
        # Strict whitelist validation based on parameter type
        # For rule names: alphanumeric, underscore, dash, dot
        if param.startswith("WinDetox_"):
            if not re.match(r'^[a-zA-Z0-9_\-\.]+$', param):
                raise ValidationError(f"Invalid characters in rule name: {param}")
        
        # For IP addresses: validate as IP (already done before, but double-check)
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', param):
            try:
                ipaddress.ip_address(param)
            except ValueError:
                raise ValidationError(f"Invalid IP address format: {param}")
        
        # For protocols: strict whitelist
        elif param in ["any", "tcp", "udp", "icmpv4", "icmpv6"]:
            pass  # Valid protocol
        
        # For directions: strict whitelist
        elif param in ["in", "out"]:
            pass  # Valid direction
        
        # For actions: strict whitelist
        elif param in ["block", "allow"]:
            pass  # Valid action
        
        # For profiles: strict whitelist
        elif param in ["any", "domain", "private", "public"]:
            pass  # Valid profile
        
        # For other parameters: strict alphanumeric
        else:
            if not re.match(r'^[a-zA-Z0-9_\-\.]+$', param):
                raise ValidationError(f"Invalid parameter format: {param}")
        
        # Remove potential command separators (defense in depth)
        dangerous_chars = ['&', '|', ';', '\n', '\r', '`', '$', '(', ')', '<', '>', '"', "'"]
        for char in dangerous_chars:
            if char in param:
                raise ValidationError(f"Dangerous character detected: {char}")
        
        # Escape for Windows cmd (use quotes for parameters with spaces)
        if ' ' in param:
            # Escape internal quotes first
            param = param.replace('"', '""')
            return f'"{param}"'
        
        return param

    def apply_firewall_rules_bulk(self, ips: List[str], add: bool = True, 
                                 progress_callback: Callable = None) -> Tuple[int, List[str]]:
        """Block or unblock hundreds of IPs at once with progress feedback - RETURNS successful IPs"""
        if not self.check_admin_rights():
            raise PermissionError("Bulk firewall operations require admin rights!")
        
        total = len(ips)
        if total == 0:
            if progress_callback:
                progress_callback(0, 0, "No IPs to process")
            return 0, []  # Return empty list for successful operations
        
        if add:
            action_text = f"Starting bulk blocking of {total} IPs..."
        else:
            action_text = f"Starting bulk removal of {total} firewall rules..."
            
        if progress_callback:
            progress_callback(0, total, action_text)
        
        success_count = 0
        successful_ips = []  # Track which IPs were successfully processed
        failed_ips = []
        skipped_duplicates = 0  # Track skipped duplicate IPs
        
        for idx, ip in enumerate(ips):
            try:
                # Validate IP first
                is_valid, error = self.ip_validator.validate(ip)
                if not is_valid:
                    self.logger.warning(f"Skipping invalid IP {ip}: {error}")
                    failed_ips.append(ip)
                    continue
                
                # When adding rules: Check if IP is already blocked in firewall
                if add and ip in self._already_blocked_in_firewall:
                    skipped_duplicates += 1
                    if progress_callback and idx % 10 == 0:
                        progress_callback(idx + 1, total, f"Skipping duplicate IP: {ip}")
                    continue
                
                # When removing rules: Check if IP is in firewall tracking
                if not add and ip not in self._already_blocked_in_firewall:
                    if progress_callback and idx % 10 == 0:
                        progress_callback(idx + 1, total, f"Skipping IP not in firewall: {ip}")
                    continue
                
                if progress_callback:
                    if add:
                        progress_text = f"Blocking IP {idx + 1}/{total}: {ip}"
                    else:
                        progress_text = f"Removing rule {idx + 1}/{total}: {ip}"
                    progress_callback(idx + 1, total, progress_text)
                
                # Use atomic method for individual operations
                if self.apply_windows_firewall_rule_atomic(ip, add):
                    success_count += 1
                    successful_ips.append(ip)  # Add to successful list
                    if add:
                        self._already_blocked_in_firewall.add(ip)
                    else:
                        self._already_blocked_in_firewall.discard(ip)
                        
                    if progress_callback and idx % 10 == 0:
                        if add:
                            status_text = f"{success_count} of {total} IPs blocked ({skipped_duplicates} duplicates skipped)"
                        else:
                            status_text = f"{success_count} of {total} rules removed"
                        progress_callback(idx + 1, total, status_text)
                else:
                    failed_ips.append(ip)
                    
            except Exception as e:
                self.logger.error(f"Failed to process IP {ip}: {e}")
                failed_ips.append(ip)
            
            # Pause after every 50 IPs to avoid overloading the Windows Firewall
            if idx % 50 == 49:
                if progress_callback:
                    if add:
                        progress_status = f"Pausing... ({success_count} blocked, {skipped_duplicates} duplicates skipped)"
                    else:
                        progress_status = f"Pausing... ({success_count} removed)"
                    progress_callback(idx + 1, total, progress_status)
                time.sleep(Config.BULK_BLOCK_DELAY)
            
            # Small delay to keep GUI responsive
            time.sleep(0.01)
        
        if progress_callback:
            if failed_ips:
                if add:
                    result_text = f"Done! {success_count} blocked, {skipped_duplicates} duplicates skipped, {len(failed_ips)} failed"
                else:
                    result_text = f"Done! {success_count} removed, {len(failed_ips)} failed"
                progress_callback(total, total, result_text)
            else:
                if add:
                    result_text = f"✅ Success! {success_count} IPs blocked ({skipped_duplicates} duplicates skipped)"
                else:
                    result_text = f"✅ Success! All {success_count} firewall rules removed"
                progress_callback(total, total, result_text)
        
        if add:
            self.logger.info(f"Bulk blocking completed: {success_count}/{total} successful, {skipped_duplicates} duplicates skipped")
        else:
            self.logger.info(f"Bulk removal completed: {success_count}/{total} successful")
        
        if failed_ips:
            self.logger.warning(f"{len(failed_ips)} IPs could not be processed")
            for ip in failed_ips[:5]:
                self.logger.warning(f"  - {ip}")
        
        # Return both count and list of successful IPs
        return success_count, successful_ips
    
    def apply_windows_firewall_rule(self, ip: str, add: bool = True) -> bool:
        """Apply individual firewall rule with detailed error reporting"""
        if not self.check_admin_rights():
            raise DetailedError(
                "Firewall rule requires admin rights",
                context={
                    "ip": ip,
                    "action": "add" if add else "remove",
                    "is_admin": False
                },
                suggestion="Right-click the application and select 'Run as administrator'"
            )
        
        # ÄNDERUNG HIER:
        is_valid, error = self.ip_validator.validate(ip)
        
        if not is_valid:
            raise DetailedError(
                f"Invalid IP address: {error}",
                context={
                    "ip": ip,
                    "validation_error": error
                },
                suggestion="Ensure IP is in format: 192.168.1.1 (IPv4 only)"
            )
        
        rule_name_base = f"WinDetox_Block_{ip.replace('.', '_')}"
        rules = [
            (f"{rule_name_base}_Any", "any"),
            (f"{rule_name_base}_ICMP", "icmpv4")
        ]
        
        success = True
        failed_rules = []
        
        try:
            for rule_name, protocol in rules:
                try:
                    # Escape parameters with validation
                    safe_rule_name = self._escape_firewall_parameter(rule_name)
                    safe_ip = self._escape_firewall_parameter(ip)
                    safe_protocol = self._escape_firewall_parameter(protocol)
                except ValidationError as e:
                    raise DetailedError(
                        f"Parameter validation failed",
                        context={
                            "rule_name": rule_name,
                            "ip": ip,
                            "protocol": protocol,
                            "validation_error": str(e)
                        },
                        suggestion="This is likely a bug. Please report to developer."
                    )
                
                if add:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={safe_rule_name}",
                        "dir=in",
                        "action=block",
                        f"remoteip={safe_ip}",
                        "enable=yes",
                        "profile=any",
                        f"protocol={safe_protocol}"
                    ]
                else:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={safe_rule_name}"
                    ]
                
                try:
                    result = safe_subprocess_run(
                        cmd,
                        capture_output=True,
                        text=True,
                        max_retries=2,
                        retry_delay=0.5
                    )
                except FirewallError as e:
                    failed_rules.append((rule_name, str(e)))
                    continue
                
                if result.returncode != 0 and not (not add and "not found" in result.stderr.lower()):
                    error_output = result.stderr[:200] if result.stderr else "No error output"
                    failed_rules.append((rule_name, error_output))
                    success = False
            
            if failed_rules:
                raise DetailedError(
                    f"Failed to {'add' if add else 'remove'} {len(failed_rules)} firewall rule(s)",
                    context={
                        "ip": ip,
                        "action": "add" if add else "remove",
                        "failed_rules": [name for name, _ in failed_rules],
                        "errors": [error for _, error in failed_rules]
                    },
                    suggestion="Check Windows Firewall service is running and not blocked by antivirus"
                )
            
            if success and add:
                self._already_blocked_in_firewall.add(ip)
            elif success and not add:
                self._already_blocked_in_firewall.discard(ip)
            
            return success
            
        except DetailedError:
            raise
        except Exception as e:
            raise DetailedError(
                f"Unexpected firewall error",
                context={
                    "ip": ip,
                    "action": "add" if add else "remove",
                    "exception_type": type(e).__name__,
                    "exception_message": str(e)
                },
                suggestion="This may be caused by antivirus software. Try temporarily disabling it."
            )

    def _apply_single_rule(self, rule_name: str, ip: str, protocol: str, add: bool) -> bool:
        """Apply a single firewall rule"""
        try:
            safe_rule_name = self._escape_firewall_parameter(rule_name)
            safe_ip = self._escape_firewall_parameter(ip)
            safe_protocol = self._escape_firewall_parameter(protocol)
            
            if add:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={safe_rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={safe_ip}",
                    "enable=yes",
                    "profile=any",
                    f"protocol={safe_protocol}"
                ]
            else:
                cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={safe_rule_name}"
                ]
            
            result = safe_subprocess_run(
                cmd,
                capture_output=True,
                text=True
            )
            
            return result.returncode == 0 or (not add and "not found" in result.stderr.lower())
        except Exception as e:
            self.logger.error(f"Exception in _apply_single_rule: {e}")
            return False

    def _rollback_rules(self, rules: List[Tuple[str, str]]):
        """Rollback applied rules on failure"""
        for rule_name, _ in rules:
            try:
                safe_rule_name = self._escape_firewall_parameter(rule_name)
                safe_subprocess_run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={safe_rule_name}"
                ], capture_output=True)
            except Exception:
                pass

    def apply_windows_firewall_rule_atomic(self, ip: str, add: bool = True) -> bool:
        """Apply firewall rules atomically with automatic rollback on failure"""
        rules_applied = []
        
        try:
            is_valid, error = self.ip_validator.validate(ip)
            if not is_valid:
                raise ValidationError(f"Invalid IP address {ip}: {error}")
            
            # Define all rules that need to be applied
            protocols = ["any", "icmpv4"]
            rule_name_base = f"WinDetox_Block_{ip.replace('.', '_')}"
            
            # Apply each rule
            for protocol in protocols:
                rule_name = f"{rule_name_base}_{protocol}"
                safe_rule_name = self._escape_firewall_parameter(rule_name)
                safe_ip = self._escape_firewall_parameter(ip)
                safe_protocol = self._escape_firewall_parameter(protocol)
                
                if add:
                    # Check if rule already exists
                    check_cmd = [
                        "netsh", "advfirewall", "firewall", "show", "rule",
                        f"name={safe_rule_name}"
                    ]
                    
                    try:
                        check_result = safe_subprocess_run(
                            check_cmd,
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        
                        # If rule exists, skip (already applied)
                        if check_result.returncode == 0 and "Rule Name:" in check_result.stdout:
                            self.logger.debug(f"Rule {rule_name} already exists, skipping")
                            rules_applied.append(rule_name)
                            continue
                            
                    except Exception as e:
                        self.logger.debug(f"Rule check failed for {rule_name}: {e}")
                    
                    # Add new rule
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={safe_rule_name}",
                        "dir=in",
                        "action=block",
                        f"remoteip={safe_ip}",
                        "enable=yes",
                        "profile=any",
                        f"protocol={safe_protocol}"
                    ]
                else:
                    # Delete rule
                    cmd = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={safe_rule_name}"
                    ]
                
                try:
                    result = safe_subprocess_run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=Config.FIREWALL_COMMAND_TIMEOUT
                    )
                    
                    # Check if operation succeeded
                    if result.returncode != 0:
                        # For delete operations, "not found" is acceptable
                        if not add and "not found" in result.stderr.lower():
                            self.logger.debug(f"Rule {rule_name} not found (already deleted)")
                            continue
                        else:
                            # Operation failed - trigger rollback
                            raise FirewallError(
                                f"Failed to {'add' if add else 'delete'} rule {rule_name}: "
                                f"{result.stderr}"
                            )
                    
                    # Success - track this rule
                    rules_applied.append(rule_name)
                    self.logger.debug(f"Successfully {'added' if add else 'deleted'} rule: {rule_name}")
                    
                except subprocess.TimeoutExpired:
                    raise FirewallError(f"Timeout applying rule {rule_name}")
                except Exception as e:
                    raise FirewallError(f"Exception applying rule {rule_name}: {e}")
            
            # All rules applied successfully
            if add:
                self._already_blocked_in_firewall.add(ip)
            else:
                self._already_blocked_in_firewall.discard(ip)
            
            return True
            
        except (ValidationError, FirewallError) as e:
            # Rollback all applied rules
            if add and rules_applied:
                self.logger.warning(f"Rolling back {len(rules_applied)} rules for {ip} due to error: {e}")
                
                for rule_name in rules_applied:
                    try:
                        safe_rule_name = self._escape_firewall_parameter(rule_name)
                        rollback_cmd = [
                            "netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={safe_rule_name}"
                        ]
                        
                        rollback_result = safe_subprocess_run(
                            rollback_cmd,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if rollback_result.returncode == 0:
                            self.logger.debug(f"Rolled back rule: {rule_name}")
                        else:
                            self.logger.error(f"Failed to rollback rule {rule_name}: {rollback_result.stderr}")
                            
                    except Exception as rollback_error:
                        self.logger.error(f"Rollback exception for {rule_name}: {rollback_error}")
            
            # Re-raise the original error
            raise
        
        except Exception as e:
            # Unexpected error - still try to rollback
            if add and rules_applied:
                self.logger.error(f"Unexpected error, attempting rollback of {len(rules_applied)} rules")
                for rule_name in rules_applied:
                    try:
                        safe_rule_name = self._escape_firewall_parameter(rule_name)
                        safe_subprocess_run([
                            "netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={safe_rule_name}"
                        ], capture_output=True, timeout=10)
                    except:
                        pass
            
            raise FirewallError(f"Atomic firewall operation failed: {e}")
    
    def apply_nuclear_firewall_rule(self, add: bool = True, allow_dns: bool = True) -> bool:
        """Apply or remove nuclear option firewall rule (block all traffic)"""
        if not self.check_admin_rights():
            raise PermissionError("Nuclear option requires admin rights!")
        
        action = "add" if add else "delete"
        success_count = 0
        
        rules_to_process = [
            ("WinDetox_Nuclear_In", "in"),
            ("WinDetox_Nuclear_Out", "out"),
        ]
        
        for rule_name, direction in rules_to_process:
            try:
                safe_rule_name = self._escape_firewall_parameter(rule_name)
                safe_direction = self._escape_firewall_parameter(direction)
                
                if add:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={safe_rule_name}",
                        f"dir={safe_direction}",
                        "action=block",
                        "remoteip=any",
                        "enable=yes",
                        "profile=any",
                        "protocol=any"
                    ]
                else:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={safe_rule_name}"
                    ]
                
                result = safe_subprocess_run(
                    cmd,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0 or (action == "delete" and "not found" in result.stderr.lower()):
                    success_count += 1
                    self.logger.info(f"Nuclear rule {rule_name} {action}ed")
                else:
                    self.logger.warning(f"Failed to {action} nuclear rule {rule_name}: {result.stderr}")
                
            except Exception as e:
                self.logger.error(f"Exception with nuclear rule: {e}")
                continue
        
        # Allow loopback traffic
        if add and success_count > 0:
            try:
                safe_subprocess_run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=WinDetox_Allow_Loopback",
                    "dir=out", "action=allow", "remoteip=127.0.0.1",
                    "enable=yes", "profile=any", "protocol=any"
                ], capture_output=True)
                self.logger.info("Loopback allowance rule added")
            except Exception as e:
                self.logger.error(f"Failed to add loopback rule: {e}")
        
        # Allow DNS (UDP port 53) for recovery
        if add and allow_dns and success_count > 0:
            try:
                safe_subprocess_run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=WinDetox_Allow_DNS",
                    "dir=out", "action=allow", "protocol=UDP", "remoteport=53",
                    "enable=yes", "profile=any"
                ], capture_output=True)
                self.logger.info("DNS allowance rule added")
            except Exception as e:
                self.logger.error(f"Failed to add DNS rule: {e}")
        
        # Block DoT (DNS over TLS) to prevent bypass via TCP 853
        if add and success_count > 0:
            try:
                safe_subprocess_run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=WinDetox_Block_DoT_DoH",
                    "dir=out", "action=block", "protocol=TCP", "remoteport=853",
                    "enable=yes", "profile=any"
                ], capture_output=True)
                self.logger.info("DoT (TCP 853) blocking rule added")
            except Exception as e:
                self.logger.error(f"Failed to add DoT blocking rule: {e}")
        
        return success_count >= 1
    
    def remove_all_nuclear_rules(self):
        """Remove all nuclear firewall rules"""
        rules_to_remove = [
            "WinDetox_Nuclear_In",
            "WinDetox_Nuclear_Out",
            "WinDetox_Allow_Loopback",
            "WinDetox_Allow_DNS",
            "WinDetox_Block_DoT_DoH",
        ]
        
        for rule in rules_to_remove:
            try:
                safe_rule = self._escape_firewall_parameter(rule)
                safe_subprocess_run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={safe_rule}"
                ], capture_output=True)
            except:
                pass

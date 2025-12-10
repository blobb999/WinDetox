"""
Turbo DNS Resolver - High-performance parallel DNS resolution
"""
import socket
import time
import concurrent.futures
from typing import List, Dict, Tuple, Optional, Callable
import threading

from network.ip_info_cache import IPAnalyzer
from core.config import Config


class TurboDNSResolver:
    """High-performance parallel DNS resolver with IP analysis"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.ip_analyzer = IPAnalyzer()
        self.cancelled = threading.Event()
        self.active_futures = []
    
    def resolve_single_ip(self, ip: str, idx: int, timeout: float = 0.8) -> Tuple[str, str, bool, bool]:
        """
        Resolve single IP with error handling and extended analysis
        
        Returns:
            (hostname, status, is_microsoft, is_cloud)
        """
        if self.cancelled.is_set():
            return None, "cancelled", False, False
        
        try:
            # Try reverse DNS lookup
            socket.setdefaulttimeout(timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname:
                # Clean up hostname
                hostname = hostname.split('.')[0]
                status = "success"
            else:
                # No reverse DNS, analyze IP
                provider = self.ip_analyzer.get_provider_info(ip)
                if provider != "Unknown ISP":
                    hostname = f"{provider}"
                else:
                    hostname = "no-reverse-dns"
                status = "success"
                
        except socket.herror:
            # No reverse DNS entry, analyze IP
            provider = self.ip_analyzer.get_provider_info(ip)
            if provider != "Unknown ISP":
                hostname = f"{provider}"
                status = "success"
            else:
                hostname = "no-reverse-dns"
                status = "success"
        except socket.gaierror:
            hostname = "invalid-ip"
            status = "error"
        except socket.timeout:
            hostname = "timeout"
            status = "timeout"
        except Exception as e:
            if self.logger:
                self.logger.debug(f"DNS resolve error for {ip}: {e}")
            hostname = "error"
            status = "error"
        
        # Determine IP type
        is_microsoft = self.ip_analyzer.is_microsoft_ip(ip)
        is_cloud = self.ip_analyzer.is_cloud_ip(ip) and not is_microsoft
        
        return hostname, status, is_microsoft, is_cloud
    
    def batch_resolve(self, ips: List[str], 
                     progress_callback: Optional[Callable] = None,
                     result_callback: Optional[Callable] = None) -> Dict[str, Dict]:
        """
        Resolve multiple IPs in parallel with progress reporting
        
        Args:
            ips: List of IP addresses to resolve
            progress_callback: Called with (current, total, message)
            result_callback: Called for each resolved IP with (idx, ip, hostname, status, is_microsoft, is_cloud)
            
        Returns:
            Dictionary with statistics
        """
        self.cancelled.clear()
        total = len(ips)
        
        if total == 0:
            return {"total": 0, "resolved": 0, "timeout": 0, "error": 0, "microsoft": 0, "cloud": 0}
        
        # Statistics
        stats = {
            "total": total,
            "resolved": 0,
            "timeout": 0,
            "error": 0,
            "microsoft": 0,
            "cloud": 0
        }
        
        # Quick analysis phase
        if progress_callback and not self.cancelled.is_set():
            try:
                progress_callback(0, total, "Phase 1: Quick IP analysis...")
            except:
                # GUI might be closed
                self.cancel()
                return stats
        
        # Pre-analyze IPs for Microsoft/Cloud detection
        microsoft_count = 0
        cloud_count = 0
        
        for idx, ip in enumerate(ips):
            if self.cancelled.is_set():
                break
            
            is_microsoft = self.ip_analyzer.is_microsoft_ip(ip)
            is_cloud = self.ip_analyzer.is_cloud_ip(ip) and not is_microsoft
            
            if is_microsoft:
                microsoft_count += 1
            elif is_cloud:
                cloud_count += 1
            
            if idx % 100 == 0 and progress_callback and not self.cancelled.is_set():
                try:
                    progress_callback(idx, total, f"Analyzing {idx}/{total} IPs...")
                except:
                    # GUI might be closed
                    self.cancel()
                    return stats
        
        stats["microsoft"] = microsoft_count
        stats["cloud"] = cloud_count
        
        if progress_callback and not self.cancelled.is_set():
            try:
                progress_callback(total, total, f"Phase 1 complete: {microsoft_count} Microsoft, {cloud_count} Cloud IPs")
            except:
                # GUI might be closed
                self.cancel()
                return stats
        
        # DNS resolution phase
        if progress_callback and not self.cancelled.is_set():
            try:
                progress_callback(0, total, "Phase 2: Starting parallel DNS resolution...")
            except:
                # GUI might be closed
                self.cancel()
                return stats
        
        # Save original timeout
        original_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(0.8)
        except:
            pass
        
        # Use ThreadPoolExecutor for parallel DNS queries
        max_workers = min(Config.MAX_CONCURRENT_DNS_QUERIES, total)
        
        # Batch processing for better performance
        batch_size = 100
        batches = [ips[i:i + batch_size] for i in range(0, total, batch_size)]
        
        for batch_num, batch in enumerate(batches):
            if self.cancelled.is_set():
                break
            
            if progress_callback and not self.cancelled.is_set():
                try:
                    progress_callback(
                        batch_num * batch_size, 
                        total,
                        f"Batch {batch_num+1}/{len(batches)}: Resolving {len(batch)} IPs..."
                    )
                except:
                    # GUI might be closed
                    self.cancel()
                    break
            
            # Process batch in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Create futures
                future_to_data = {}
                for idx_in_batch, ip in enumerate(batch):
                    if self.cancelled.is_set():
                        break
                    
                    global_idx = batch_num * batch_size + idx_in_batch
                    future = executor.submit(self.resolve_single_ip, ip, global_idx)
                    future_to_data[future] = (global_idx, ip)
                    self.active_futures.append(future)
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_data):
                    if self.cancelled.is_set():
                        break
                    
                    idx, ip = future_to_data[future]
                    try:
                        hostname, status, is_microsoft, is_cloud = future.result(
                            timeout=Config.DNS_TIMEOUT + 1
                        )
                        
                        # Update statistics
                        if status == "success":
                            stats["resolved"] += 1
                        elif status == "timeout":
                            stats["timeout"] += 1
                        else:
                            stats["error"] += 1
                        
                        # Call result callback (if GUI still exists)
                        if result_callback and not self.cancelled.is_set():
                            try:
                                result_callback(idx, ip, hostname, status, is_microsoft, is_cloud)
                            except:
                                # GUI window closed, cancel operation
                                self.cancel()
                        
                        # Update progress periodically
                        processed = stats["resolved"] + stats["timeout"] + stats["error"]
                        if processed % 20 == 0 and progress_callback and not self.cancelled.is_set():
                            try:
                                progress_callback(
                                    batch_num * batch_size + idx_in_batch,
                                    total,
                                    f"Resolved: {stats['resolved']}, "
                                    f"Microsoft: {stats['microsoft']}, Cloud: {stats['cloud']}"
                                )
                            except:
                                # GUI might be closed
                                self.cancel()
                                
                    except concurrent.futures.TimeoutError:
                        stats["timeout"] += 1
                        if result_callback and not self.cancelled.is_set():
                            try:
                                result_callback(idx, ip, "timeout", "timeout", False, False)
                            except:
                                self.cancel()
                    except Exception as e:
                        if self.logger:
                            self.logger.debug(f"Future processing error: {e}")
                        stats["error"] += 1
                
                # Clean up futures
                self.active_futures = [f for f in self.active_futures if not f.done()]
            
            # Update progress after each batch
            processed = min((batch_num + 1) * batch_size, total)
            if progress_callback and not self.cancelled.is_set():
                try:
                    progress_callback(
                        processed, total,
                        f"Batch {batch_num+1}/{len(batches)} complete. "
                        f"Resolved: {stats['resolved']}/{processed}, "
                        f"Microsoft: {stats['microsoft']}, Cloud: {stats['cloud']}"
                    )
                except:
                    # GUI might be closed
                    self.cancel()
                    break
            
            # Small delay between batches
            if not self.cancelled.is_set() and batch_num < len(batches) - 1:
                time.sleep(0.1)
        
        # Restore original timeout
        try:
            socket.setdefaulttimeout(original_timeout)
        except:
            pass
        
        return stats
    
    def cancel(self):
        """Cancel ongoing resolution"""
        self.cancelled.set()
        
        # Cancel all active futures
        for future in self.active_futures:
            if not future.done():
                try:
                    future.cancel()
                except:
                    pass
        
        if self.logger:
            self.logger.debug("DNS resolution cancelled")
    
    def quick_analyze_ips(self, ips: List[str]) -> Tuple[int, int]:
        """
        Quick analysis of IPs for Microsoft/Cloud detection
        
        Returns:
            (microsoft_count, cloud_count)
        """
        microsoft_count = 0
        cloud_count = 0
        
        for ip in ips:
            if self.ip_analyzer.is_microsoft_ip(ip):
                microsoft_count += 1
            elif self.ip_analyzer.is_cloud_ip(ip):
                cloud_count += 1
        
        return microsoft_count, cloud_count

"""
IP Validator Module for WinDetox
Version: 1.0
Description: IP validation with caching for performance
"""

import ipaddress
import re
from typing import Dict, Tuple, Optional


class IPValidator:
    """IP validation with caching for performance"""
    
    def __init__(self, cache_size: int = 10000):
        self._validation_cache: Dict[str, Tuple[bool, str]] = {}
        self._normalization_cache: Dict[str, str] = {}
        self._cache_size = cache_size
    
    def validate(self, ip: str) -> Tuple[bool, str]:
        """Validate IP with caching"""
        if ip in self._validation_cache:
            return self._validation_cache[ip]
        
        result = self._validate_uncached(ip)
        
        if len(self._validation_cache) >= self._cache_size:
            self._validation_cache.pop(next(iter(self._validation_cache)))
        
        self._validation_cache[ip] = result
        return result
    
    def _validate_uncached(self, ip: str) -> Tuple[bool, str]:
        """Internal validation without caching"""
        if not ip:
            return False, "IP address is empty"
        
        if ':' in ip:
            return False, "IPv6 addresses are not supported"
        
        try:
            addr = ipaddress.ip_address(ip)
            if not isinstance(addr, ipaddress.IPv4Address):
                return False, "Not an IPv4 address"
            return True, ""
        except ValueError as e:
            return False, f"Invalid IP address: {str(e)}"
    
    def normalize(self, ip: str) -> Optional[str]:
        """Normalize IP with caching"""
        if ip in self._normalization_cache:
            return self._normalization_cache[ip]
        
        is_valid, error = self.validate(ip)
        if not is_valid:
            return None
        
        try:
            parts = ip.split('.')
            normalized = '.'.join(str(int(part)) for part in parts)
            
            if len(self._normalization_cache) >= self._cache_size:
                self._normalization_cache.pop(next(iter(self._normalization_cache)))
            
            self._normalization_cache[normalized] = normalized
            return normalized
        except:
            return None
    
    def clear_cache(self):
        """Clear all caches"""
        self._validation_cache.clear()
        self._normalization_cache.clear()


# Global validator instance
_ip_validator = IPValidator()


def validate_ip_address(ip: str) -> Tuple[bool, str]:
    """
    Validate an IP address using the global IP validator.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    return _ip_validator.validate(ip)


def normalize_ip_address(ip: str) -> Optional[str]:
    """
    Normalize an IP address using the global IP validator.
    
    Args:
        ip: IP address string to normalize
        
    Returns:
        Normalized IP string or None if invalid
    """
    return _ip_validator.normalize(ip)


def clear_ip_cache():
    """Clear the IP validator cache"""
    _ip_validator.clear_cache()

# exceptions.py
"""
Custom exceptions for WinDetox
"""
from typing import Dict, Any


class WinDetoxError(Exception):
    """Base exception for all WinDetox errors"""
    pass


class SecurityError(WinDetoxError):
    """Security-related errors (signature verification, etc.)"""
    pass


class FirewallError(WinDetoxError):
    """Firewall operation failed"""
    pass


class BlocklistError(WinDetoxError):
    """Blocklist operation failed"""
    pass


class UpdateError(WinDetoxError):
    """Update-related errors"""
    pass


class ValidationError(WinDetoxError):
    """Input validation failed"""
    pass


class PermissionError(WinDetoxError):
    """Permission/Admin rights error"""
    pass


class DetailedError(WinDetoxError):
    """Error with detailed context information"""
    
    def __init__(self, message: str, context: Dict[str, Any] = None, suggestion: str = None):
        self.message = message
        self.context = context or {}
        self.suggestion = suggestion
        super().__init__(self._format_message())
    
    def _format_message(self) -> str:
        """Format error message with context"""
        parts = [f"Error: {self.message}"]
        
        if self.context:
            parts.append("\nContext:")
            for key, value in self.context.items():
                parts.append(f"  - {key}: {value}")
        
        if self.suggestion:
            parts.append(f"\nSuggestion: {self.suggestion}")
        
        return "\n".join(parts)

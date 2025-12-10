#!/usr/bin/env python3
"""
Test Script for WinDetox Structure
"""

import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("WinDetox Structure Test")
print("=" * 60)

# Test critical imports
tests = [
    ("core.config.Config", "from core.config import Config"),
    ("core.logger.Logger", "from core.logger import Logger"),
    ("core.utils.is_admin", "from core.utils import is_admin"),
    ("core.exceptions.WinDetoxError", "from core.exceptions import WinDetoxError"),
    ("managers.settings_manager.SettingsManager", "from managers.settings_manager import SettingsManager"),
    ("network.blocklist_manager.BlocklistManager", "from network.blocklist_manager import BlocklistManager"),
    ("network.firewall_manager.FirewallManager", "from network.firewall_manager import FirewallManager"),
    ("network.network_service.NetworkService", "from network.network_service import NetworkService"),
    ("ui.main_window.WinDetoxGUI", "from ui.main_window import WinDetoxGUI"),
    ("ui.system_tray.SystemTrayManager", "from ui.system_tray import SystemTrayManager"),
]

all_passed = True
for description, import_stmt in tests:
    try:
        exec(import_stmt)
        print(f"✅ {description}")
    except ImportError as e:
        print(f"❌ {description}: {e}")
        all_passed = False
    except Exception as e:
        print(f"⚠️  {description}: {e}")
        all_passed = False

print("=" * 60)
if all_passed:
    print("✅ ALL IMPORTS PASSED!")
    print("
🚀 Try starting WinDetox:")
    print("  python WinDetox.py")
    print("
📊 Main file should be clean and modular!")
else:
    print("⚠️  SOME IMPORTS FAILED")
    print("
💡 Check the structure and import paths.")

print("=" * 60)

# update_manager.py
"""
Update manager for WinDetox
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from typing import Tuple

import requests

from core.config import Config
from core.exceptions import UpdateError, SecurityError
from core.utils import verify_file_signature


class UpdateManager:
    """Manages program updates with signature verification"""

    def __init__(self, logger=None):
        self.logger = logger

    @staticmethod
    def compare_versions(current: str, latest: str) -> bool:
        """Compare version strings, return True if update needed"""
        try:
            current_parts = list(map(int, current.split('.')))
            latest_parts = list(map(int, latest.split('.')))

            # Pad with zeros if needed
            max_len = max(len(current_parts), len(latest_parts))
            current_parts.extend([0] * (max_len - len(current_parts)))
            latest_parts.extend([0] * (max_len - len(latest_parts)))

            for i in range(max_len):
                if latest_parts[i] > current_parts[i]:
                    return True
                elif latest_parts[i] < current_parts[i]:
                    return False
            return False
        except:
            return False

    def check_for_updates(self) -> Tuple[bool, str, str, str]:
        """Check for available updates with signature verification"""
        try:
            # Get latest version info (now expects JSON)
            response = requests.get(Config.LATEST_VERSION_URL, timeout=10)

            # Check if response is valid
            if response.status_code != 200:
                raise UpdateError(f"Server returned status code: {response.status_code}")

            try:
                version_info = response.json()
            except json.JSONDecodeError:
                # If not JSON, check if it's plain text
                content = response.text.strip()
                if content.startswith('{'):
                    raise UpdateError("Invalid JSON format from update server")
                else:
                    # Try to parse as simple version file
                    latest_version = content.strip()
                    changes = "No change log available for this version"
                    expected_hash = ""

                    update_needed = self.compare_versions(Config.CURRENT_VERSION, latest_version)
                    return update_needed, latest_version, changes, expected_hash

            latest_version = version_info.get('version', '')
            changes = version_info.get('changes', 'No change log available')
            expected_hash = version_info.get('sha256', '')

            if not latest_version:
                raise UpdateError("No version information received")

            # Compare versions
            update_needed = self.compare_versions(Config.CURRENT_VERSION, latest_version)

            return update_needed, latest_version, changes, expected_hash

        except requests.RequestException as e:
            raise UpdateError(f"Could not connect to update server: {e}")
        except Exception as e:
            raise UpdateError(f"Error checking for updates: {e}")

    def perform_update(self, expected_hash: str) -> bool:
        """Download and install the latest version with signature verification"""
        try:
            # Create temporary directory
            temp_dir = tempfile.gettempdir()
            new_exe_path = os.path.join(temp_dir, "WinDetox_Update.exe")

            # Download new version
            if self.logger:
                self.logger.info(f"Downloading update from: {Config.LATEST_EXE_URL}")

            # Download with requests for better error handling
            response = requests.get(Config.LATEST_EXE_URL, stream=True, timeout=30)
            response.raise_for_status()

            # Save file
            with open(new_exe_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Verify signature
            if not verify_file_signature(new_exe_path, expected_hash):
                os.remove(new_exe_path)
                raise SecurityError(
                    "Download verification failed - file may be corrupted or tampered with")

            # Get current executable path
            current_exe_path = os.path.realpath(sys.argv[0])

            # Create batch script to replace executable
            bat_script_path = os.path.join(temp_dir, "update_WinDetox.bat")

            with open(bat_script_path, 'w', encoding='utf-8') as bat_file:
                bat_file.write(f"""
@echo off
chcp 65001 >nul
echo Updating WinDetox...
echo Waiting for application to close...
timeout /t 3 /nobreak >nul

echo Replacing executable...
move /y "{new_exe_path}" "{current_exe_path}" >nul

if %ERRORLEVEL% EQU 0 (
    echo Starting updated application...
    start "" "{current_exe_path}"
    echo Update successful!
) else (
    echo Update failed!
    pause
)

echo Cleaning up...
del "{bat_script_path}" >nul
""")

            # Run the batch script
            subprocess.Popen([bat_script_path], shell=True,
                             creationflags=subprocess.CREATE_NO_WINDOW)

            return True

        except requests.RequestException as e:
            raise UpdateError(f"Download failed: {e}")
        except SecurityError as e:
            raise e
        except Exception as e:
            raise UpdateError(f"Update error: {e}")

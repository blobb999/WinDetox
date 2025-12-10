# 🛡️ WinDetox - Windows Network Security & Privacy Tool

<img width="160" height="160" alt="WinDetox Icon" src="https://github.com/user-attachments/assets/5a1943a4-e371-4d6d-a816-edd48ad3abc5" />

## 🚀 What is WinDetox?

WinDetox is a fully portable, powerful Windows application for network monitoring, connection blocking, and system privacy enhancement. It provides real-time visibility into all network activity while offering comprehensive tools to protect your privacy.

## ✨ Key Features

### 🔍 **Real-time Network Monitoring**
- Live tracking of all network connections (incoming, outgoing, listening)
- Process identification with PID and executable names
- Filter connections by type and source
- Connection history with timestamps

### 🛑 **Advanced IP Blocking**
- Manual IP blocking from connection list
- Comprehensive Microsoft telemetry blocking
- Cloud service IP detection and blocking
- Dynamic blocklist updates
- Windows Firewall integration for persistent blocking

### 🛡️ **Privacy Protection**
- **NCSI Control** - Disable Windows internet connectivity detection
- **DNS over HTTPS** - Enable/disable Windows DoH
- **Delivery Optimization** - Control Windows Update peer-to-peer sharing
- **Hosts File Management** - Block domains at system level
- **Microsoft Services** - Disable telemetry and tracking services

### ⚡ **Performance & Usability**
- Parallel DNS resolution with TurboDNS
- Color-coded IP categorization (Microsoft/Cloud/Regular)
- System tray integration with monitoring controls
- Export blocked IPs to CSV with enhanced information
- One-click privacy mode activation

### 🔧 **Administrative Tools**
- Windows Firewall rule management
- Bulk IP blocking/unblocking
- Connection history export (JSON/CSV)
- Automatic blocklist updates
- Admin rights detection and warnings

## 📊 Enhanced Visualization

**Blocked IPs Viewer** includes:
- Fast parallel DNS reverse lookup
- IP categorization (Microsoft, Cloud, CDN, Regular)
- Statistics dashboard (resolved/timeout/error counts)
- Color-coded treeview for quick identification
- Export with provider and location information

## 🎯 One-Click Operations

### **Full Privacy Mode**
Activate with one click to:
1. Block Microsoft telemetry IPs
2. Disable Windows DoH
3. Stop delivery optimization
4. Disable NCSI (no more "No Internet" messages)
5. Block Microsoft domains in hosts file
6. Stop tracking services

### **Emergency Options**
- **Nuclear Option** - Block all internet traffic (except DNS and loopback)
- **Complete Undo** - Revert all privacy changes systematically

## 🏗️ Installation & Usage

### **For End Users:**
1. Download the latest release `.exe` file
2. **Run as Administrator** (required for firewall operations)
3. Start monitoring from the main interface
4. Use right-click context menu to block suspicious IPs

### **For Developers:**
```bash
# Clone the repository
git clone https://github.com/blobb999/WinDetox.git

# Install dependencies
pip install -r requirements.txt

# Run the application
python WinDetox.py

## 📋 System Requirements
- **Windows 10/11** (64-bit)
- **Administrator rights** (for full functionality)
- **Python 3.8+** (if running from source)

## 🚨 Current Status & Roadmap

**⚠️ IMPORTANT: This is a Beta Release (v1.0)**

### **✅ Currently Working:**
- Core network monitoring functionality
- IP blocking and firewall integration
- Privacy protection features
- System tray integration
- Basic settings management

### **🔧 Under Development / Planned:**
1. **GUI Themes** - Dark/Light theme support (UI elements exist but not functional)
2. **Multi-language Support** - Internationalization framework (UI ready, translation needed)
3. **Error Handling** - Comprehensive error recovery and user feedback
4. **Update System** - Automatic update mechanism (partially implemented)
5. **Enhanced Logging** - Detailed debugging and diagnostics
6. **Rule Presets** - Pre-configured blocking profiles
7. **Scheduled Tasks** - Automated blocking based on time/events

### **🐛 Known Issues:**
- Some edge cases in error handling need improvement
- Update system requires final integration testing
- Theme switching not yet implemented
- Language files need to be created and integrated

## 🛠️ Contributing

We welcome contributions! Areas where help is particularly needed:

1. **UI Themes** - Implement dark/light theme switching
2. **Translations** - Create language files for internationalization
3. **Error Handling** - Improve robustness and user feedback
4. **Testing** - Help test the update system and edge cases
5. **Documentation** - Improve user guides and API documentation

## 📄 License

**free 4@ll** - This project is freely available for personal and educational use.

## 🤝 Support & Community

**Current Status:** Beta Release - Ready for use but undergoing active development

**Note:** Always run with administrator privileges for full functionality. Some features require Windows Firewall access and registry modifications.

---
*WinDetox - Making Windows networking transparent and private since 2025*
# Initial Triage Script 🔍🛡️📄

**An initial malware analysis tool with multi-engine scanning and automated reporting**

## Features ✨
- **Multi-engine Scanning**:
  - VirusTotal integration
  - Hybrid Analysis submission
  - Real-time report polling
- **Comprehensive Analysis**:
  - SHA-256 hash generation
  - PE file header analysis
  - IOC extraction (IPs, URLs, Domains)
- **Automated Reporting**:
  - Microsoft Word report generation
  - Executive summary creation
  - Detailed technical findings
- **User Interface**:
  - File selection dialog
  - Progress tracking
  - Error handling

## Installation 🛠️
```bash
pip install pefile requests python-docx python-magic-bin
sudo apt install python3-tk

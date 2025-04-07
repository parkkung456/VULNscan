# VulnScan - Automated Web Vulnerability Scanner

VulnScan is a lightweight and extensible automated vulnerability scanner for websites. It aggregates results from well-known tools like `nmap`, `nikto`, `uniscan`, `wapiti`, `gobuster`, and more to detect common web vulnerabilities with clear categorization, severity scoring, and comprehensive reporting (including HTML and TXT formats).

---

## 📄 Features

- ✅ Integrates multiple scanning tools in one interface
- ⚖️ Classifies vulnerabilities by severity: Low, Medium, High, Critical
- 📈 Provides rich reports: Summary, Remediation, Charts (HTML)
- ⌛ Shows scan duration and progress animation
- 🚫 Handles tool skips (e.g., via Ctrl+C) and unavailable dependencies
- ⬆️ Auto-updatable using `-U` flag (Git clone)

---

## ⚙️ Installation

### Requirements

- Python 3.6+
- Linux environment (tested on Kali Linux)
- Tools that must be installed beforehand (if not present, the scanner will skip their scans):
  - `nmap`
  - `nikto`
  - `uniscan`
  - `wapiti`
  - `gobuster`
  - `lbd`

---

## ⚡ Usage

### Basic Command
```bash
sudo python3 scannerDemo.py [options] target
```

### Options

| Option | Description |
|--------|-------------|
| `-V` or `-v` | Print version information |
| `-U` or `-u` | Replace local files with the latest from GitHub |
| `-H` or `-h` or `-help` | Show help message |

---

## 🔹 Example

### Run a full vulnerability scan on a target:
```bash
sudo python3 scannerDemo.py testphp.vulnweb.com
```

### Update the scanner to the latest version from GitHub:
```bash
python3 scannerDemo.py -U
```

### Check the version:
```bash
python3 scannerDemo.py -V
```

---

## 📝 Output

- **Raw Report**: Detailed tool output saved as `.txt`
- **Summary Report**: Organized threat summary with remediation
- **HTML Report**: Colorful interactive report with charts

All reports are saved in the `scan_reports/` folder.

---

## ⚠️ Disclaimer
This tool is designed for educational and authorized security auditing purposes only. Unauthorized use is strictly prohibited.

---

## 🚀 Credits
Developed and maintained by [@parkkung456](https://github.com/parkkung456/VULNscan)


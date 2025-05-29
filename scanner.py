import sys
import socket
import signal
import argparse
import subprocess
import os
import time
import re
import threading
import tldextract
import shutil 
from urllib.parse import urlsplit
from datetime import datetime

VERSION = "1.0"

# Help function to display user guide
def show_help():
    help_text = """
Usage: python3 scanner.py [options] 

Options:
  -V, -v           Print the version of this program.
  -U, -u           Replace every file and directory with:
                   git clone https://github.com/parkkung456/VULNscan.git
  -H, -h, help     Show this help message and exit.
  target           Must be a DNS name string. for examples "goooogle.com", "testphp.vulnweb.com"
If no option is provided, the program runs the normal vulnerability scan.
"""
    print(help_text)

class bcolors:
    HEADER = '\033[38;2;203;108;230m'  # light magenta
    OKBLUE = '\033[94m'  # light blue
    OKGREEN = '\033[92m' # green
    WARNING = '\033[93m' # yellow
    BADFAIL = '\033[91m' # red
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    CYAN = '\033[96m'    # extra option

# Vulnerability detection mapping (specific to nmap results)
VULNERABILITY_PATTERNS = {
    "80/tcp open  http": "l",
    "23/tcp open telnet": "c",  # Critical (Telnet open)
    "21/tcp open ftp": "h",     # High (FTP open)
    "3306/tcp open mysql": "m",  # Medium (MySQL open)
    "1433/tcp open": "m",  # Medium (MySQL open)
    "1521/tcp open": "m",  # Medium (MySQL open)
    "does NOT use Load-balancing": "m",
    "[+] Vul [Blind SQL-i]": "m",
    "[+] Vul [SQL-i]": "m",
    "[+] Vul [XSS]": "m",
    "[+] Vul [RCE]": "m",
    "0 item(s) reported": "l"
}

def print_banner(
        first_line="WWW.EXAMPLE.COM",     # what appears after “>_”
        second_line="SCANNING . . ."      # second prompt line (can be "")
):
    # keep lines inside 24‑char field so the frame stays aligned
    first = first_line.upper()[:24]
    second = second_line.upper()[:24]

    ascii_art = rf"""
                   ______________________________
                  / ____________________________ \
                 | |                            | |
                 | |  >_ {first:<23}| |
                 | |  >_ {second:<23}| |
                 | |                            | |
                 | |                            | |
                 | |                            | |
                 | |                            | |
                 | |                            | |
                 |  ----------------------------  |
                  \______________________________/
                             __|____|__
                            /__________\ 
    """
    print(ascii_art)

def bg_blue(text: str) -> str:
    """white text on blue background"""
    return f"\033[44;97m{text}\033[0m"

def bg_green(text: str) -> str:
    """black text on green background"""
    return f"\033[42;30m{text}\033[0m"

def check_dynamic_tools(tool_list):
    """
    Verifies that the base binaries (nmap, nikto …) exist.
    Prints a blue highlighted 'Checking…' banner, then either:
      • 'All tools are available …'  (green banner on success), or
      • A warning list (red/yellow)  and ‘Complete’ (green banner).
    Returns the filtered tool list.
    """
    banner_txt = "-> [  Checking available security tools in tool list phase . . .  "
    print(bg_blue(banner_txt + "Checking. ]"))

    filtered, missing = [], set()

    for tool_name, command in tool_list:
        # infer the binary 
        if   "nmap"     in tool_name: base = "nmap"
        elif "nikto"    in tool_name: base = "nikto"
        elif "uniscan"  in tool_name: base = "uniscan"
        elif "wapiti"   in tool_name: base = "wapiti"
        elif "gobuster" in tool_name: base = "gobuster"
        else: base = None            

        if base and shutil.which(base) is None:
            print(f"{bcolors.WARNING}Warning: {base} not found; skipping {tool_name}.{bcolors.ENDC}")
            missing.add(base)
        else:
            filtered.append((tool_name, command))

    # summary line
    if missing:
        print(f"{bcolors.BADFAIL}Missing prerequisites: {', '.join(sorted(missing))}{bcolors.ENDC}")
    else:
        print(f"\n{bcolors.OKBLUE}All tools are available.  "
              f"The scanner will perform the task normally .{bcolors.ENDC}\n")

    # closing banner
    print(bg_green(banner_txt + "Complete. ]"))

    return filtered


def url_maker(url):
    """Ensures the target URL is correctly formatted for Wapiti."""
    if not re.match(r'http(s?)\:', url):  # If missing http:// or https://
        url = 'http://' + url  # Default to HTTP if missing
    parsed = urlsplit(url)
    return parsed.geturl()  # Returns properly formatted URL

def check_internet():
    """Checks internet connectivity."""
    return os.system('ping -c1 github.com > /dev/null 2>&1') == 0

def loading_animation(event):
    """Displays a loading animation while scanning."""
    animation = ["🔸", "🔶", "🟠","🟧", "🟠", "🔶"]
    i = 0
    while not event.is_set():
        print(f"\rScanning... {animation[i % len(animation)]} ", end='', flush=True)
        i += 1
        time.sleep(0.5)
    print("\r", end='', flush=True)  # Clears the animation

def print_vulnerability_summary(proc_vul_list):
    """Prints a summary of vulnerabilities detected by severity and returns the counts."""
    # Initialize counts for each severity
    severity_counts = {"c": 0, "h": 0, "m": 0, "l": 0}

    # Count occurrences from all tools in the proc_vul_list
    for tool, vulns in proc_vul_list.items():
        for vuln, severity in vulns:
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts[severity] = 1  # In case an unexpected severity appears

    # Map severity codes to human-friendly labels
    severity_labels = {
        "c": "CRITICAL",
        "h": "HIGH",
        "m": "MEDIUM",
        "l": "LOW"
    }

    # Print the summary
    print("\nVulnerability Summary:")
    print("----------------------")
    for sev_code, count in severity_counts.items():
        label = severity_labels.get(sev_code, sev_code)
        print(f"{label}: {count}")

    return severity_counts

def execute_scan(tool_name, command, target, event):
    """Executes the scanning tool dynamically"""
    global skip_current_tool
    
    tool_messages = {
        "nmap": " - Checking for open ports...",
        "nmap_sqlserver": " - Checking for SQL Server...",
        "nmap_mysql": " - Checking for MySQL Server...",
        "nmap_oracle": " - Checking for Oracle Server...",
        "nikto": " - Checking for Apache Expect XSS Header...",
        "uniscan_rce": " - Performing RCE & RFI scan...",
        "uniscan_xss": " - Performing BSQLi, SQLi, & XSS scan...",
        "lbd": " - Checking for load balancing...",
        "wapiti_sqli": " - Checking for SQL Injection...",
        "wapiti_ssrf": " - Checking for Server-side Request Forgery...",
        "wapiti_xss": " - Checking for Cross-site Scripting...",
        "gobuster_directory_traversal": " - Checking for Directiory Traversal...",
        "uniscan_directory_traversal": " - Checking for Accessible Directiory...",
        "uniscan_file_traversal": " - Checking for Accessible File...",
        "nikto_outdated": " - Checking for Outdated components...",
        "nikto_accessible_paths": " - Checking for Accessible Paths...",
    }
    
    scan_message = tool_messages[tool_name.lower()]

    # Print tool execution
    print()
    print(f"-> {bcolors.BOLD}{bcolors.HEADER}[{tool_name.upper()}]{bcolors.ENDC}{scan_message}", flush=True)

    # Reset skip flag
    skip_current_tool = False

    event.clear()
    loader_thread = threading.Thread(target=loading_animation, args=(event,))
    loader_thread.start()

    try:
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output = result.stdout + result.stderr

        # If tool was skipped, return None and continue with next tool
        if skip_current_tool:
            print(f"{bcolors.WARNING}Skipped {tool_name}.{bcolors.ENDC}")
            return None  

    except KeyboardInterrupt:
        # Catch CTRL+C and skip tool without error
        print(f"\n{bcolors.WARNING}Skipping {tool_name} due to user interrupt.{bcolors.ENDC}")
        skip_current_tool = True
        event.set()  # Stop loading animation safely
        return None  # Skip processing this tool

    except subprocess.CalledProcessError:
        # Handle tool failure due to CTRL+C sending SIGINT
        if skip_current_tool:
            print(f"{bcolors.WARNING}Skipped {tool_name}.{bcolors.ENDC}")
            return None
        output = f"Error executing {tool_name}"
        print(f"{bcolors.WARNING}Failed to run {tool_name}.{bcolors.ENDC}", flush=True)

    event.set()
    loader_thread.join()

    return output

def wapiti_url(target):
    """Returns the target's resolved IP formatted as HTTP://target_ip."""
    target_ip = get_target_ip(target)  # Resolve the IP address

    if target_ip == "Unknown":
        print(f"{bcolors.BADFAIL}Error: Unable to resolve target IP for {target}.{bcolors.ENDC}")
        sys.exit(1)

    return f"http://{target_ip}"

def detect_errors(tool_name, output, raw_report_file):
    detected_vulns = []
    seen_lines = set()  # Track unique lines to avoid duplicates

    # Write the raw output to the report
    with open(raw_report_file, "a") as report:
        report.write(f"\n== {tool_name} Scan Output ==\n")
        report.write(output + "\n")

    for line in output.splitlines():
        line = line.strip()

        if not line or line in seen_lines:
            continue  # Skip duplicate or empty lines

        seen_lines.add(line)

        # --- Nmap-specific detection logic ---
        if tool_name.lower() == "nmap":
            # Match open ports with service names and versions
            nmap_match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$", line)
            if nmap_match:
                port = int(nmap_match.group(1))
                service = nmap_match.group(2).lower()
                version_info = nmap_match.group(3)

                risk_level = "l"  # Default LOW risk
                # Add known high-risk ports and services
                high_risk_ports = {
                    21, 22, 23, 110, 143, 3306, 5432, 3389, 137, 138, 139, 445, 161, 162, 69, 5900, 9200, 11211, 5000
                }
                critical_ports = {23, 3389, 445}  # e.g., Telnet, RDP, SMB

                if port in critical_ports:
                    risk_level = "c"
                elif port in high_risk_ports:
                    risk_level = "h"
                elif service in ["http", "smtp", "imap", "pop3"]:
                    risk_level = "m"

                # Extra check for outdated OpenSSH
                if "OpenSSH 6.6.1p1" in version_info:
                    risk_level = "h"
                    line += " [Outdated OpenSSH detected]"

                detected_vulns.append((line, risk_level))
                severity_label = {
                    "c": "CRITICAL",
                    "h": "HIGH",
                    "m": "MEDIUM",
                    "l": "LOW"
                }.get(risk_level, "INFO")

                print(
                    f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{line}{bcolors.ENDC} "
                    f"detected as {bcolors.BADFAIL}{severity_label}{bcolors.ENDC}"
                )

        # --- Existing tool handlers ---
        elif tool_name.lower() in ["wapiti_sqli", "wapiti_ssrf", "wapiti_xss"]:
            wapiti_match = re.match(r"^\[\+\].*\((\d+)\)$", line)
            if wapiti_match:
                severity_rating = int(wapiti_match.group(1))
                severity = "l" if severity_rating in [1, 2] else "m" if severity_rating == 3 else "h"
                detected_vulns.append((line, severity))
                severity_label = {
                    "c": "CRITICAL",
                    "h": "HIGH",
                    "m": "MEDIUM",
                    "l": "LOW"
                }.get(severity, "INFO")
                print(
                    f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{line}{bcolors.ENDC} "
                    f"detected as {bcolors.BADFAIL}{severity_label}{bcolors.ENDC}"
                )

        elif tool_name.lower() in ["uniscan_file_traversal", "uniscan_directory_traversal"]:
            if line.startswith("| [+] CODE: 200 URL:"):
                detected_vulns.append((line, "h"))
                print(
                    f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{line}{bcolors.ENDC} "
                    f"detected as {bcolors.BADFAIL}HIGH{bcolors.ENDC}"
                )

        elif tool_name.lower() in ["gobuster_directory_traversal"]:
            clean_line = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', line)
            if clean_line.startswith("/"):
                status_match = re.search(r"\(Status:\s*(\d+)\)", clean_line)
                if status_match:
                    status_code = int(status_match.group(1))
                    severity = "h" if status_code == 200 else "l"
                    detected_vulns.append((clean_line, severity))
                    label = "HIGH" if severity == "h" else "LOW"
                    print(
                        f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{clean_line}{bcolors.ENDC} "
                        f"detected as {bcolors.BADFAIL}{label}{bcolors.ENDC}"
                    )

        elif tool_name.lower() in ["uniscan_xss", "uniscan_rce"]:
            if line.startswith("| [+]"):
                detected_vulns.append((line, "m"))
                print(
                    f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{line}{bcolors.ENDC} "
                    f"detected as {bcolors.BADFAIL}MEDIUM{bcolors.ENDC}"
                )

        else:
            for pattern, severity in VULNERABILITY_PATTERNS.items():
                if pattern.lower() in line.lower():
                    detected_vulns.append((line, severity))
                    severity_label = {
                        "c": "CRITICAL",
                        "h": "HIGH",
                        "m": "MEDIUM",
                        "l": "LOW"
                    }.get(severity, "INFO")
                    print(
                        f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{line}{bcolors.ENDC} "
                        f"detected as {bcolors.BADFAIL}{severity_label}{bcolors.ENDC}"
                    )

    with open(raw_report_file, "a") as report:
        for vuln, severity in detected_vulns:
            report.write(f"{vuln} - Severity: {severity}\n")

    return detected_vulns



def generate_report(proc_vul_list, target, raw_report_file):
    """Generates a vulnerability report and appends it to the raw report.
    For each tool, only one consolidated block is printed using the worst severity detected.
    """
    if not proc_vul_list:
        print(f"Task complete. {bcolors.OKGREEN}No vulnerability was found in this task.{bcolors.ENDC}")
        return

    # Custom vulnerability information per tool and severity.
    vul_info_by_tool = {
        "nmap": {
            "l": "Nmap (Low): Open port detected. Low risk if no sensitive services are running.",
            "m": "Nmap (Medium): Service version may be outdated and vulnerable.",
            "h": "Nmap (High): Critical service misconfiguration detected.",
            "c": "Nmap (Critical): Exploitable configuration vulnerability discovered."
        },
        "nmap_sqlserver": {
            "l": "Nmap SQL Server (Low): SQL Server port open, but may be secured by default.",
            "m": "Nmap SQL Server (Medium): SQL Server port open with outdated version.",
            "h": "Nmap SQL Server (High): SQL Server misconfiguration detected.",
            "c": "Nmap SQL Server (Critical): Exploitable SQL Server vulnerability discovered."
        },
        "nmap_mysql": {
            "l": "Nmap MySQL (Low): MySQL port open, but no obvious vulnerabilities.",
            "m": "Nmap MySQL (Medium): MySQL port open with potentially outdated version.",
            "h": "Nmap MySQL (High): Critical MySQL misconfiguration detected.",
            "c": "Nmap MySQL (Critical): Exploitable MySQL vulnerability discovered."
        },
        "nmap_oracle": {
            "l": "Nmap Oracle (Low): Oracle service detected with open port, minimal risk.",
            "m": "Nmap Oracle (Medium): Oracle service may be outdated and vulnerable.",
            "h": "Nmap Oracle (High): Oracle misconfiguration detected.",
            "c": "Nmap Oracle (Critical): Exploitable Oracle vulnerability discovered."
        },
        "nikto": {
            "l": "Nikto (Low): Minor misconfigurations noted in HTTP headers.",
            "m": "Nikto (Medium): Potential exposure of sensitive information via server banners.",
            "h": "Nikto (High): Critical misconfiguration may expose the web server to attack.",
            "c": "Nikto (Critical): Vulnerable server configuration discovered that requires immediate attention."
        },
        "uniscan_rce": {
            "l": "Uniscan RCE (Low): Minor RCE-related findings that appear non-exploitable.",
            "m": "Uniscan RCE (Medium): Potential remote code execution pattern detected.",
            "h": "Uniscan RCE (High): Exploitable RCE vulnerability discovered.",
            "c": "Uniscan RCE (Critical): Confirmed critical remote code execution vulnerability."
        },
        "uniscan_xss": {
            "l": "Uniscan XSS (Low): Minor cross-site scripting issues detected.",
            "m": "Uniscan XSS (Medium): XSS vulnerability that may be exploitable under certain conditions.",
            "h": "Uniscan XSS (High): High-risk XSS vulnerability discovered.",
            "c": "Uniscan XSS (Critical): Severe cross-site scripting vulnerability allowing session hijacking."
        },
        "lbd": {
            "l": "LBD (Low): No significant load balancing issues detected.",
            "m": "LBD (Medium): Minor load balancing misconfiguration detected.",
            "h": "LBD (High): Load balancing misconfiguration exposing potential vulnerabilities.",
            "c": "LBD (Critical): Critical load balancing vulnerability detected."
        },
        "wapiti_sqli": {
            "l": "Wapiti SQLi (Low): SQL injection patterns detected but not confirmed.",
            "m": "Wapiti SQLi (Medium): Potential SQL injection vulnerability requiring further analysis.",
            "h": "Wapiti SQLi (High): Confirmed SQL injection vulnerability with significant risk.",
            "c": "Wapiti SQLi (Critical): Severe SQL injection vulnerability discovered."
        },
        "wapiti_ssrf": {
            "l": "Wapiti SSRF (Low): SSRF patterns detected with minimal risk.",
            "m": "Wapiti SSRF (Medium): Potential SSRF vulnerability identified.",
            "h": "Wapiti SSRF (High): Confirmed SSRF vulnerability with possible data exposure.",
            "c": "Wapiti SSRF (Critical): Critical SSRF vulnerability detected; immediate remediation required."
        },
        "wapiti_xss": {
            "l": "Wapiti XSS (Low): Minor cross-site scripting findings detected.",
            "m": "Wapiti XSS (Medium): Potential XSS vulnerability that should be investigated.",
            "h": "Wapiti XSS (High): High-risk XSS vulnerability discovered.",
            "c": "Wapiti XSS (Critical): Critical XSS vulnerability detected that may allow exploitation."
        },
        "gobuster_directory_traversal": {
            "l": "Gobuster (Low): Directory listing appears benign.",
            "m": "Gobuster (Medium): Found directories that might expose non-sensitive content.",
            "h": "Gobuster (High): Critical directories accessible that should be restricted.",
            "c": "Gobuster (Critical): Sensitive directories exposed."
        },
        "uniscan_directory_bruteforce": {
            "l": "Uniscan Directory Bruteforce (Low): Found public directories that pose minimal risk.",
            "m": "Uniscan Directory Bruteforce (Medium): Discovered potentially sensitive directories exposed.",
            "h": "Uniscan Directory Bruteforce (High): High-risk directory exposure; could lead to unauthorized access.",
            "c": "Uniscan Directory Bruteforce (Critical): Critical system directory exposed; immediate remediation required."
        },
        "uniscan_file_bruteforce": {
            "l": "Uniscan File Bruteforce (Low): Found accessible files with low risk.",
            "m": "Uniscan File Bruteforce (Medium): Potentially sensitive files exposed to the public.",
            "h": "Uniscan File Bruteforce (High): High-risk files (e.g., configs, backups) exposed.",
            "c": "Uniscan File Bruteforce (Critical): Critical files (e.g., credentials) accessible; immediate action needed."
        },
        "nikto_accessible_paths": {
            "l": "Nikto Accessible Paths (Low): Minor exposure of non-sensitive accessible paths detected.",
            "m": "Nikto Accessible Paths (Medium): Several accessible paths detected that might reveal sensitive data.",
            "h": "Nikto Accessible Paths (High): Critical accessible paths detected exposing confidential files.",
            "c": "Nikto Accessible Paths (Critical): Severe accessible paths vulnerability; unauthorized file access is possible."
        },
        "nikto_outdated": {
            "l": "Nikto Outdated (Low): Outdated software components detected with minimal risk.",
            "m": "Nikto Outdated (Medium): Outdated components identified that may be exploited under certain conditions.",
            "h": "Nikto Outdated (High): Outdated software poses a high risk due to known vulnerabilities.",
            "c": "Nikto Outdated (Critical): Critical outdated components detected; immediate patching is required."
        }
    }

    # Custom remediation advice per tool and severity.
    vul_reme_by_tool = {
        "nmap": {
            "l": "Review the open ports and disable services that are unnecessary.",
            "m": "Update the vulnerable service and check for secure configuration options.",
            "h": "Apply security patches immediately and restrict access to this service.",
            "c": "Isolate the affected system and perform a full security audit; patch immediately."
        },
        "nmap_sqlserver": {
            "l": "Ensure SQL Server is secured with proper authentication and firewall rules.",
            "m": "Update SQL Server to the latest version and apply necessary security patches.",
            "h": "Harden SQL Server configuration and limit external access immediately.",
            "c": "Immediately secure SQL Server and perform an in-depth security audit."
        },
        "nmap_mysql": {
            "l": "Ensure MySQL is running with minimal privileges and proper firewall settings.",
            "m": "Update MySQL and verify that secure configuration practices are in place.",
            "h": "Apply critical patches and secure MySQL access promptly.",
            "c": "Isolate the affected MySQL instance and conduct a full security review."
        },
        "nmap_oracle": {
            "l": "Verify Oracle service configuration; ensure no unnecessary ports are open.",
            "m": "Update Oracle service and review configuration for vulnerabilities.",
            "h": "Apply immediate patches and restrict Oracle access as necessary.",
            "c": "Isolate the Oracle service and perform a comprehensive security audit."
        },
        "nikto": {
            "l": "Verify web server configurations and minimize banner information.",
            "m": "Update your server software and hide version information.",
            "h": "Reconfigure your web server to limit exposure of sensitive data.",
            "c": "Immediately reconfigure the server and consider a full penetration test."
        },
        "uniscan_rce": {
            "l": "Monitor the findings and verify if the risk is exploitable.",
            "m": "Patch the vulnerable application components and update to a secure version.",
            "h": "Immediately apply patches and restrict access to vulnerable services.",
            "c": "Isolate the service and perform an urgent security audit."
        },
        "uniscan_xss": {
            "l": "Ensure proper output encoding to mitigate XSS risks.",
            "m": "Implement stricter input validation and output encoding.",
            "h": "Apply patches and update the code to eliminate XSS vulnerabilities.",
            "c": "Immediately fix the XSS vulnerability and perform a full security review."
        },
        "lbd": {
            "l": "Verify load balancing configurations and ensure redundancy.",
            "m": "Review load balancer settings and apply necessary security updates.",
            "h": "Reconfigure the load balancer to prevent exploitation.",
            "c": "Perform an immediate security audit of the load balancing setup."
        },
        "wapiti_sqli": {
            "l": "Review SQL query constructions and disable unnecessary database features.",
            "m": "Apply input sanitization and update vulnerable SQL queries.",
            "h": "Implement parameterized queries and secure database access.",
            "c": "Immediately patch the SQL injection vulnerability and perform a full database audit."
        },
        "wapiti_ssrf": {
            "l": "Limit outbound requests and review network firewall rules.",
            "m": "Implement input validation and restrict server-side requests.",
            "h": "Apply security patches and monitor outbound network traffic closely.",
            "c": "Isolate the vulnerable service and conduct a comprehensive review of server configurations."
        },
        "wapiti_xss": {
            "l": "Ensure output encoding and implement a content security policy.",
            "m": "Patch the application to fix XSS vulnerabilities.",
            "h": "Implement robust input validation and output encoding measures.",
            "c": "Immediately remediate the XSS vulnerability and audit the application code."
        },
        "gobuster_directory_traversal": {
            "l": "Review directory permissions and ensure that only necessary directories are exposed.",
            "m": "Audit the directory structure and secure sensitive directories.",
            "h": "Restrict access to critical directories via proper authentication.",
            "c": "Immediately restrict directory access and conduct a security audit."
        },
        "uniscan_directory_bruteforce": {
            "l": "Review publicly accessible directories and apply appropriate access restrictions.",
            "m": "Restrict access to directories not meant for public exposure via .htaccess or server config.",
            "h": "Harden server configuration, and ensure only whitelisted directories are public.",
            "c": "Immediately secure exposed directories and perform a full access audit."
        },
        "uniscan_file_bruteforce": {
            "l": "Verify the files are intended to be public and contain no sensitive information.",
            "m": "Remove or secure files containing sensitive metadata or information.",
            "h": "Restrict access to configuration or backup files; consider moving them outside the web root.",
            "c": "Immediately revoke public access to critical files and audit for possible compromise."
        },
        "nikto_accessible_paths": {
            "l": "Review file and directory permissions to ensure non-essential paths are not publicly accessible.",
            "m": "Restrict access to sensitive directories using proper authentication and access control measures.",
            "h": "Immediately secure the exposed paths by updating server configuration and applying strict access controls.",
            "c": "Isolate the server and remediate access control issues immediately; perform a thorough security audit."
        },
        "nikto_outdated": {
            "l": "Verify the software components and update if necessary.",
            "m": "Patch the outdated components promptly; review vulnerability advisories for potential risks.",
            "h": "Apply critical patches immediately; implement temporary workarounds if required.",
            "c": "Immediately update the critical outdated software and conduct a comprehensive security review."
        }
    }

    # Mapping of tool names to scan messages.
    tool_messages = {
        "nmap": " - Checking for open ports...",
        "nmap_sqlserver": " - Checking for SQL Server...",
        "nmap_mysql": " - Checking for MySQL Server...",
        "nmap_oracle": " - Checking for Oracle Server...",
        "nikto": " - Checking for Apache Expect XSS Header...",
        "uniscan_rce": " - Performing RCE & RFI scan...",
        "uniscan_xss": " - Performing BSQLi, SQLi, & XSS scan...",
        "lbd": " - Checking for load balancing...",
        "wapiti_sqli": " - Checking for SQL Injection...",
        "wapiti_ssrf": " - Checking for Server-side Request Forgery...",
        "wapiti_xss": " - Checking for Cross-site Scripting...",
        "gobuster_directory_traversal": " - Checking for Directiory Traversal...",
        "uniscan_directory_traversal": " - Checking for Accessible Directiory...",
        "uniscan_file_traversal": " - Checking for Accessible File...",
        "nikto_outdated": " - Checking for Outdated components...",
        "nikto_accessible_paths": " - Checking for Accessible Paths...",
    }

    # Mapping of tool names to commands from original tool list.
    tool_command_dict = {
        "nmap": f"nmap -sV {target}",
        "nmap_sqlserver": f"nmap -p1433 --open -Pn {target}",
        "nmap_mysql": f"nmap -p3306 --open -Pn {target}",
        "nmap_oracle": f"nmap -p1521 --open -Pn {target}",
        "nikto": f"nikto -Plugins 'apache_expect_xss' -host {target}",
        "uniscan_rce": f"uniscan -s -u {target}",
        "uniscan_xss": f"uniscan -d -u {target}",
        "lbd": f"lbd {target}",
        "wapiti_sqli": f"wapiti -m sql -u {target} --verbose 2",
        "wapiti_ssrf": f"wapiti -m ssrf -u {target} --verbose 2",
        "wapiti_xss": f"wapiti -m xss -u {target} --verbose 2",
        "gobuster_directory_traversal": f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -u {target}",
        "uniscan_directory_traversal": f"uniscan -q -u {target}",
        "uniscan_file_traversal": f"uniscan -w -u {target}",
        "nikto_outdated": f"nikto -Plugins 'outdated' -host {target}",
        "nikto_accessible_paths": f"nikto -Plugins 'paths' -host {target}",
    }

    # Helper to convert severity code to human-readable text.
    severity_text = {
        "l": "low",
        "m": "medium",
        "h": "high",
        "c": "critical"
    }

    # Define an ordering to determine the worst severity.
    severity_order = {"l": 1, "m": 2, "h": 3, "c": 4}

    timestamp = datetime.now().strftime("%d-%m-%Y-%H%M")
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
    report_txt_file = f"scan_reports/{timestamp}-scan_report_{safe_target}.txt"

    os.makedirs("scan_reports", exist_ok=True)

    try:
        with open(report_txt_file, 'w') as report, open(raw_report_file, "a") as raw_report:
            report.write(f"Scan Report for {target}\n\n")
            raw_report.write("\n== Vulnerability Summary ==\n")
            
            # For each tool that produced vulnerabilities, aggregate the findings.
            for tool, vulns in proc_vul_list.items():
                tool_key = tool.lower()
                scan_msg = tool_messages.get(tool_key, "")
                command_used = tool_command_dict.get(tool_key, "N/A")
                
                # Determine the worst severity for this tool.
                worst_severity = None
                for vuln, severity in vulns:
                    if worst_severity is None or severity_order.get(severity, 0) > severity_order.get(worst_severity, 0):
                        worst_severity = severity
                if worst_severity is None:
                    worst_severity = "l"
                
                threat_level = severity_text.get(worst_severity, worst_severity)
                tool_info = vul_info_by_tool.get(tool_key, {})
                tool_reme = vul_reme_by_tool.get(tool_key, {})
                info_text = tool_info.get(worst_severity, "No information available.")
                reme_text = tool_reme.get(worst_severity, "No remediation available.")
                
                # Write one consolidated block per tool.
                report.write(f"Task : Running {tool}{scan_msg}\n")
                report.write(f"Command : {command_used}\n")
                report.write(f"Vulnerability threat level : {threat_level}\n")
                report.write(f"Vulnerability Information: {info_text}\n")
                report.write(f"Vulnerability remediation: {reme_text}\n")
                report.write("\n")
                
                # For the raw report, list the aggregated result.
                raw_report.write(f"== {tool} Aggregated Findings ==\n")
                raw_report.write(f"Aggregated Severity: {worst_severity} ({threat_level})\n\n")
            
        print(f"\n{bcolors.BOLD}Scan completed.{bcolors.ENDC}")
        print(f"Report saved as {bcolors.OKGREEN}{report_txt_file}{bcolors.ENDC}")
        print(f"Full raw output saved in {bcolors.OKGREEN}{raw_report_file}{bcolors.ENDC}")
    except Exception as e:
        print(f"{bcolors.BADFAIL}Error writing reports: {e}{bcolors.ENDC}")

def generate_html_report(proc_vul_list, target, target_ip, severity_counts, tasks_executed, 
                         tools_skipped_count, total_time, raw_report_file):
    """
    Creates an HTML report file in the 'scan_reports' folder, containing:
      - High-Level Summary
      - Bar Charts:
          1. Severity Breakdown
          2. Vulnerability Detected by Tool
          3. Vulnerability Category Breakdown
      - Detailed Tool Results Table
    """
    import os, json
    from datetime import datetime

    # -------------------------------------------------------------------------
    # Dictionaries for vulnerability information and remediation.
    # -------------------------------------------------------------------------
    vul_info_by_tool = {
        "nmap": {
            "l": "Nmap (Low): Open port detected. Low risk if no sensitive services are running.",
            "m": "Nmap (Medium): Service version may be outdated and vulnerable.",
            "h": "Nmap (High): Critical service misconfiguration detected.",
            "c": "Nmap (Critical): Exploitable configuration vulnerability discovered."
        },
        "nmap_sqlserver": {
            "l": "Nmap SQL Server (Low): SQL Server port open, but may be secured by default.",
            "m": "Nmap SQL Server (Medium): SQL Server port open with outdated version.",
            "h": "Nmap SQL Server (High): SQL Server misconfiguration detected.",
            "c": "Nmap SQL Server (Critical): Exploitable SQL Server vulnerability discovered."
        },
        "nmap_mysql": {
            "l": "Nmap MySQL (Low): MySQL port open, but no obvious vulnerabilities.",
            "m": "Nmap MySQL (Medium): MySQL port open with potentially outdated version.",
            "h": "Nmap MySQL (High): Critical MySQL misconfiguration detected.",
            "c": "Nmap MySQL (Critical): Exploitable MySQL vulnerability discovered."
        },
        "nmap_oracle": {
            "l": "Nmap Oracle (Low): Oracle service detected with open port, minimal risk.",
            "m": "Nmap Oracle (Medium): Oracle service may be outdated and vulnerable.",
            "h": "Nmap Oracle (High): Oracle misconfiguration detected.",
            "c": "Nmap Oracle (Critical): Exploitable Oracle vulnerability discovered."
        },
        "nikto": {
            "l": "Nikto (Low): Minor misconfigurations noted in HTTP headers.",
            "m": "Nikto (Medium): Potential exposure of sensitive information via server banners.",
            "h": "Nikto (High): Critical misconfiguration may expose the web server to attack.",
            "c": "Nikto (Critical): Vulnerable server configuration discovered that requires immediate attention."
        },
        "uniscan_rce": {
            "l": "Uniscan RCE (Low): Minor RCE-related findings that appear non-exploitable.",
            "m": "Uniscan RCE (Medium): Potential remote code execution pattern detected.",
            "h": "Uniscan RCE (High): Exploitable RCE vulnerability discovered.",
            "c": "Uniscan RCE (Critical): Confirmed critical remote code execution vulnerability."
        },
        "uniscan_xss": {
            "l": "Uniscan XSS (Low): Minor cross-site scripting issues detected.",
            "m": "Uniscan XSS (Medium): XSS vulnerability that may be exploitable under certain conditions.",
            "h": "Uniscan XSS (High): High-risk XSS vulnerability discovered.",
            "c": "Uniscan XSS (Critical): Severe cross-site scripting vulnerability allowing session hijacking."
        },
        "lbd": {
            "l": "LBD (Low): No significant load balancing issues detected.",
            "m": "LBD (Medium): Minor load balancing misconfiguration detected.",
            "h": "LBD (High): Load balancing misconfiguration exposing potential vulnerabilities.",
            "c": "LBD (Critical): Critical load balancing vulnerability detected."
        },
        "wapiti_sqli": {
            "l": "Wapiti SQLi (Low): SQL injection patterns detected but not confirmed.",
            "m": "Wapiti SQLi (Medium): Potential SQL injection vulnerability requiring further analysis.",
            "h": "Wapiti SQLi (High): Confirmed SQL injection vulnerability with significant risk.",
            "c": "Wapiti SQLi (Critical): Severe SQL injection vulnerability discovered."
        },
        "wapiti_ssrf": {
            "l": "Wapiti SSRF (Low): SSRF patterns detected with minimal risk.",
            "m": "Wapiti SSRF (Medium): Potential SSRF vulnerability identified.",
            "h": "Wapiti SSRF (High): Confirmed SSRF vulnerability with possible data exposure.",
            "c": "Wapiti SSRF (Critical): Critical SSRF vulnerability detected; immediate remediation required."
        },
        "wapiti_xss": {
            "l": "Wapiti XSS (Low): Minor cross-site scripting findings detected.",
            "m": "Wapiti XSS (Medium): Potential XSS vulnerability that should be investigated.",
            "h": "Wapiti XSS (High): High-risk XSS vulnerability discovered.",
            "c": "Wapiti XSS (Critical): Critical XSS vulnerability detected that may allow exploitation."
        },
        "gobuster_directory_traversal": {
            "l": "Gobuster (Low): Directory listing appears benign.",
            "m": "Gobuster (Medium): Found directories that might expose non-sensitive content.",
            "h": "Gobuster (High): Critical directories accessible that should be restricted.",
            "c": "Gobuster (Critical): Sensitive directories exposed."
        },
        "uniscan_directory_bruteforce": {
            "l": "Uniscan Directory Bruteforce (Low): Found public directories that pose minimal risk.",
            "m": "Uniscan Directory Bruteforce (Medium): Discovered potentially sensitive directories exposed.",
            "h": "Uniscan Directory Bruteforce (High): High-risk directory exposure; could lead to unauthorized access.",
            "c": "Uniscan Directory Bruteforce (Critical): Critical system directory exposed; immediate remediation required."
        },
        "uniscan_file_bruteforce": {
            "l": "Uniscan File Bruteforce (Low): Found accessible files with low risk.",
            "m": "Uniscan File Bruteforce (Medium): Potentially sensitive files exposed to the public.",
            "h": "Uniscan File Bruteforce (High): High-risk files (e.g., configs, backups) exposed.",
            "c": "Uniscan File Bruteforce (Critical): Critical files (e.g., credentials) accessible; immediate action needed."
        },
        "nikto_accessible_paths": {
            "l": "Nikto Accessible Paths (Low): Minor exposure of non-sensitive accessible paths detected.",
            "m": "Nikto Accessible Paths (Medium): Several accessible paths detected that might reveal sensitive data.",
            "h": "Nikto Accessible Paths (High): Critical accessible paths detected exposing confidential files.",
            "c": "Nikto Accessible Paths (Critical): Severe accessible paths vulnerability; unauthorized file access is possible."
        },
        "nikto_outdated": {
            "l": "Nikto Outdated (Low): Outdated software components detected with minimal risk.",
            "m": "Nikto Outdated (Medium): Outdated components identified that may be exploited under certain conditions.",
            "h": "Nikto Outdated (High): Outdated software poses a high risk due to known vulnerabilities.",
            "c": "Nikto Outdated (Critical): Critical outdated components detected; immediate patching is required."
        }
    }

    vul_reme_by_tool = {
        "nmap": {
            "l": "Review the open ports and disable services that are unnecessary.",
            "m": "Update the vulnerable service and check secure configuration options.",
            "h": "Apply security patches immediately and restrict access to this service.",
            "c": "Isolate the affected system and perform a full security audit; patch immediately."
        },
        "nmap_sqlserver": {
            "l": "Ensure SQL Server is secured with proper authentication and firewall rules.",
            "m": "Update SQL Server to the latest version and apply necessary security patches.",
            "h": "Harden SQL Server configuration and limit external access immediately.",
            "c": "Immediately secure SQL Server and perform an in-depth security audit."
        },
        "nmap_mysql": {
            "l": "Ensure MySQL is running with minimal privileges and proper firewall settings.",
            "m": "Update MySQL and verify that secure configuration practices are in place.",
            "h": "Apply critical patches and secure MySQL access promptly.",
            "c": "Isolate the affected MySQL instance and conduct a full security review."
        },
        "nmap_oracle": {
            "l": "Verify Oracle service configuration; ensure no unnecessary ports are open.",
            "m": "Update Oracle service and review configuration for vulnerabilities.",
            "h": "Apply immediate patches and restrict Oracle access as necessary.",
            "c": "Isolate the Oracle service and perform a comprehensive security audit."
        },
        "nikto": {
            "l": "Verify web server configurations and minimize banner information.",
            "m": "Update your server software and hide version information.",
            "h": "Reconfigure your web server to limit exposure of sensitive data.",
            "c": "Immediately reconfigure the server and consider a full penetration test."
        },
        "uniscan_rce": {
            "l": "Monitor the findings and verify if the risk is exploitable.",
            "m": "Patch the vulnerable application components and update to a secure version.",
            "h": "Immediately apply patches and restrict access to vulnerable services.",
            "c": "Isolate the service and perform an urgent security audit."
        },
        "uniscan_xss": {
            "l": "Ensure proper output encoding to mitigate XSS risks.",
            "m": "Implement stricter input validation and output encoding.",
            "h": "Apply patches and update the code to eliminate XSS vulnerabilities.",
            "c": "Immediately fix the XSS vulnerability and perform a full security review."
        },
        "lbd": {
            "l": "Verify load balancing configurations and ensure redundancy.",
            "m": "Review load balancer settings and apply necessary security updates.",
            "h": "Reconfigure the load balancer to prevent exploitation.",
            "c": "Perform an immediate security audit of the load balancing setup."
        },
        "wapiti_sqli": {
            "l": "Review SQL query constructions and disable unnecessary database features.",
            "m": "Apply input sanitization and update vulnerable SQL queries.",
            "h": "Implement parameterized queries and secure database access.",
            "c": "Immediately patch the SQL injection vulnerability and perform a full database audit."
        },
        "wapiti_ssrf": {
            "l": "Limit outbound requests and review network firewall rules.",
            "m": "Implement input validation and restrict server-side requests.",
            "h": "Apply security patches and monitor outbound network traffic closely.",
            "c": "Isolate the vulnerable service and conduct a comprehensive review of server configurations."
        },
        "wapiti_xss": {
            "l": "Ensure output encoding and implement a content security policy.",
            "m": "Patch the application to fix XSS vulnerabilities.",
            "h": "Implement robust input validation and output encoding measures.",
            "c": "Immediately remediate the XSS vulnerability and audit the application code."
        },
        "gobuster_directory_traversal": {
            "l": "Review directory permissions and ensure that only necessary directories are exposed.",
            "m": "Audit the directory structure and secure sensitive directories.",
            "h": "Restrict access to critical directories via proper authentication.",
            "c": "Immediately restrict directory access and conduct a security audit."
        },
        "uniscan_directory_bruteforce": {
            "l": "Review publicly accessible directories and apply appropriate access restrictions.",
            "m": "Restrict access to directories not meant for public exposure via .htaccess or server config.",
            "h": "Harden server configuration, and ensure only whitelisted directories are public.",
            "c": "Immediately secure exposed directories and perform a full access audit."
        },
        "uniscan_file_bruteforce": {
            "l": "Verify the files are intended to be public and contain no sensitive information.",
            "m": "Remove or secure files containing sensitive metadata or information.",
            "h": "Restrict access to configuration or backup files; consider moving them outside the web root.",
            "c": "Immediately revoke public access to critical files and audit for possible compromise."
        },
        "nikto_accessible_paths": {
            "l": "Review file and directory permissions to ensure non-essential paths are not publicly accessible.",
            "m": "Restrict access to sensitive directories using proper authentication and access control measures.",
            "h": "Immediately secure the exposed paths by updating server configuration and applying strict access controls.",
            "c": "Isolate the server and remediate access control issues immediately; perform a thorough security audit."
        },
        "nikto_outdated": {
            "l": "Verify the software components and update if necessary.",
            "m": "Patch the outdated components promptly; review vulnerability advisories for potential risks.",
            "h": "Apply critical patches immediately; implement temporary workarounds if required.",
            "c": "Immediately update the critical outdated software and conduct a comprehensive security review."
        }
    }

    # Mapping of tool names to scan messages.
    tool_messages = {
        "nmap": " - Checking for open ports...",
        "nmap_sqlserver": " - Checking for SQL Server...",
        "nmap_mysql": " - Checking for MySQL Server...",
        "nmap_oracle": " - Checking for Oracle Server...",
        "nikto": " - Checking for Apache Expect XSS Header...",
        "uniscan_rce": " - Performing RCE & RFI scan...",
        "uniscan_xss": " - Performing BSQLi, SQLi, & XSS scan...",
        "lbd": " - Checking for load balancing...",
        "wapiti_sqli": " - Checking for SQL Injection...",
        "wapiti_ssrf": " - Checking for Server-side Request Forgery...",
        "wapiti_xss": " - Checking for Cross-site Scripting...",
        "gobuster_directory_traversal": " - Checking for Directiory Traversal...",
        "uniscan_directory_traversal": " - Checking for Accessible Directiory...",
        "uniscan_file_traversal": " - Checking for Accessible File...",
        "nikto_outdated": " - Checking for Outdated components...",
        "nikto_accessible_paths": " - Checking for Accessible Paths..."
    }

    # Mapping of tool names to commands from original tool list.
    tool_command_dict = {
        "nmap": f"nmap -sV {target}",
        "nmap_sqlserver": f"nmap -p1433 --open -Pn {target}",
        "nmap_mysql": f"nmap -p3306 --open -Pn {target}",
        "nmap_oracle": f"nmap -p1521 --open -Pn {target}",
        "nikto": f"nikto -Plugins 'apache_expect_xss' -host {target}",
        "uniscan_rce": f"uniscan -s -u {target}",
        "uniscan_xss": f"uniscan -d -u {target}",
        "lbd": f"lbd {target}",
        "wapiti_sqli": f"wapiti -m sql -u {target} --verbose 2",
        "wapiti_ssrf": f"wapiti -m ssrf -u {target} --verbose 2",
        "wapiti_xss": f"wapiti -m xss -u {target} --verbose 2",
        "gobuster_directory_traversal": f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -u {target}",
        "uniscan_directory_traversal": f"uniscan -q -u {target}",
        "uniscan_file_traversal": f"uniscan -w -u {target}",
        "nikto_outdated": f"nikto -Plugins 'outdated' -host {target}",
        "nikto_accessible_paths": f"nikto -Plugins 'paths' -host {target}"
    }

    # Helper to convert severity code to human-readable text.
    severity_text = {
        "l": "low",
        "m": "medium",
        "h": "high",
        "c": "critical"
    }

    # Define an ordering to determine the worst severity.
    severity_order = {"l": 1, "m": 2, "h": 3, "c": 4}

    timestamp = datetime.now().strftime("%d-%m-%Y-%H%M")
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
    report_html_file = f"scan_reports/{timestamp}-scan_report_{safe_target}.html"

    os.makedirs("scan_reports", exist_ok=True)

    try:
        with open(report_html_file, "w", encoding="utf-8") as f, open(raw_report_file, "a") as raw_report:
            # Write raw text report header
            f.write(f"Scan Report for {target}\n\n")
            raw_report.write("\n== Vulnerability Summary ==\n")
            
            # For each tool that produced vulnerabilities, aggregate the findings.
            for tool, vulns in proc_vul_list.items():
                tool_key = tool.lower()
                scan_msg = tool_messages.get(tool_key, "")
                command_used = tool_command_dict.get(tool_key, "N/A")
                
                # Determine the worst severity for this tool.
                worst_severity = None
                for vuln, severity in vulns:
                    if worst_severity is None or severity_order.get(severity, 0) > severity_order.get(worst_severity, 0):
                        worst_severity = severity
                if worst_severity is None:
                    worst_severity = "l"
                
                threat_level = severity_text.get(worst_severity, worst_severity)
                tool_info = vul_info_by_tool.get(tool_key, {})
                tool_reme = vul_reme_by_tool.get(tool_key, {})
                info_text = tool_info.get(worst_severity, "No information available.")
                reme_text = tool_reme.get(worst_severity, "No remediation available.")
                
                # Write one consolidated block per tool.
                f.write(f"Task : Running {tool}{scan_msg}\n")
                f.write(f"Command : {command_used}\n")
                f.write(f"Vulnerability threat level : {threat_level}\n")
                f.write(f"Vulnerability Information: {info_text}\n")
                f.write(f"Vulnerability remediation: {reme_text}\n")
                f.write("\n")
                
                # For the raw report, list the aggregated result.
                raw_report.write(f"== {tool} Aggregated Findings ==\n")
                raw_report.write(f"Aggregated Severity: {worst_severity} ({threat_level})\n\n")          
    except Exception as e:
        print(f"{bcolors.BADFAIL}Error writing HTML report: {e}{bcolors.ENDC}")
    # -------------------------------------------------------------------------
    # Prepare data for the charts
    # -------------------------------------------------------------------------
    # Severity Bar Chart data
    severity_labels = ["Critical", "High", "Medium", "Low"]
    severity_values = [
        severity_counts.get("c", 0),
        severity_counts.get("h", 0),
        severity_counts.get("m", 0),
        severity_counts.get("l", 0)
    ]

    # Group vulnerability by tool data for the bar chart
    group_mapping = {
        "nmap": ["nmap_sqlserver", "nmap", "nmap_oracle"],
        "wapiti": ["wapiti_xss", "wapiti_ssrf", "wapiti_sqli"],
        "uniscan": ["uniscan_rce", "uniscan_xss", "uniscan_directory_traversal", "uniscan_file_traversal"],
        "lbd": ["lbd"],
        "gobuster": ["gobuster_directory_traversal"],
        "nikto": ["nikto", "nikto_accessible_paths", "nikto_outdated"]
    }
    grouped_vul_counts = {}
    for group, tools in group_mapping.items():
        count = 0
        for tool in tools:
            if tool in proc_vul_list:
                count += len(proc_vul_list[tool])
        grouped_vul_counts[group] = count

    group_labels = list(grouped_vul_counts.keys())
    group_values = list(grouped_vul_counts.values())
    
    # Calculate Vulnerability Lists counts
    vulnerability_categories = {
        "Broken Access Control": ["gobuster_directory_traversal", "uniscan_directory_traversal", "uniscan_file_traversal"],
        "SQL Injection": ["wapiti_sqli"],
        "Cross-Site Scripting": ["wapiti_xss", "uniscan_xss", "nikto"],
        "Remote Code Execution (RCE)": ["uniscan_rce"],
        "Server-Side Request Forgery (SSRF)": ["nikto_accessible_paths", "nikto_outdated", "wapiti_ssrf", "lbd", "nmap", "nmap_sqlserver", "nmap_mysql", "nmap_oracle", "nikto_accessible_paths", "nikto_outdated"]
    }
    
    vul_list_counts = {}
    for category, tools in vulnerability_categories.items():
        count = 0
        for tool in tools:
            tool_lower = tool.lower()
            if tool_lower in proc_vul_list:
                count += len(proc_vul_list[tool_lower])
        vul_list_counts[category] = count
    
    vul_list_labels = list(vul_list_counts.keys())
    vul_list_values = list(vul_list_counts.values())

    # -------------------------------------------------------------------------
    # Aggregate vulnerabilities by category using key phrases.
    # -------------------------------------------------------------------------
    vuln_category_counts = {
        "Broken Access Control": 0,
        "SQL Injection": 0,
        "Cross-Site Scripting": 0,
        "Remote Code Execution": 0,
        "Server-Side Request Forgery": 0
    }
    for tool, vulns in proc_vul_list.items():
        for vuln, _ in vulns:
            vuln_lower = vuln.lower()
            if "sql injection" in vuln_lower or "sqli" in vuln_lower:
                vuln_category_counts["SQL Injection"] += 1
            elif "xss" in vuln_lower:
                vuln_category_counts["Cross-Site Scripting"] += 1
            elif "rce" in vuln_lower:
                vuln_category_counts["Remote Code Execution"] += 1
            elif "ssrf" in vuln_lower:
                vuln_category_counts["Server-Side Request Forgery"] += 1
            elif "path traversal" in vuln_lower or "ccs injection" in vuln_lower or "access control" in vuln_lower:
                vuln_category_counts["Broken Access Control"] += 1

    vuln_category_labels = list(vuln_category_counts.keys())
    vuln_category_values = list(vuln_category_counts.values())

    # -------------------------------------------------------------------------
    # 3. Build the HTML content with embedded charts and results (Bar Charts version)
    # -------------------------------------------------------------------------
    html_content = []
    html_content.append("<html>")
    html_content.append("<head>")
    html_content.append("  <meta charset='UTF-8' />")
    html_content.append("  <title>Vulnerability Scan Report</title>")
    html_content.append("  <style>")
    html_content.append("    body { font-family: Arial, sans-serif; margin: 0; padding: 0; }")
    html_content.append("    nav { background: #333; color: #fff; padding: 10px; }")
    html_content.append("    nav .nav-container { display: flex; justify-content: space-between; align-items: center; }")
    html_content.append("    nav .logo { font-size: 40px; font-weight: bold; }")
    html_content.append("    nav ul { list-style: none; display: flex; margin: 0; padding: 0; }")
    html_content.append("    nav ul li { margin-left: 20px; }")
    html_content.append("    nav ul li a { color: #fff; text-decoration: none; }")
    html_content.append("    nav ul li a:hover { text-decoration: underline; }")
    html_content.append("    .content { margin: 20px; }")
    html_content.append("    h1, h2, h3 { margin-bottom: 0.3em; }")
    html_content.append("    table { border-collapse: collapse; width: 100%; margin-bottom: 2em; }")
    html_content.append("    th, td { border: 1px solid #ccc; padding: 8px; }")
    html_content.append("    th { background: #f2f2f2; }")
    html_content.append("    .summary-table td { vertical-align: top; }")
    html_content.append("    .charts-container { display: flex; flex-wrap: wrap; justify-content: space-around; }")
    html_content.append("    .chart-box { flex: 1; min-width: 300px; margin: 10px; }")
    html_content.append("  </style>")
    # Include Chart.js from a CDN
    html_content.append("  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>")
    html_content.append("</head>")
    html_content.append("<body>")

    # -------------------------------------------------------------------------
    # 3.1 Add the navigation bar at the top
    # -------------------------------------------------------------------------
    html_content.append("""
    <nav>
      <div class="nav-container">
        <div class="logo">
          <img src="logo.png" alt="Logo" style="width:50px; vertical-align:middle; margin-right:10px;">
          VulnScan Report
        </div>
        <ul>
          <li><a href="#vulnerabilities_summary">Vulnerabilities Summary</a></li>
          <li><a href="#charts_section">Charts</a></li>
        </ul>
      </div>
    </nav>
    """)

    # -------------------------------------------------------------------------
    # 3.2 Main content container
    # -------------------------------------------------------------------------
    html_content.append("<div class='content'>")

    # High-Level Summary
    html_content.append(f"<h1 id='vulnerabilities_summary'>Vulnerabilities Summary</h1>")
    html_content.append("<table class='summary-table'>")
    html_content.append(f"<tr><td><strong>Target URL:</strong></td><td>{target}</td></tr>")
    html_content.append(f"<tr><td><strong>Resolved IP:</strong></td><td>{target_ip}</td></tr>")
    html_content.append(f"<tr><td><strong>Date and Time of Scan:</strong></td><td>{timestamp}</td></tr>")
    html_content.append(f"<tr><td><strong>Total Scan Duration:</strong></td><td>{total_time:.2f} seconds</td></tr>")
    html_content.append(f"<tr><td><strong>Total Tasks Executed:</strong></td><td>{tasks_executed}</td></tr>")
    html_content.append(f"<tr><td><strong>Total Tools Skipped:</strong></td><td>{tools_skipped_count}</td></tr>")
    html_content.append("<tr><td><strong>Severity Breakdown:</strong></td>")
    html_content.append("<td>")
    html_content.append(f"Critical: {severity_counts.get('c', 0)}<br>")
    html_content.append(f"High: {severity_counts.get('h', 0)}<br>")
    html_content.append(f"Medium: {severity_counts.get('m', 0)}<br>")
    html_content.append(f"Low: {severity_counts.get('l', 0)}")
    html_content.append("</td></tr>")

    overall_rating = "None"
    if severity_counts.get('c', 0) > 0:
        overall_rating = "Critical"
    elif severity_counts.get('h', 0) > 0:
        overall_rating = "High"
    elif severity_counts.get('m', 0) > 0:
        overall_rating = "Medium"
    elif severity_counts.get('l', 0) > 0:
        overall_rating = "Low"

    html_content.append(f"<tr><td><strong>Overall Risk Rating:</strong></td><td>{overall_rating}</td></tr>")
    html_content.append("</table>")

    # -------------------------------------------------------------------------
    # 3.3 Insert Canvas elements for the bar charts (displayed side by side)
    # -------------------------------------------------------------------------
    html_content.append("<div class='charts-container' id='charts_section'>")
    html_content.append("<div class='chart-box'>")
    html_content.append("<h3>Severity Breakdown Bar Chart</h3>")
    html_content.append("<canvas id='severityBarChart' width='400' height='400'></canvas>")
    html_content.append("</div>")
    html_content.append("<div class='chart-box'>")
    html_content.append("<h3>Vulnerability Detected by Tool Bar Chart</h3>")
    html_content.append("<canvas id='toolBarChart' width='400' height='400'></canvas>")
    html_content.append("</div>")
    html_content.append("<div class='chart-box'>")
    html_content.append("<h3>Vulnerability Lists Bar Chart</h3>")
    html_content.append("<canvas id='vulListBarChart' width='400' height='400'></canvas>")
    html_content.append("</div>")
    html_content.append("</div>")

    # -------------------------------------------------------------------------
    # 4. Chart.js Scripts (Bar Chart version)
    # -------------------------------------------------------------------------
    html_content.append("<script>")
    # Severity Bar Chart
    html_content.append("var severityData = {")
    html_content.append("  labels: " + json.dumps(severity_labels) + ",")
    html_content.append("  datasets: [{")
    html_content.append("    label: 'Severity Count',")
    html_content.append("    data: " + json.dumps(severity_values) + ",")
    html_content.append("    backgroundColor: ['#C70039', '#FF5733', '#FFC300', '#DAF7A6']")
    html_content.append("  }]")
    html_content.append("};")
    html_content.append("""
    new Chart(document.getElementById('severityBarChart'), {
      type: 'bar',
      data: severityData,
      options: {
        responsive: false,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { stepSize: 1 } }
        }
      }
    });
    """)
    # Tool Bar Chart
    html_content.append("var toolData = {")
    html_content.append("  labels: " + json.dumps(group_labels) + ",")
    html_content.append("  datasets: [{")
    html_content.append("    label: 'Vulnerabilities by Tool',")
    html_content.append("    data: " + json.dumps(group_values) + ",")
    html_content.append("    backgroundColor: ['#3366cc', '#dc3912', '#ff9900', '#109618', '#990099', '#0099c6']")
    html_content.append("  }]")
    html_content.append("};")
    html_content.append("""
    new Chart(document.getElementById('toolBarChart'), {
      type: 'bar',
      data: toolData,
      options: {
        responsive: false,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { stepSize: 1 } }
        }
      }
    });
    """)
    # Vulnerability Lists Bar Chart
    html_content.append("var vulListData = {")
    html_content.append("  labels: " + json.dumps(vul_list_labels) + ",")
    html_content.append("  datasets: [{")
    html_content.append("    label: 'Vulnerabilities by Category',")
    html_content.append("    data: " + json.dumps(vul_list_values) + ",")
    html_content.append("    backgroundColor: ['#8e44ad', '#2980b9', '#27ae60', '#f39c12', '#c0392b']")
    html_content.append("  }]")
    html_content.append("};")
    html_content.append("""
    new Chart(document.getElementById('vulListBarChart'), {
      type: 'bar',
      data: vulListData,
      options: {
        responsive: false,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { stepSize: 1 } }
        }
      }
    });
    """)
    html_content.append("</script>")

    # -------------------------------------------------------------------------
    # 5. Detailed Tool Results Table
    # -------------------------------------------------------------------------
    html_content.append("<h2>Detailed Tool Results</h2>")
    html_content.append("<table>")
    html_content.append("<tr>")
    html_content.append("<th>Command Executed</th>")
    html_content.append("<th>Threat Level</th>")
    html_content.append("<th>Vulnerability Information</th>")
    html_content.append("<th>Recommended Remediation</th>")
    html_content.append("</tr>")

    severity_order = {"l": 1, "m": 2, "h": 3, "c": 4}
    
    for tool, vulns in proc_vul_list.items():
        tool_key = tool.lower()
        worst_sev = None
        for vuln, sev_code in vulns:
            if worst_sev is None or severity_order.get(sev_code, 0) > severity_order.get(worst_sev, 0):
                worst_sev = sev_code
        if worst_sev is None:
            worst_sev = "l"

        info_text = vul_info_by_tool.get(tool_key, {}).get(worst_sev, "No information available.")
        reme_text = vul_reme_by_tool.get(tool_key, {}).get(worst_sev, "No remediation available.")
        command_used = tool_command_dict.get(tool_key, "N/A")
        severity_label = {"c": "CRITICAL", "h": "HIGH", "m": "MEDIUM", "l": "LOW"}.get(worst_sev, "INFO")

        html_content.append("<tr>")
        html_content.append(f"<td>{command_used}</td>")
        html_content.append(f"<td>{severity_label}</td>")
        html_content.append(f"<td>{info_text}</td>")
        html_content.append(f"<td>{reme_text}</td>")
        html_content.append("</tr>")

    html_content.append("</table>")
    html_content.append("</div>")  # Close .content div
    html_content.append("</body></html>")

    # -------------------------------------------------------------------------
    # 6. Write the HTML content to file
    # -------------------------------------------------------------------------
    with open(report_html_file, "w", encoding="utf-8") as f:
        f.write("\n".join(html_content))
    
    print(f"HTML report generated: {bcolors.OKGREEN} {report_html_file}")


skip_current_tool = False
# Create a global threading event
event = threading.Event()  

def signal_handler(sig, frame):
    """Handles CTRL+C (SIGINT) to skip current tool and CTRL+Z (SIGTSTP) to exit immediately."""
    global skip_current_tool, event

    if sig == signal.SIGINT:  # CTRL+C → Skip the current tool
        if not skip_current_tool:  # Prevent multiple "Skipping current tool..." messages
            skip_current_tool = True  # Set flag to skip current tool
            event.set()  # Stop loading animation safely

    elif sig == signal.SIGTSTP:  # CTRL+Z → Exit program immediately
        print(f"\n{bcolors.BADFAIL}Scan interrupted. Exiting immediately...{bcolors.ENDC}")
        event.set()  # Stop loading animation safely
        sys.exit(0)  # Stop program immediately

def get_target_ip(target):
    try:
        parsed_url = urlsplit(target)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path  
        # Remove the port if present
        hostname = hostname.split(":")[0]
        # Use the full hostname instead of stripping subdomains
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return "Unknown"

def main():
    # ---------- argument parsing ----------
    parser = argparse.ArgumentParser(add_help=False)
    group  = parser.add_mutually_exclusive_group()
    group.add_argument("-V", "-v", action="store_true",
                       help="Print version information")
    group.add_argument("-U", "-u", action="store_true",
                       help="Replace every file/directory with a git clone")
    group.add_argument("-H", "-h", "-help", action="store_true",
                       help="Show help message")
    parser.add_argument("target", nargs="?", help="Target URL to scan")
    args = parser.parse_args()

    # ---------- banner for each mode ----------
    if args.V:
        print_banner("CHECKING . . .", "")
        print(f"Version: {VERSION}")
        sys.exit(0)

    if args.U:
        print_banner("UPDATING . . .", "")
        os.system("git clone https://github.com/parkkung456/VULNscan.git")
        sys.exit(0)

    if args.H or not args.target:
        print_banner("HELP", "")
        show_help()
        sys.exit(0)

    # ---------- normal scan banner ----------
    target_raw = args.target
    print_banner(target_raw, "SCANNING . . .")

    target       = url_maker(args.target)
    target_ip    = get_target_ip(target)
    wapiti_target = wapiti_url(target)

    if target_ip == "Unknown":
        print(f"{bcolors.BADFAIL}Error: Unable to resolve target IP for "
              f"{target}.{bcolors.ENDC}")
        sys.exit(1)


    # ---------- house‑keeping ----------
    timestamp   = datetime.now().strftime("%d-%m-%Y-%H%M")
    reports_dir = "scan_reports"
    os.makedirs(reports_dir, exist_ok=True)
    raw_report_file = os.path.join(
        reports_dir,
        f"{timestamp}-raw_report_{target.replace('http://','').replace('https://','').replace('/','_')}.txt"
    )

    print(f"\n{bcolors.BOLD}Starting security scan on {bcolors.OKBLUE}{target}"
          f"{bcolors.ENDC} ({bcolors.OKGREEN}IP: {target_ip}{bcolors.ENDC})...\n")

    if not check_internet():
        print(f"{bcolors.BADFAIL}No internet connection. Exiting...{bcolors.ENDC}")
        sys.exit(1)

    # ---------- tool list ----------
    tool_list = [
        ["nmap",                     f"nmap -sC -sV {target_ip}"],
        ["nmap_sqlserver",           f"nmap -p1433 --open -Pn {target_ip}"],
        ["nmap_mysql",               f"nmap -p3306 --open -Pn {target_ip}"],
        ["nmap_oracle",              f"nmap -p1521 --open -Pn {target_ip}"],
        ["nikto",                    f"nikto -Plugins 'apache_expect_xss' -host {target}"],
        ["uniscan_rce",              f"uniscan -s -u {target}"],
        ["uniscan_xss",              f"uniscan -d -u {target}"],
        ["lbd",                      f"lbd {target}"],
        ["wapiti_sqli",              f"wapiti -m sql -u {target} --verbose 2"],
        ["wapiti_ssrf",              f"wapiti -m ssrf -u {target} --verbose 2"],
        ["wapiti_xss",               f"wapiti -m xss -u {target} --verbose 2"],
        ["gobuster_directory_traversal",
         f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -u {target}"],
        ["uniscan_directory_traversal", f"uniscan -q -u {target}"],
        ["uniscan_file_traversal",      f"uniscan -w -u {target}"],
        ["nikto_outdated",              f"nikto -Plugins 'outdated' -host {target}"],
        ["nikto_accessible_paths",      f"nikto -Plugins 'paths' -host {target}"]
    ]

    tool_list = check_dynamic_tools(tool_list)

    # ---------- status bar: scan phase begins ----------
    print()
    phase_bar = "-> [  Main scan Phase Checking . . .  "
    print(bg_blue(phase_bar + "Loading Task . . . ]"))

    tasks_executed      = len(tool_list)
    tools_skipped_count = 0
    proc_vul_list       = {}
    event               = threading.Event()

    with open(raw_report_file, "w") as f:
        f.write(f"Raw Scan Report for {target} (IP: {target_ip})\n")
        f.write("=" * 50 + "\n")

    # ---------- main scan loop ----------
    start_time = time.time()
    for tool_name, command in tool_list:
        output = execute_scan(tool_name, command, target, event)
        if output is None:
            tools_skipped_count += 1
            continue
        vulns = detect_errors(tool_name, output, raw_report_file)
        if vulns:
            proc_vul_list[tool_name] = vulns
        else:
            print(f"{bcolors.OKBLUE}Task complete.{bcolors.ENDC}{bcolors.OKGREEN}No vulnerability found for "
                  f"{tool_name}.{bcolors.ENDC}")

    total_time = time.time() - start_time

    # ---------- status bar: scan finished ----------
    print(bg_green(phase_bar + "Complete ]"))
    print()
# ---------- log‑file status banners ----------
    log_bar = "-> [  Creating log file from all task . . .  "
    print(bg_blue(log_bar + "Generating . . . ]"))

    severity_counts = {"c": 0, "h": 0, "m": 0, "l": 0}
    for tool, vulns in proc_vul_list.items():
        for vuln, severity in vulns:
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts[severity] = 1

    print("\nFinal Summary:")
    print("----------------------")
    print(f"Total Vulnerability Task check       : {tasks_executed}")
    print(f"Total Tool skipped                   : {tools_skipped_count}")
    print(f"Total Vulnerability Thread detected  : CRITICAL({severity_counts.get('c', 0)}), HIGH ({severity_counts.get('h', 0)}), MEDIUM({severity_counts.get('m', 0)}), LOW ({severity_counts.get('l', 0)})")
    print(f"Total time from scan                 : {total_time:.2f} seconds")
    print("----------------------")

    generate_report(proc_vul_list, target, raw_report_file)
    generate_html_report(
        proc_vul_list=proc_vul_list,
        target=target,
        target_ip=target_ip,
        severity_counts=severity_counts,
        tasks_executed=tasks_executed,
        tools_skipped_count=tools_skipped_count,
        total_time=total_time,
        raw_report_file=raw_report_file 
    )
    print()
    print(bg_green(log_bar + "Complete . . . ]"))

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    main()


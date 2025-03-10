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

# ANSI Colors for Terminal Output
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

VULNERABILITY_PATTERNS = {
    "80/tcp open  http": "l",
    "23/tcp open telnet": "c", 
    "21/tcp open ftp": "h", 
    "3306/tcp open mysql": "m", 
    "1433/tcp open": "m", 
    "1521/tcp open": "m", 
    "does NOT use Load-balancing": "m",
    "[+] Vul [Blind SQL-i]": "m",
    "[+] Vul [SQL-i]": "m",
    "[+] Vul [XSS]": "m",
    "[+] Vul [RCE]": "m",
    "0 item(s) reported": "l"
}

def print_banner():
    ascii_art = r"""
 __     ___   _ _     _   _ ____   ____    _    _   _ 
 \ \   / / | | | |   | \ | / ___| / ___|  / \  | \ | |
  \ \ / /| | | | |   |  \| \___ \| |     / _ \ |  \| |
   \ V / | |_| | |___| |\  |___) | |___ / ___ \| |\  |
    \_/   \___/|_____|_| \_|____/ \____/_/   \_\_| \_|
    """
    print(ascii_art)

def check_dynamic_tools(tool_list):
    """
    Checks for required tools dynamically.
    For each tool in the tool_list, if the base tool (nmap, nikto, uniscan, wapiti, gobuster)
    is missing, prints a warning and removes that scan from the list.
    Returns a filtered list of available tools.
    """
    filtered_tool_list = []
    missing_tools = set()

    for tool_name, command in tool_list:
        # Determine the required base tool from the tool_name
        base_tool = None
        if "nmap" in tool_name:
            base_tool = "nmap"
        elif "nikto" in tool_name:
            base_tool = "nikto"
        elif "uniscan" in tool_name:
            base_tool = "uniscan"
        elif "wapiti" in tool_name:
            base_tool = "wapiti"
        elif "gobuster" in tool_name:
            base_tool = "gobuster"

        # If we identified a base tool, check its availability
        if base_tool and shutil.which(base_tool) is None:
            print(f"{bcolors.WARNING}Warning: {base_tool} is not available. Skipping {tool_name} scan.{bcolors.ENDC}")
            missing_tools.add(base_tool)
        else:
            filtered_tool_list.append((tool_name, command))

    # Alert the user about overall availability
    required = {"nmap", "nikto", "uniscan", "wapiti", "gobuster"}
    available = required - missing_tools
    if missing_tools:
        print(f"{bcolors.WARNING}The following tools are missing: {', '.join(sorted(missing_tools))}.{bcolors.ENDC}")
    else:
        print(f"{bcolors.OKGREEN}All required tools are available. Starting scanning...{bcolors.ENDC}")

    return filtered_tool_list


def url_maker(url):
    """Ensures the target URL is correctly formatted for Wapiti."""
    if not re.match(r'http(s?)\:', url):  # If missing http:// or https://
        url = 'http://' + url  # Default to HTTP if missing
    parsed = urlsplit(url)
    return parsed.geturl() 

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
    print("\r", end='', flush=True) 

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
                severity_counts[severity] = 1  # Unexpected severity appears

    severity_labels = {
        "c": "CRITICAL",
        "h": "HIGH",
        "m": "MEDIUM",
        "l": "LOW"
    }

    print("\nVulnerability Summary:")
    print("----------------------")
    for sev_code, count in severity_counts.items():
        label = severity_labels.get(sev_code, sev_code)
        print(f"{label}: {count}")

    return severity_counts


def main():
    print_banner() 

    global event  
    parser = argparse.ArgumentParser()
    parser.add_argument('target', metavar='URL', help='Target URL to scan.')
    args = parser.parse_args()

    target = url_maker(args.target)  # Ensure correct URL format
    target_ip = get_target_ip(target)  # Get the resolved IP address
    wapiti_target = wapiti_url(target)

    if target_ip == "Unknown":
        print(f"{bcolors.BADFAIL}Error: Unable to resolve target IP for {target}. Please check your network or DNS settings.{bcolors.ENDC}")
        sys.exit(1)

    timestamp = datetime.now().strftime("%d-%m-%Y-%H%M")
    reports_dir = "scan_reports"
    os.makedirs(reports_dir, exist_ok=True)
    raw_report_file = os.path.join(
        reports_dir,
        f"{timestamp}-raw_report_{target.replace('http://', '').replace('https://', '').replace('/', '_')}.txt"
    )

    print(f"\n{bcolors.BOLD}Starting security scan on {bcolors.OKBLUE}{target}{bcolors.ENDC} "
          f"({bcolors.OKGREEN}IP: {target_ip}{bcolors.ENDC})...\n")

    if not check_internet():
        print(f"{bcolors.BADFAIL}No internet connection. Exiting...{bcolors.ENDC}")
        sys.exit(1)

    # Define full tool list
    tool_list = [
        ["nmap", f"nmap -sV {target_ip}"],
        ["nmap_sqlserver", f"nmap -p1433 --open -Pn {target_ip}"],
        ["nmap_mysql", f"nmap -p3306 --open -Pn {target_ip}"],
        ["nmap_oracle", f"nmap -p1521 --open -Pn {target_ip}"],
        ["nikto", f"nikto -Plugins 'apache_expect_xss' -host {target}"],
        ["uniscan_rce", f"uniscan -s -u {target}"],
        ["uniscan_xss", f"uniscan -d -u {target}"],
        ["lbd", f"lbd {target}"],
        ["wapiti_sqli", f"wapiti -m sql -u {target} --verbose 2"],
        ["wapiti_ssrf", f"wapiti -m ssrf -u {target} --verbose 2"],
        ["wapiti_xss", f"wapiti -m xss -u {target} --verbose 2"],
        ["wapiti_http_headers", f"wapiti -m http_headers -u {target} --verbose 2"],
        ["gobuster_directory_traversal", f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -u {target}"]
    ]
    
    # Dynamically check tool availability and filter tool_list
    tool_list = check_dynamic_tools(tool_list)
    tasks_executed = len(tool_list)
    tools_skipped_count = 0
    proc_vul_list = {}
    event = threading.Event()

    try:
        with open(raw_report_file, "w") as file:
            file.write(f"Raw Scan Report for {target} (IP: {target_ip})\n")
            file.write("=" * 50 + "\n")
    except Exception as e:
        print(f"{bcolors.BADFAIL}Error: Could not write to report file: {e}{bcolors.ENDC}")
        sys.exit(1)

    start_time = time.time()
    for i, (tool_name, command) in enumerate(tool_list):
        output = execute_scan(tool_name, command, target, event)

        # If no output is returned, count it as a skipped tool
        if output is None:
            tools_skipped_count += 1
            continue

        detected_vulns = detect_errors(tool_name, output, raw_report_file)
        if detected_vulns:
            proc_vul_list[tool_name] = detected_vulns
        else:
            print(f"{bcolors.OKGREEN}Task complete. No vulnerability was found in this task for {tool_name}.{bcolors.ENDC}")

    total_time = time.time() - start_time

    # Print the vulnerability summary and retrieve counts
    severity_counts = print_vulnerability_summary(proc_vul_list)

    print("\nFinal Summary:")
    print("----------------------")
    print(f"Total Vulnerability Task check: {tasks_executed}")
    print(f"Total Tool skipped: {tools_skipped_count}")
    print("Total Vulnerability Thread detected:")
    print(f"    CRITICAL: {severity_counts.get('c', 0)}")
    print(f"    HIGH: {severity_counts.get('h', 0)}")
    print(f"    MEDIUM: {severity_counts.get('m', 0)}")
    print(f"    LOW: {severity_counts.get('l', 0)}")
    print(f"Total time from scan: {total_time:.2f} seconds")

    generate_report(proc_vul_list, target, raw_report_file)


def execute_scan(tool_name, command, target, event):
    """Executes the scanning tool dynamically and allows skipping on CTRL+C."""
    global skip_current_tool

    # Dynamic scan message for different tools
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
	"wapiti_http_headers": " - Checking for HTTP Header security...",
	"gobuster_directory_traversal": " - Checking for Directiory Traversal...",
    }
    scan_message = tool_messages[tool_name.lower()]

    print(f"{bcolors.OKBLUE}Running {tool_name}{bcolors.BOLD}{scan_message}{bcolors.ENDC}", flush=True)

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

        # If tool was skipped, return None
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
    target_ip = get_target_ip(target) 

    if target_ip == "Unknown":
        print(f"{bcolors.BADFAIL}Error: Unable to resolve target IP for {target}.{bcolors.ENDC}")
        sys.exit(1)

    return f"http://{target_ip}"

def detect_errors(tool_name, output, raw_report_file):
    """Checks scan result for vulnerabilities and writes them to the raw report."""
    detected_vulns = []

    with open(raw_report_file, "a") as report:
        report.write(f"\n== {tool_name} Scan Output ==\n")
        report.write(output + "\n")

    for line in output.splitlines():
        line = line.strip()

        
        if tool_name.lower() in ["wapiti_sqli", "wapiti_ssrf", "wapiti_xss", "wapiti_http_headers"]:
            if re.match(r"^\[\+\].*\(3\)$", line):
                detected_vulns.append((line, "m"))
                print(
                    f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{line}{bcolors.ENDC} "
                    f"detected as {bcolors.BADFAIL}MEDIUM{bcolors.ENDC}"
                )

        # Check for gobuster directory traversal output
        elif tool_name.lower() in ["gobuster_directory_traversal"]:
            # Remove ANSI escape sequences from the line
            clean_line = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', line)
            if clean_line.startswith("/"):
                status_match = re.search(r"\(Status:\s*(\d+)\)", clean_line)
                if status_match:
                    status_code = int(status_match.group(1))
                    if status_code == 200:
                        detected_vulns.append((clean_line, "h"))
                        print(
                            f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{clean_line}{bcolors.ENDC} "
                            f"detected as {bcolors.BADFAIL}HIGH{bcolors.ENDC}"
                        )
                    else:
                        detected_vulns.append((clean_line, "l"))
                        print(
                            f"{bcolors.WARNING}[{tool_name}]{bcolors.ENDC} {bcolors.BOLD}{clean_line}{bcolors.ENDC} "
                            f"detected as {bcolors.BADFAIL}LOW{bcolors.ENDC}"
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

    # Save vulnerabilities to raw report
    with open(raw_report_file, "a") as report:
        for vuln, severity in detected_vulns:
            report.write(f"{vuln} - Severity: {severity}\n")

    return detected_vulns

def generate_report(proc_vul_list, target, raw_report_file):
    """Generates a vulnerability report and appends it to the raw report.
    For each tool, only one consolidated block is printed using the worst severity detected.
    """
    if not proc_vul_list:
        print(f"{bcolors.OKGREEN}Task complete. No vulnerability was found in this task.{bcolors.ENDC}")
        return

    # Custom vulnerability information tool and severity.
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
        "wapiti_http_headers": {
            "l": "Wapiti HTTP Headers (Low): No major issues detected in HTTP header configuration.",
            "m": "Wapiti HTTP Headers (Medium): Some header misconfigurations identified.",
            "h": "Wapiti HTTP Headers (High): Critical HTTP header misconfigurations detected.",
            "c": "Wapiti HTTP Headers (Critical): Severe HTTP header vulnerabilities discovered."
        },
        "gobuster_directory_traversal": {
            "l": "Gobuster (Low): Directory listing appears benign.",
            "m": "Gobuster (Medium): Found directories that might expose non-sensitive content.",
            "h": "Gobuster (High): Critical directories accessible that should be restricted.",
            "c": "Gobuster (Critical): Sensitive directories exposed."
        }
    }

    # Custom remediation advice tool and severity.
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
        "wapiti_http_headers": {
            "l": "Review HTTP header configurations; minor adjustments may be sufficient.",
            "m": "Update server configurations to enforce security headers.",
            "h": "Apply strict security policies on HTTP headers immediately.",
            "c": "Immediately enforce comprehensive security headers and perform a server audit."
        },
        "gobuster_directory_traversal": {
            "l": "Review directory permissions and ensure that only necessary directories are exposed.",
            "m": "Audit the directory structure and secure sensitive directories.",
            "h": "Restrict access to critical directories via proper authentication.",
            "c": "Immediately restrict directory access and conduct a security audit."
        }
    }

    # Mapping of tool names scan messages.
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
        "wapiti_http_headers": " - Checking for HTTP Header security...",
        "gobuster_directory_traversal": " - Checking for Directiory Traversal..."
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
        "wapiti_http_headers": f"wapiti -m http_headers -u {target} --verbose 2",
        "gobuster_directory_traversal": f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -u {target}"
    }

    # Convert severity code to human-readable text.
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
                
                # raw report, list the aggregated result.
                raw_report.write(f"== {tool} Aggregated Findings ==\n")
                raw_report.write(f"Aggregated Severity: {worst_severity} ({threat_level})\n\n")
            
        print(f"\n{bcolors.BOLD}Scan completed.{bcolors.ENDC}")
        print(f"Report saved as {bcolors.OKGREEN}{report_txt_file}{bcolors.ENDC}")
        print(f"Full raw output saved in {bcolors.OKGREEN}{raw_report_file}{bcolors.ENDC}")
    except Exception as e:
        print(f"{bcolors.BADFAIL}Error writing reports: {e}{bcolors.ENDC}")


skip_current_tool = False
event = threading.Event()  # global threading event

def signal_handler(sig, frame):
    """Handles CTRL+C (SIGINT) to skip current tool and CTRL+Z (SIGTSTP) to exit immediately."""
    global skip_current_tool, event

    if sig == signal.SIGINT:  # CTRL+C → Skip the current tool
        if not skip_current_tool:
            skip_current_tool = True  # Set flag to skip current tool
            event.set()  # Stop loading animation 

    elif sig == signal.SIGTSTP:  # CTRL+Z → Exit program immediately
        print(f"\n{bcolors.BADFAIL}Scan interrupted. Exiting immediately...{bcolors.ENDC}")
        event.set()
        sys.exit(0) 

def get_target_ip(target):
    try:
        parsed_url = urlsplit(target)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path  
        hostname = hostname.split(":")[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return "Unknown"

def main():
    print_banner() 

    global event  
    parser = argparse.ArgumentParser()
    parser.add_argument('target', metavar='URL', help='Target URL to scan.')
    args = parser.parse_args()

    target = url_maker(args.target)  # Ensure correct URL format
    target_ip = get_target_ip(target)  # Get the resolved IP address
    wapiti_target = wapiti_url(target)  # Get the properly formatted Wapiti URL

    if target_ip == "Unknown":
        print(f"{bcolors.BADFAIL}Error: Unable to resolve target IP for {target}. Please check your network or DNS settings.{bcolors.ENDC}")
        sys.exit(1)

    timestamp = datetime.now().strftime("%d-%m-%Y-%H%M")
    reports_dir = "scan_reports"
    os.makedirs(reports_dir, exist_ok=True)
    raw_report_file = os.path.join(
        reports_dir, 
        f"{timestamp}-raw_report_{target.replace('http://', '').replace('https://', '').replace('/', '_')}.txt"
    )

    print(f"\n{bcolors.BOLD}Starting security scan on {bcolors.OKBLUE}{target}{bcolors.ENDC} "
          f"({bcolors.OKGREEN}IP: {target_ip}{bcolors.ENDC})...\n")

    if not check_internet():
        print(f"{bcolors.BADFAIL}No internet connection. Exiting...{bcolors.ENDC}")
        sys.exit(1)

    # Define your full tool list
    tool_list = [
        ["nmap", f"nmap -sV {target_ip}"],
        ["nmap_sqlserver", f"nmap -p1433 --open -Pn {target_ip}"],
        ["nmap_mysql", f"nmap -p3306 --open -Pn {target_ip}"],
        ["nmap_oracle", f"nmap -p1521 --open -Pn {target_ip}"],
        ["nikto", f"nikto -Plugins 'apache_expect_xss' -host {target}"],
        ["uniscan_rce", f"uniscan -s -u {target}"],
        ["uniscan_xss", f"uniscan -d -u {target}"],
        ["lbd", f"lbd {target}"],
        ["wapiti_sqli", f"wapiti -m sql -u {target} --verbose 2"],
        ["wapiti_ssrf", f"wapiti -m ssrf -u {target} --verbose 2"],
        ["wapiti_xss", f"wapiti -m xss -u {target} --verbose 2"],
        ["wapiti_http_headers", f"wapiti -m http_headers -u {target} --verbose 2"],
        ["gobuster_directory_traversal", f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -u {target}"]
    ]
    
    # Dynamically check tool availability and filter tool_list accordingly.
    tool_list = check_dynamic_tools(tool_list)
    tasks_executed = len(tool_list)
    tools_skipped_count = 0
    proc_vul_list = {}
    event = threading.Event()

    try:
        with open(raw_report_file, "w") as file:
            file.write(f"Raw Scan Report for {target} (IP: {target_ip})\n")
            file.write("=" * 50 + "\n")
    except Exception as e:
        print(f"{bcolors.BADFAIL}Error: Could not write to report file: {e}{bcolors.ENDC}")
        sys.exit(1)

    start_time = time.time()
    for i, (tool_name, command) in enumerate(tool_list):
        output = execute_scan(tool_name, command, target, event)

        # If no output is returned, count it as a skipped tool.
        if output is None:
            tools_skipped_count += 1
            continue

        detected_vulns = detect_errors(tool_name, output, raw_report_file)
        if detected_vulns:
            proc_vul_list[tool_name] = detected_vulns
        else:
            print(f"{bcolors.OKGREEN}Task complete. No vulnerability was found in this task for {tool_name}.{bcolors.ENDC}")

    total_time = time.time() - start_time

    # Compute severity counts without printing 
    severity_counts = {"c": 0, "h": 0, "m": 0, "l": 0}
    for tool, vulns in proc_vul_list.items():
        for vuln, severity in vulns:
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts[severity] = 1

    # Print final summary report
    print("\nFinal Summary:")
    print("-----------------------------------------------------------------------------------")
    print(f"Total Vulnerability Task check       : {tasks_executed}")
    print(f"Total Tool skipped                   : {tools_skipped_count}")
    print(f"Total Vulnerability Thread detected  : CRITICAL({severity_counts.get('c', 0)}), HIGH ({severity_counts.get('h', 0)}), MEDIUM({severity_counts.get('m', 0)}), LOW ({severity_counts.get('l', 0)})")
    print(f"Total time from scan                 : {total_time:.2f} seconds")
    print("-----------------------------------------------------------------------------------")

    generate_report(proc_vul_list, target, raw_report_file)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C (skip task)
    signal.signal(signal.SIGTSTP, signal_handler)  # Handle Ctrl+Z (exit gracefully)
    main()

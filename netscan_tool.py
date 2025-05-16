#!/usr/bin/env python3
# NetScan v1.1.0 - Network Scanning Tool
# Developed by xAI Cybersecurity
# For network administrators and security professionals

import os
import sys
import json
import sqlite3
import argparse
import datetime
import subprocess
from pathlib import Path
import threading
import time
import ipaddress
import re
import nmap
import colorama
from colorama import Fore, Back, Style
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from tqdm import tqdm
from tabulate import tabulate

# Initialize colorama
colorama.init(autoreset=True)

# ASCII Art Banner
BANNER = r"""
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                              v1.1.0
      [ Network Security Scanner by xAI Cybersecurity ]
"""

# Create necessary directories
BASE_DIR = Path(__file__).resolve().parent
SCANS_DIR = BASE_DIR / "scans"
CONFIG_FILE = BASE_DIR / "config.json"
DB_FILE = BASE_DIR / "scan_history.db"

SCANS_DIR.mkdir(exist_ok=True)

# Default vulnerability database if config.json doesn't exist
DEFAULT_CONFIG = {
    "vulnerable_software": {
        "Apache 2.4.29": {
            "cve": "CVE-2021-44790",
            "severity": "HIGH",
            "action": "Upgrade to Apache 2.4.52 or later"
        },
        "OpenSSH 7.5": {
            "cve": "CVE-2018-15473",
            "severity": "MEDIUM",
            "action": "Upgrade to OpenSSH 7.9 or later"
        },
        "MySQL 5.7.30": {
            "cve": "CVE-2020-14760",
            "severity": "MEDIUM",
            "action": "Upgrade to MySQL 5.7.31 or later"
        },
        "Nginx 1.16.0": {
            "cve": "CVE-2019-20372",
            "severity": "HIGH",
            "action": "Upgrade to Nginx 1.16.1 or later"
        },
        "ProFTPD 1.3.5": {
            "cve": "CVE-2019-12815",
            "severity": "CRITICAL",
            "action": "Upgrade to ProFTPD 1.3.6 or later"
        }
    },
    "scan_settings": {
        "default_timeout": 300,
        "default_threads": 5,
        "stealth_delay": 0.5
    }
}

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        scan_type TEXT,
        timestamp TEXT,
        report_file TEXT,
        open_ports INTEGER,
        vulnerabilities INTEGER
    )
    ''')
    conn.commit()
    conn.close()

# Check for config file and create if it doesn't exist
def init_config():
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        print(f"{Fore.YELLOW}Config file created at {CONFIG_FILE}")
    
    # Load config
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

# Check for nmap binary
def check_nmap():
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

class NetScan:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.config = init_config()
        self.target = None
        self.scan_type = None
        self.report_file = None
        self.open_ports = 0
        self.vulnerabilities = 0
        self.scan_start_time = None
        
    def validate_target(self, target):
        """Validate if the target is a valid IP address, range, or hostname"""
        # Check if it's a single IP
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Check if it's a CIDR range
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
        
        # Check if it's an IP range like 192.168.1.1-10
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$', target):
            return True
            
        # Check if it's a hostname (basic validation)
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', target):
            return True
            
        return False

    def quick_scan(self, target):
        """Performs a quick scan of the most common ports"""
        self.target = target
        self.scan_type = "Quick Scan"
        
        print(f"\n{Fore.CYAN}[*] Starting Quick Scan on {target}...")
        
        try:
            # Scan the most common 100 ports
            self.scan_start_time = datetime.datetime.now()
            self.nm.scan(hosts=target, arguments="-F -T4")
            
            self.generate_report()
            self.save_to_db()
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error during quick scan: {str(e)}")
            return False

    def full_port_scan(self, target):
        """Performs a scan of all 65535 ports"""
        self.target = target
        self.scan_type = "Full Port Scan"
        
        print(f"\n{Fore.CYAN}[*] Starting Full Port Scan on {target}...")
        print(f"{Fore.YELLOW}[*] This may take a while. All 65535 ports will be scanned.")
        
        try:
            # Scan all ports with version detection
            self.scan_start_time = datetime.datetime.now()
            self.nm.scan(hosts=target, arguments="-p- -sV --version-intensity 4")
            
            self.generate_report()
            self.save_to_db()
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error during full port scan: {str(e)}")
            return False

    def indepth_scan(self, target):
        """Performs an in-depth scan with OS detection and script scanning"""
        self.target = target
        self.scan_type = "In-depth Scan"
        
        print(f"\n{Fore.CYAN}[*] Starting In-depth Scan on {target}...")
        print(f"{Fore.YELLOW}[*] This comprehensive scan may take significant time.")
        
        try:
            # Comprehensive scan with OS detection and default scripts
            self.scan_start_time = datetime.datetime.now()
            self.nm.scan(hosts=target, arguments="-sS -sV -sC -A -O")
            
            self.generate_report()
            self.save_to_db()
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error during in-depth scan: {str(e)}")
            return False

    def vulnerability_scan(self, target):
        """Performs a vulnerability scan using Nmap scripts"""
        self.target = target
        self.scan_type = "Vulnerability Scan"
        
        print(f"\n{Fore.CYAN}[*] Starting Vulnerability Scan on {target}...")
        print(f"{Fore.YELLOW}[*] Checking for known vulnerabilities...")
        
        try:
            # Run vulnerability scanning scripts
            self.scan_start_time = datetime.datetime.now()
            self.nm.scan(hosts=target, arguments="-sV --script vuln")
            
            self.generate_report()
            self.check_vulnerabilities()
            self.save_to_db()
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error during vulnerability scan: {str(e)}")
            return False

    def stealth_scan(self, target):
        """Performs a stealthy scan to avoid detection"""
        self.target = target
        self.scan_type = "Stealth Scan"
        
        print(f"\n{Fore.CYAN}[*] Starting Stealth Scan on {target}...")
        print(f"{Fore.YELLOW}[*] Scanning with minimal footprint...")
        
        try:
            # Stealthy scan options
            delay = self.config['scan_settings']['stealth_delay']
            self.scan_start_time = datetime.datetime.now()
            self.nm.scan(hosts=target, arguments=f"-sS -T2 --max-retries 1 --host-timeout 30 --scan-delay {delay}")
            
            self.generate_report()
            self.save_to_db()
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error during stealth scan: {str(e)}")
            return False

    def web_stack_scan(self, target):
        """Focuses on web server detection and web application scanning"""
        self.target = target
        self.scan_type = "Web Stack Scan"
        
        print(f"\n{Fore.CYAN}[*] Starting Web Stack Scan on {target}...")
        print(f"{Fore.YELLOW}[*] Detecting web servers and applications...")
        
        try:
            # Web focused scan
            self.scan_start_time = datetime.datetime.now()
            self.nm.scan(hosts=target, arguments="-p 80,443,8080,8443 -sV --script=http-enum,http-headers,http-methods,http-title")
            
            self.generate_report()
            self.save_to_db()
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error during web stack scan: {str(e)}")
            return False

    def custom_scan(self, target, arguments):
        """Performs a scan with custom arguments"""
        self.target = target
        self.scan_type = "Custom Scan"
        
        print(f"\n{Fore.CYAN}[*] Starting Custom Scan on {target}...")
        print(f"{Fore.YELLOW}[*] Using arguments: {arguments}")
        
        try:
            # Run the custom scan
            self.scan_start_time = datetime.datetime.now()
            self.nm.scan(hosts=target, arguments=arguments)
            
            self.generate_report()
            self.save_to_db()
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error during custom scan: {str(e)}")
            return False

    def check_vulnerabilities(self):
        """Checks scan results against known vulnerabilities in config"""
        vulnerable_software = self.config.get('vulnerable_software', {})
        vulnerable_hosts = []
        
        print(f"\n{Fore.CYAN}[*] Checking for known vulnerabilities...")
        
        # Check each scanned host
        for host in self.nm.all_hosts():
            host_vulns = []
            
            # Check each open port
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    service = self.nm[host][proto][port]
                    product = service.get('product', '')
                    version = service.get('version', '')
                    
                    if product and version:
                        software = f"{product} {version}"
                        
                        # Check if this software version is in our vulnerability database
                        for vuln_sw in vulnerable_software:
                            if software.lower().startswith(vuln_sw.lower()):
                                vuln_info = vulnerable_software[vuln_sw]
                                host_vulns.append({
                                    'port': port,
                                    'software': software,
                                    'cve': vuln_info.get('cve', 'Unknown'),
                                    'severity': vuln_info.get('severity', 'UNKNOWN'),
                                    'action': vuln_info.get('action', 'No recommendation available')
                                })
                                self.vulnerabilities += 1
            
            if host_vulns:
                vulnerable_hosts.append((host, host_vulns))
        
        # Append vulnerability information to the report
        if vulnerable_hosts:
            with open(self.report_file, 'a') as f:
                f.write("\n\n" + "="*60 + "\n")
                f.write("VULNERABILITY ASSESSMENT\n")
                f.write("="*60 + "\n\n")
                
                for host, vulns in vulnerable_hosts:
                    f.write(f"Host: {host}\n")
                    f.write("-"*40 + "\n")
                    
                    for v in vulns:
                        f.write(f"  Port {v['port']}: {v['software']}\n")
                        f.write(f"  CVE: {v['cve']}\n")
                        f.write(f"  Severity: {v['severity']}\n")
                        f.write(f"  Remediation: {v['action']}\n\n")
        
        return vulnerable_hosts

    def generate_report(self):
        """Generates a detailed report from scan results"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_target = self.target.replace('/', '_').replace(':', '_')
        report_filename = f"{self.scan_type.lower().replace(' ', '_')}_{sanitized_target}_{timestamp}.txt"
        self.report_file = str(SCANS_DIR / report_filename)
        
        # Calculate scan duration
        scan_duration = datetime.datetime.now() - self.scan_start_time
        
        with open(self.report_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write(f"NetScan v1.1.0 - Scan Report\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Target: {self.target}\n")
            f.write(f"Scan Type: {self.scan_type}\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {scan_duration}\n\n")
            
            f.write("="*60 + "\n")
            f.write("SCAN RESULTS\n")
            f.write("="*60 + "\n\n")
            
            # Process each host
            for host in self.nm.all_hosts():
                f.write(f"Host: {host}\n")
                f.write(f"State: {self.nm[host].state()}\n")
                
                # OS detection results if available
                if 'osmatch' in self.nm[host]:
                    for osmatch in self.nm[host]['osmatch']:
                        f.write(f"OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)\n")
                
                f.write("\nOpen Ports:\n")
                f.write("-"*40 + "\n")
                
                # Process each protocol
                for proto in self.nm[host].all_protocols():
                    f.write(f"Protocol: {proto}\n")
                    
                    # Get all ports for that protocol
                    ports = sorted(self.nm[host][proto].keys())
                    
                    for port in ports:
                        self.open_ports += 1
                        service = self.nm[host][proto][port]
                        service_name = service.get('name', 'unknown')
                        product = service.get('product', '')
                        version = service.get('version', '')
                        
                        port_info = f"Port {port}/{proto}: {service_name}"
                        if product:
                            port_info += f" - {product}"
                            if version:
                                port_info += f" {version}"
                        
                        f.write(f"{port_info}\n")
                        
                        # Include script output if available
                        if 'script' in service:
                            f.write("  Script Results:\n")
                            for script_name, output in service['script'].items():
                                f.write(f"    {script_name}: {output}\n")
                
                f.write("\n")
            
            f.write("\n" + "="*60 + "\n")
            f.write("SUMMARY\n")
            f.write("="*60 + "\n\n")
            f.write(f"Total Hosts Scanned: {len(self.nm.all_hosts())}\n")
            f.write(f"Total Open Ports: {self.open_ports}\n")
            
        print(f"{Fore.GREEN}[+] Report generated: {self.report_file}")
        
        # Display dashboard after scan is complete
        self.display_dashboard()
        
        return self.report_file
        
    def display_dashboard(self):
        """Displays a colorful dashboard with scan results"""
        hosts = self.nm.all_hosts()
        
        if not hosts:
            print(f"{Fore.YELLOW}[!] No hosts found in scan results.")
            return
            
        print("\n" + "="*100)
        print(f"{Fore.CYAN}{Style.BRIGHT}  NETSCAN DASHBOARD - SCAN RESULTS  ".center(100, "="))
        print("="*100 + "\n")
        
        print(f"{Fore.GREEN}{Style.BRIGHT}SCAN INFORMATION:")
        print(f"{Fore.WHITE}Target:       {Fore.YELLOW}{self.target}")
        print(f"{Fore.WHITE}Scan Type:    {Fore.YELLOW}{self.scan_type}")
        print(f"{Fore.WHITE}Duration:     {Fore.YELLOW}{datetime.datetime.now() - self.scan_start_time}")
        print(f"{Fore.WHITE}Total Hosts:  {Fore.YELLOW}{len(hosts)}")
        print(f"{Fore.WHITE}Open Ports:   {Fore.YELLOW}{self.open_ports}")
        
        if self.scan_type == "Vulnerability Scan":
            print(f"{Fore.WHITE}Vulnerabilities: {Fore.RED}{self.vulnerabilities}")
        print("\n")
        
        # For each host, display a summary of findings
        for host in hosts:
            host_up = self.nm[host].state() == 'up'
            status_color = Fore.GREEN if host_up else Fore.RED
            print(f"{Fore.CYAN}{Style.BRIGHT}HOST: {host} {status_color}[{self.nm[host].state()}]{Style.RESET_ALL}")
            
            # OS detection if available
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                top_match = self.nm[host]['osmatch'][0]
                print(f"{Fore.WHITE}OS: {Fore.MAGENTA}{top_match['name']} {Fore.YELLOW}(Accuracy: {top_match['accuracy']}%)")
            
            # Display open ports in a table
            port_data = []
            for proto in self.nm[host].all_protocols():
                ports = sorted(self.nm[host][proto].keys())
                for port in ports:
                    service = self.nm[host][proto][port]
                    service_name = service.get('name', 'unknown')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    
                    service_info = service_name
                    if product:
                        service_info = f"{product}"
                        if version:
                            service_info += f" {version}"
                    
                    # Set color based on common ports
                    port_color = Fore.WHITE
                    if port in [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]:
                        port_color = Fore.YELLOW
                    
                    port_data.append([f"{port_color}{port}{Fore.RESET}", 
                                     f"{Fore.CYAN}{proto}{Fore.RESET}", 
                                     f"{Fore.GREEN}{service_name}{Fore.RESET}", 
                                     f"{Fore.BLUE}{service_info}{Fore.RESET}"])
            
            if port_data:
                print(f"\n{Fore.WHITE}{Style.BRIGHT}Open Ports:")
                headers = [f"{Fore.WHITE}{Style.BRIGHT}Port", "Protocol", "Service", "Version"]
                print(tabulate(port_data, headers=headers, tablefmt="simple"))
            else:
                print(f"{Fore.YELLOW}No open ports found.")
            
            # Display vulnerabilities if this was a vulnerability scan
            if self.scan_type == "Vulnerability Scan":
                vuln_data = []
                vulnerable_software = self.config.get('vulnerable_software', {})
                
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        service = self.nm[host][proto][port]
                        product = service.get('product', '')
                        version = service.get('version', '')
                        
                        if product and version:
                            software = f"{product} {version}"
                            
                            for vuln_sw in vulnerable_software:
                                if software.lower().startswith(vuln_sw.lower()):
                                    vuln_info = vulnerable_software[vuln_sw]
                                    severity = vuln_info.get('severity', 'UNKNOWN')
                                    
                                    # Set color based on severity
                                    severity_color = Fore.WHITE
                                    if severity == "LOW":
                                        severity_color = Fore.BLUE
                                    elif severity == "MEDIUM":
                                        severity_color = Fore.YELLOW
                                    elif severity == "HIGH":
                                        severity_color = Fore.RED
                                    elif severity == "CRITICAL":
                                        severity_color = Fore.RED + Style.BRIGHT
                                    
                                    vuln_data.append([
                                        f"{Fore.YELLOW}{port}{Fore.RESET}",
                                        f"{Fore.GREEN}{software}{Fore.RESET}",
                                        f"{Fore.CYAN}{vuln_info.get('cve', 'Unknown')}{Fore.RESET}",
                                        f"{severity_color}{severity}{Fore.RESET}",
                                        f"{Fore.WHITE}{vuln_info.get('action', 'No action specified')}{Fore.RESET}"
                                    ])
                
                if vuln_data:
                    print(f"\n{Fore.RED}{Style.BRIGHT}Vulnerabilities:")
                    vuln_headers = [f"{Fore.WHITE}{Style.BRIGHT}Port", "Software", "CVE", "Severity", "Recommendation"]
                    print(tabulate(vuln_data, headers=vuln_headers, tablefmt="simple"))
                else:
                    print(f"\n{Fore.GREEN}No vulnerabilities detected.")
            
            print("\n" + "-"*100)
        
        # Display a summary of recommendations if vulnerabilities were found
        if self.scan_type == "Vulnerability Scan" and self.vulnerabilities > 0:
            print(f"\n{Fore.RED}{Style.BRIGHT}Security Recommendations:")
            vulnerable_software = set()
            
            for host in hosts:
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto].keys():
                        service = self.nm[host][proto][port]
                        product = service.get('product', '')
                        version = service.get('version', '')
                        
                        if product and version:
                            software = f"{product} {version}"
                            
                            for vuln_sw in self.config.get('vulnerable_software', {}):
                                if software.lower().startswith(vuln_sw.lower()):
                                    vulnerable_software.add(vuln_sw)
            
            # List recommendations
            for i, sw in enumerate(vulnerable_software, 1):
                vuln_info = self.config['vulnerable_software'][sw]
                print(f"{Fore.YELLOW}{i}. {Fore.WHITE}{vuln_info.get('action', 'Update ' + sw)}")
            
            # Generic recommendations
            if self.vulnerabilities > 0:
                print(f"{Fore.YELLOW}{len(vulnerable_software) + 1}. {Fore.WHITE}Consider implementing a web application firewall (WAF)")
                print(f"{Fore.YELLOW}{len(vulnerable_software) + 2}. {Fore.WHITE}Review and restrict unnecessary open ports")
        
        print("\n" + "="*100)
        print(f"{Fore.GREEN}{Style.BRIGHT}Scan complete! Full report saved to: {self.report_file}")
        print("="*100 + "\n")

    def save_to_db(self):
        """Saves scan information to the database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('''
        INSERT INTO scan_history (target, scan_type, timestamp, report_file, open_ports, vulnerabilities)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (self.target, self.scan_type, timestamp, self.report_file, self.open_ports, self.vulnerabilities))
        
        conn.commit()
        conn.close()

    def view_past_scans(self):
        """Displays a list of past scans from the database"""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, target, scan_type, timestamp, open_ports, vulnerabilities FROM scan_history ORDER BY timestamp DESC')
        scans = cursor.fetchall()
        
        conn.close()
        
        if not scans:
            print(f"{Fore.YELLOW}[!] No scan history found.")
            return None
        
        print(f"\n{Fore.CYAN}[*] Scan History:")
        print(f"{Fore.WHITE}{'ID':^5} | {'Target':^15} | {'Scan Type':^20} | {'Timestamp':^20} | {'Ports':^5} | {'Vulns':^5}")
        print("-" * 80)
        
        for scan in scans:
            scan_id, target, scan_type, timestamp, ports, vulns = scan
            print(f"{scan_id:^5} | {target[:15]:^15} | {scan_type[:20]:^20} | {timestamp:^20} | {ports:^5} | {vulns:^5}")
        
        # Prompt user to select a scan to view
        try:
            selected = input(f"\n{Fore.CYAN}Enter scan ID to view details (or 'q' to go back): ")
            if selected.lower() == 'q':
                return None
            
            selected_id = int(selected)
            
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            cursor.execute('SELECT report_file FROM scan_history WHERE id = ?', (selected_id,))
            result = cursor.fetchone()
            
            conn.close()
            
            if result and result[0]:
                report_file = result[0]
                if os.path.exists(report_file):
                    # Display the report content
                    with open(report_file, 'r') as f:
                        report_content = f.read()
                    
                    print("\n" + "="*80)
                    print(report_content)
                    print("="*80)
                    
                    return report_file
                else:
                    print(f"{Fore.RED}[!] Report file not found: {report_file}")
            else:
                print(f"{Fore.RED}[!] Invalid scan ID or report not available.")
        
        except ValueError:
            print(f"{Fore.RED}[!] Please enter a valid scan ID.")
        except Exception as e:
            print(f"{Fore.RED}[!] Error retrieving scan details: {str(e)}")
        
        return None

def display_help():
    """Displays help information"""
    print(f"\n{Fore.CYAN}NetScan Help:")
    print(f"{Fore.WHITE}{'Option':^5} | {'Scan Type':^20} | {'Description'}")
    print("-" * 80)
    print(f"{'1':^5} | {'Quick Scan':^20} | Fast scan of the most common ports")
    print(f"{'2':^5} | {'Full Port Scan':^20} | Comprehensive scan of all 65535 ports")
    print(f"{'3':^5} | {'In-depth Scan':^20} | Detailed scan with OS detection and service fingerprinting")
    print(f"{'4':^5} | {'Vulnerability Scan':^20} | Scan for known vulnerabilities using Nmap scripts")
    print(f"{'5':^5} | {'Stealth Scan':^20} | Low-profile scan to avoid detection")
    print(f"{'6':^5} | {'Web Stack Scan':^20} | Focused scan for web servers and applications")
    print(f"{'7':^5} | {'Custom Scan':^20} | Scan with custom Nmap arguments")
    print(f"{'8':^5} | {'View Past Scans':^20} | View reports from previous scans")
    print(f"{'9':^5} | {'Help':^20} | Display this help information")
    print(f"{'10':^5} | {'Exit':^20} | Exit NetScan")
    print("\n")
    print(f"{Fore.YELLOW}Note: Some scan types require root/administrator privileges.")
    print(f"{Fore.YELLOW}      All scan reports are saved to the 'scans/' directory.")

def main():
    # Check if running with necessary privileges for certain scans
    is_admin = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    if not is_admin:
        print(f"{Fore.YELLOW}[!] Warning: Some scan types require root/administrator privileges.")
        print(f"{Fore.YELLOW}    Consider running with 'sudo' for full functionality.\n")
    
    # Check for nmap
    if not check_nmap():
        print(f"{Fore.RED}[!] Error: Nmap is not installed or not in PATH")
        print(f"{Fore.YELLOW}    Please install Nmap before using NetScan.")
        sys.exit(1)
    
    # Initialize database
    init_db()
    
    # Clear screen and show banner
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Fore.GREEN}{BANNER}")
    
    scanner = NetScan()
    running = True
    
    while running:
        print(f"\n{Fore.CYAN}Select scan type:")
        print(f"{Fore.WHITE}1. Quick Scan")
        print(f"{Fore.WHITE}2. Full Port Scan")
        print(f"{Fore.WHITE}3. In-depth Scan")
        print(f"{Fore.WHITE}4. Vulnerability Scan")
        print(f"{Fore.WHITE}5. Stealth Scan")
        print(f"{Fore.WHITE}6. Web Stack Scan")
        print(f"{Fore.WHITE}7. Custom Scan")
        print(f"{Fore.WHITE}8. View Past Scans")
        print(f"{Fore.WHITE}9. Help")
        print(f"{Fore.WHITE}10. Exit")
        
        try:
            choice = input(f"\n{Fore.CYAN}Enter choice (1-10): ")
            
            if choice == '1':  # Quick Scan
                target = input(f"{Fore.CYAN}Enter target IP/hostname/range: ")
                if scanner.validate_target(target):
                    scanner.quick_scan(target)
                else:
                    print(f"{Fore.RED}[!] Invalid target format.")
            
            elif choice == '2':  # Full Port Scan
                target = input(f"{Fore.CYAN}Enter target IP/hostname/range: ")
                if scanner.validate_target(target):
                    scanner.full_port_scan(target)
                else:
                    print(f"{Fore.RED}[!] Invalid target format.")
            
            elif choice == '3':  # In-depth Scan
                target = input(f"{Fore.CYAN}Enter target IP/hostname/range: ")
                if scanner.validate_target(target):
                    scanner.indepth_scan(target)
                else:
                    print(f"{Fore.RED}[!] Invalid target format.")
            
            elif choice == '4':  # Vulnerability Scan
                target = input(f"{Fore.CYAN}Enter target IP/hostname/range: ")
                if scanner.validate_target(target):
                    scanner.vulnerability_scan(target)
                else:
                    print(f"{Fore.RED}[!] Invalid target format.")
            
            elif choice == '5':  # Stealth Scan
                target = input(f"{Fore.CYAN}Enter target IP/hostname/range: ")
                if scanner.validate_target(target):
                    scanner.stealth_scan(target)
                else:
                    print(f"{Fore.RED}[!] Invalid target format.")
            
            elif choice == '6':  # Web Stack Scan
                target = input(f"{Fore.CYAN}Enter target IP/hostname/range: ")
                if scanner.validate_target(target):
                    scanner.web_stack_scan(target)
                else:
                    print(f"{Fore.RED}[!] Invalid target format.")
            
            elif choice == '7':  # Custom Scan
                target = input(f"{Fore.CYAN}Enter target IP/hostname/range: ")
                if scanner.validate_target(target):
                    args = input(f"{Fore.CYAN}Enter custom Nmap arguments: ")
                    scanner.custom_scan(target, args)
                else:
                    print(f"{Fore.RED}[!] Invalid target format.")
            
            elif choice == '8':  # View Past Scans
                scanner.view_past_scans()
            
            elif choice == '9':  # Help
                display_help()
            
            elif choice == '10':  # Exit
                running = False
                print(f"{Fore.GREEN}[+] Thank you for using NetScan!")
            
            else:
                print(f"{Fore.RED}[!] Invalid choice. Please enter a number between 1 and 10.")
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Operation cancelled by user.")
        except Exception as e:
            print(f"{Fore.RED}[!] An error occurred: {str(e)}")
    
    # Clean up before exit
    colorama.deinit()

if __name__ == "__main__":
    # Parse command line arguments if any
    parser = argparse.ArgumentParser(description="NetScan v1.1.0 - Network Scanning Tool")
    parser.add_argument('-t', '--target', help='Target IP, hostname or range')
    parser.add_argument('-s', '--scan', type=int, choices=range(1, 8), 
                        help='Scan type (1-7): 1=Quick, 2=Full, 3=In-depth, 4=Vulnerability, 5=Stealth, 6=Web, 7=Custom')
    parser.add_argument('-a', '--args', help='Custom scan arguments (for scan type 7)')
    
    args = parser.parse_args()
    
    # Run in command-line mode if arguments provided
    if args.target and args.scan:
        scanner = NetScan()
        if not scanner.validate_target(args.target):
            print(f"{Fore.RED}[!] Invalid target format.")
            sys.exit(1)
            
        if args.scan == 1:
            scanner.quick_scan(args.target)
        elif args.scan == 2:
            scanner.full_port_scan(args.target)
        elif args.scan == 3:
            scanner.indepth_scan(args.target)
        elif args.scan == 4:
            scanner.vulnerability_scan(args.target)
        elif args.scan == 5:
            scanner.stealth_scan(args.target)
        elif args.scan == 6:
            scanner.web_stack_scan(args.target)
        elif args.scan == 7:
            if not args.args:
                print(f"{Fore.RED}[!] Custom scan requires arguments (-a/--args)")
                sys.exit(1)
            scanner.custom_scan(args.target, args.args)
    else:
        # Run in interactive mode
        main()

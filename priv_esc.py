import os
import subprocess
import platform
from datetime import datetime

# ANSI escape codes for colorful output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

def print_header(title):
    """
    Print a formatted header for each section.
    """
    print(f"\n{CYAN}=== {title} ==={RESET}")

def log_to_file(filename, content):
    """
    Save results to a log file with a timestamp.
    """
    with open(filename, "a") as file:
        file.write(f"=== {datetime.now()} ===\n")
        file.write(content + "\n\n")

def check_network_config():
    print_header("Checking Network Configuration")
    try:
        result = subprocess.run(['ifconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Network configuration:{RESET}")
        print(result.stdout)
        log_to_file("network_config.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking network configuration: {e}{RESET}")

def check_active_users():
    print_header("Checking Active Users")
    try:
        result = subprocess.run(['w'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Active users and sessions:{RESET}")
        print(result.stdout)
        log_to_file("active_users.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking active users: {e}{RESET}")

def check_installed_packages():
    print_header("Checking Installed Packages")
    try:
        result = subprocess.run(['dpkg', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Installed packages:{RESET}")
        print(result.stdout[:500] + "\n... (Output truncated)")
        log_to_file("installed_packages.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking installed packages: {e}{RESET}")

def check_open_ports():
    print_header("Checking Open Ports")
    try:
        result = subprocess.run(['netstat', '-tuln'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Open ports:{RESET}")
        print(result.stdout)
        log_to_file("open_ports.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking open ports: {e}{RESET}")

def detect_suspicious_files():
    print_header("Detecting Suspicious Files (e.g., backup files, config files)")
    try:
        patterns = ['*.bak', '*.old', '*.tmp', '*~']
        for pattern in patterns:
            print(f"{YELLOW}[*] Searching for files matching pattern: {pattern}{RESET}")
            result = subprocess.run(['find', '/', '-name', pattern, '-type', 'f', '-exec', 'ls', '-la', '{}', '+'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(result.stdout)
            log_to_file("suspicious_files.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error detecting suspicious files: {e}{RESET}")

def check_recent_logins():
    print_header("Checking Recent Login History")
    try:
        result = subprocess.run(['last'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Recent login history:{RESET}")
        print(result.stdout)
        log_to_file("login_history.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking recent login history: {e}{RESET}")

def check_services_status():
    print_header("Checking Services Status")
    try:
        result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Running services:{RESET}")
        print(result.stdout)
        log_to_file("services_status.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking services status: {e}{RESET}")

def check_unmounted_drives():
    print_header("Checking for Unmounted Drives")
    try:
        result = subprocess.run(['lsblk'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Drive information:{RESET}")
        print(result.stdout)
        log_to_file("drives_info.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking drives: {e}{RESET}")

def check_firewall_status():
    print_header("Checking Firewall Status")
    try:
        result = subprocess.run(['ufw', 'status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Firewall status:{RESET}")
        print(result.stdout)
        log_to_file("firewall_status.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking firewall status: {e}{RESET}")

def check_system_logs():
    print_header("Checking System Logs for Warnings/Errors")
    try:
        result = subprocess.run(['journalctl', '-p', '3', '-n', '50'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{YELLOW}[!] Recent warnings and errors from system logs:{RESET}")
        print(result.stdout)
        log_to_file("system_logs.log", result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking system logs: {e}{RESET}")

def main():
    print(f"{MAGENTA}Welcome to Snake Elevate++ - Enhanced Privilege Escalation Checker!{RESET}")
    print(f"{MAGENTA}============================================={RESET}")
    
    check_sudo()
    check_suid_files()
    check_kernel_version()
    check_environment_variables()
    check_writable_files()
    check_cron_jobs()
    check_shadow_file_permissions()
    check_path_variable()
    check_weak_passwords()
    check_docker_privileges()
    check_unmounted_drives()
    check_network_config()
    check_active_users()
    check_installed_packages()
    check_open_ports()
    detect_suspicious_files()
    check_recent_logins()
    check_services_status()
    check_firewall_status()
    check_system_logs()
    
    print(f"{MAGENTA}============================================={RESET}")
    print(f"{MAGENTA}Created by 0xMaximux - Pushing the boundaries of cybersecurity! 🦅{RESET}")

if __name__ == "__main__":
    main()

import os
import subprocess
import platform

# ANSI escape codes for colorful output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_header(title):
    """
    Print a formatted header for each section.
    """
    print(f"\n{CYAN}=== {title} ==={RESET}")

def check_sudo():
    """
    Check if the user has sudo privileges.
    """
    print_header("Checking Sudo Privileges")
    try:
        result = subprocess.run(['sudo', '-n', 'true'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"{GREEN}[+] User has sudo privileges.{RESET}")
            return True
        else:
            print(f"{RED}[-] User does not have sudo privileges.{RESET}")
            return False
    except Exception as e:
        print(f"{RED}[!] Error checking sudo privileges: {e}{RESET}")
        return False

def check_suid_files():
    print_header("Searching for SUID Binaries")
    try:
        result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '-exec', 'ls', '-la', '{}', '+'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error searching for SUID files: {e}{RESET}")

def check_kernel_version():
    print_header("Checking Kernel Version")
    kernel_version = platform.release()
    print(f"{GREEN}[+] Kernel version: {kernel_version}{RESET}")
    print(f"{YELLOW}[!] Check this version against known vulnerabilities (e.g., CVE databases).{RESET}")

def check_environment_variables():
    print_header("Checking Environment Variables")
    env_vars = os.environ
    for key, value in env_vars.items():
        print(f"{key}: {value}")

def check_writable_files():
    print_header("Searching for World-Writable Files")
    try:
        result = subprocess.run(['find', '/', '-perm', '-2', '-type', 'f', '-exec', 'ls', '-la', '{}', '+'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error searching for world-writable files: {e}{RESET}")

def check_cron_jobs():
    print_header("Checking Cron Jobs")
    try:
        result = subprocess.run(['cat', '/etc/crontab'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] System-wide crontab:{RESET}")
        print(result.stdout)
        
        user_cron = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Current user crontab:{RESET}")
        print(user_cron.stdout)
    except Exception as e:
        print(f"{RED}[!] Error reading cron jobs: {e}{RESET}")

def check_shadow_file_permissions(sudo_allowed):
    print_header("Checking /etc/shadow Permissions")
    try:
        cmd = ['ls', '-la', '/etc/shadow']
        if sudo_allowed:
            cmd.insert(0, 'sudo')
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking /etc/shadow permissions: {e}{RESET}")

def check_path_variable():
    print_header("Checking PATH Variable")
    path = os.environ.get('PATH', '')
    print(f"{GREEN}[+] Current PATH: {path}{RESET}")
    if '.' in path.split(':'):
        print(f"{YELLOW}[!] Warning: '.' in PATH could allow privilege escalation.{RESET}")

def check_weak_passwords(sudo_allowed):
    print_header("Checking for Weak Passwords")
    try:
        passwd_content = subprocess.run(['cat', '/etc/passwd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] /etc/passwd content:{RESET}")
        print(passwd_content.stdout)

        if sudo_allowed:
            shadow_content = subprocess.run(['sudo', 'cat', '/etc/shadow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(f"{GREEN}[+] /etc/shadow content (requires sudo):{RESET}")
            print(shadow_content.stdout)
        else:
            print(f"{YELLOW}[!] Skipping /etc/shadow as it requires sudo privileges.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error reading password files: {e}{RESET}")

def check_docker_privileges():
    print_header("Checking Docker Privileges")
    try:
        groups = subprocess.run(['groups'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if 'docker' in groups.stdout:
            print(f"{YELLOW}[+] User is in the Docker group. This could be exploited for privilege escalation.{RESET}")
        else:
            print(f"{RED}[-] User is not in the Docker group.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error checking Docker group membership: {e}{RESET}")

def check_unmounted_drives():
    print_header("Checking for Unmounted Drives")
    try:
        result = subprocess.run(['lsblk'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{GREEN}[+] Drive information:{RESET}")
        print(result.stdout)
    except Exception as e:
        print(f"{RED}[!] Error checking drives: {e}{RESET}")

def main():
    print(f"{CYAN}Welcome to Snake Elevate - Advanced Privilege Escalation Checker!{RESET}")
    print(f"{CYAN}============================================={RESET}")
    
    sudo_allowed = check_sudo()
    check_suid_files()
    check_kernel_version()
    check_environment_variables()
    check_writable_files()
    check_cron_jobs()
    check_shadow_file_permissions(sudo_allowed)
    check_path_variable()
    check_weak_passwords(sudo_allowed)
    check_docker_privileges()
    check_unmounted_drives()
    
    print(f"{CYAN}============================================={RESET}")
    print(f"{CYAN}Created by 0xMaximux{RESET}")

if __name__ == "__main__":
    main()

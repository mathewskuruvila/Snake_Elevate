import os
import subprocess
import platform
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_banner():
    """
    Print the banner with ASCII art.
    """
    banner = f"""
{Fore.RED}      ___       __      _       __      __ _
{Fore.RED}     /   | ____/ /___  (_)___  / /___  / /(_)
{Fore.RED}    / /| |/ __  / __ \/ / __ \/ / __ \/ / / 
{Fore.RED}   / ___ / /_/ / /_/ / / / / / / /_/ / / /  
{Fore.RED}  /_/  |_\__,_/\____/_/_/ /_/_/\____/_/_/   

{Fore.CYAN}========================================
{Fore.GREEN}            Snake_Elevate              
{Fore.CYAN}========================================
    """
    print(banner)

def print_section(title):
    """
    Print a section header with formatting.
    """
    print(f"\n{Fore.YELLOW}[*] {title}")
    print(f"{Fore.CYAN}{'-' * len(title)}")

def check_sudo():
    print_section("Checking Sudo Privileges")
    try:
        result = subprocess.run(['sudo', '-n', 'true'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"{Fore.GREEN}[+] User has sudo privileges.")
        else:
            print(f"{Fore.RED}[-] User does not have sudo privileges.")
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking sudo privileges: {e}")

def check_suid_files():
    print_section("Searching for SUID Binaries")
    try:
        result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '-exec', 'ls', '-la', '{}', '+'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Error searching for SUID files: {e}")

def check_kernel_version():
    print_section("Checking Kernel Version")
    kernel_version = platform.release()
    print(f"{Fore.GREEN}[+] Kernel version: {kernel_version}")
    print(f"{Fore.YELLOW}[*] Check this version against known vulnerabilities (e.g., CVE databases).")

def check_environment_variables():
    print_section("Checking Environment Variables")
    env_vars = os.environ
    for key, value in env_vars.items():
        print(f"{Fore.BLUE}{key}: {value}")

def check_writable_files():
    print_section("Searching for World-Writable Files")
    try:
        result = subprocess.run(['find', '/', '-perm', '-2', '-type', 'f', '-exec', 'ls', '-la', '{}', '+'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Error searching for world-writable files: {e}")

def check_cron_jobs():
    print_section("Checking Cron Jobs")
    try:
        result = subprocess.run(['cat', '/etc/crontab'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{Fore.GREEN}[+] System-wide crontab:")
        print(result.stdout)

        user_cron = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{Fore.GREEN}[+] Current user crontab:")
        print(user_cron.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading cron jobs: {e}")

def check_shadow_file_permissions():
    print_section("Checking /etc/shadow Permissions")
    try:
        result = subprocess.run(['ls', '-la', '/etc/shadow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking /etc/shadow permissions: {e}")

def check_path_variable():
    print_section("Checking PATH Variable")
    path = os.environ.get('PATH', '')
    print(f"{Fore.GREEN}[+] Current PATH: {path}")
    if '.' in path.split(':'):
        print(f"{Fore.RED}[!] Warning: '.' in PATH could allow privilege escalation.")

def check_weak_passwords():
    print_section("Checking for Weak Passwords")
    try:
        passwd_content = subprocess.run(['cat', '/etc/passwd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{Fore.GREEN}[+] /etc/passwd content:")
        print(passwd_content.stdout)

        shadow_content = subprocess.run(['sudo', 'cat', '/etc/shadow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{Fore.GREEN}[+] /etc/shadow content (requires sudo):")
        print(shadow_content.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading password files: {e}")

def check_docker_privileges():
    print_section("Checking Docker Privileges")
    try:
        groups = subprocess.run(['groups'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if 'docker' in groups.stdout:
            print(f"{Fore.GREEN}[+] User is in the Docker group. This could be exploited for privilege escalation.")
        else:
            print(f"{Fore.RED}[-] User is not in the Docker group.")
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking Docker group membership: {e}")

def check_unmounted_drives():
    print_section("Checking for Unmounted Drives")
    try:
        result = subprocess.run(['lsblk'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f"{Fore.GREEN}[+] Drive information:")
        print(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking drives: {e}")

def main():
    print_banner()
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
    print(f"\n{Fore.YELLOW}[*] Remember to use findings responsibly and within the scope of your engagement.")

if __name__ == "__main__":
    main()

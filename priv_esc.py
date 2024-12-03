import os
import subprocess
import platform

def check_sudo():
    """
    Check if the current user has sudo privileges.
    """
    try:
        result = subprocess.run(['sudo', '-n', 'true'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print("[+] User has sudo privileges.")
        else:
            print("[-] User does not have sudo privileges.")
    except Exception as e:
        print(f"[!] Error checking sudo privileges: {e}")

def check_suid_files():
    """
    Search for SUID binaries that could be exploited.
    """
    print("[*] Searching for SUID binaries...")
    try:
        result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '-exec', 'ls', '-la', '{}', '+'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[!] Error searching for SUID files: {e}")

def check_kernel_version():
    """
    Get the system's kernel version and check for vulnerabilities.
    """
    print("[*] Checking kernel version...")
    kernel_version = platform.release()
    print(f"[+] Kernel version: {kernel_version}")
    print("[*] Check this version against known vulnerabilities (e.g., CVE databases).")

def check_environment_variables():
    """
    Look for potentially dangerous environment variables.
    """
    print("[*] Checking environment variables...")
    env_vars = os.environ
    for key, value in env_vars.items():
        print(f"{key}: {value}")

def check_writable_files():
    """
    Find world-writable files that could be abused.
    """
    print("[*] Searching for world-writable files...")
    try:
        result = subprocess.run(['find', '/', '-perm', '-2', '-type', 'f', '-exec', 'ls', '-la', '{}', '+'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[!] Error searching for world-writable files: {e}")

def check_cron_jobs():
    """
    List all cron jobs for the current and all users.
    """
    print("[*] Checking cron jobs...")
    try:
        result = subprocess.run(['cat', '/etc/crontab'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("[+] System-wide crontab:")
        print(result.stdout)
        
        user_cron = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("[+] Current user crontab:")
        print(user_cron.stdout)
    except Exception as e:
        print(f"[!] Error reading cron jobs: {e}")

def check_shadow_file_permissions():
    """
    Check permissions on /etc/shadow file to identify potential misconfigurations.
    """
    print("[*] Checking /etc/shadow permissions...")
    try:
        result = subprocess.run(['ls', '-la', '/etc/shadow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[!] Error checking /etc/shadow permissions: {e}")

def check_path_variable():
    """
    Look for dangerous entries in the PATH variable.
    """
    print("[*] Checking PATH variable...")
    path = os.environ.get('PATH', '')
    print(f"[+] Current PATH: {path}")
    if '.' in path.split(':'):
        print("[!] Warning: '.' in PATH could allow privilege escalation.")

def check_weak_passwords():
    """
    Search for weak or default passwords in system accounts.
    """
    print("[*] Checking for weak passwords in /etc/passwd and /etc/shadow...")
    try:
        passwd_content = subprocess.run(['cat', '/etc/passwd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("[+] /etc/passwd content:")
        print(passwd_content.stdout)

        shadow_content = subprocess.run(['sudo', 'cat', '/etc/shadow'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("[+] /etc/shadow content (requires sudo):")
        print(shadow_content.stdout)
    except Exception as e:
        print(f"[!] Error reading password files: {e}")

def check_docker_privileges():
    """
    Check if the user is in the Docker group, which can lead to privilege escalation.
    """
    print("[*] Checking Docker privileges...")
    try:
        groups = subprocess.run(['groups'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if 'docker' in groups.stdout:
            print("[+] User is in the Docker group. This could be exploited for privilege escalation.")
        else:
            print("[-] User is not in the Docker group.")
    except Exception as e:
        print(f"[!] Error checking Docker group membership: {e}")

def check_unmounted_drives():
    """
    Check for unmounted drives or partitions that could contain sensitive data.
    """
    print("[*] Checking for unmounted drives...")
    try:
        result = subprocess.run(['lsblk'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("[+] Drive information:")
        print(result.stdout)
    except Exception as e:
        print(f"[!] Error checking drives: {e}")

def main():
    print("=== Enhanced Privilege Escalation Checker ===")
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
    print("[*] Remember to use findings responsibly and within the scope of your engagement.")

if __name__ == "__main__":
    main()

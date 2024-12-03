
# Snake_Elevate 🐍 - Privilege Escalation Checker

**Snake_Elevate** is a Python-based tool for ethical hacking and security auditing. It automates the detection of misconfigurations, vulnerabilities, and potential privilege escalation paths in Linux environments. Perfect for penetration testers, security researchers, and system administrators aiming to secure their systems. 🚀

---

## Features

- **🛠 SUID Binary Analysis**: Detect exploitable SUID binaries.
- **🕒 Cron Job Review**: Find vulnerable system or user cron jobs.
- **🔗 PATH Variable Inspection**: Highlight dangerous entries in the PATH variable.
- **🔓 World-Writable Files**: Identify files with overly permissive permissions.
- **🐳 Docker Privileges Check**: Warn about risky Docker group memberships.
- **🧑‍💻 Environment Variable Analysis**: Reveal sensitive or exploitable environment variables.
- **🐧 Kernel Vulnerability Check**: Check the system's kernel version for known issues.
- **🔐 Shadow File Permissions**: Verify the security of `/etc/shadow` file permissions.
- **🔒 Weak Password Detection**: Look for default or weak passwords.
- **📦 Unmounted Drives Check**: Identify potentially sensitive data on unmounted drives.

---

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/mathewskuruvila/Snake_Elevate.git
   cd Snake_Elevate
   ```

2. Install required dependencies:

   The tool uses standard Python libraries; no additional installations are required. Ensure Python 3.6+ is installed.

3. Set execution permissions for the script:

   ```bash
   chmod +x priv_esc.py
   ```

---

## Usage

1. Run the tool with Python:

   ```bash
   python3 priv_esc.py
   ```

   > **Note:** Some checks require `sudo` privileges for full functionality.

2. The tool will display detailed findings for each check.

3. Use the findings responsibly and only within authorized engagements.

---

## Functionality Overview

The tool includes the following modules:

- **`check_sudo`**: Verifies if the user has `sudo` privileges.
- **`check_suid_files`**: Identifies SUID binaries with potential exploitation risks.
- **`check_kernel_version`**: Displays the kernel version for vulnerability checks.
- **`check_environment_variables`**: Examines environment variables for security concerns.
- **`check_writable_files`**: Finds world-writable files.
- **`check_cron_jobs`**: Lists all cron jobs for the system and the current user.
- **`check_shadow_file_permissions`**: Checks `/etc/shadow` file permissions for misconfigurations.
- **`check_path_variable`**: Inspects the `PATH` variable for risky entries.
- **`check_weak_passwords`**: Looks for weak or default passwords in system accounts.
- **`check_docker_privileges`**: Checks user membership in the `docker` group.
- **`check_unmounted_drives`**: Lists unmounted drives that might contain sensitive data.

---

## Contribution

Contributions are welcome! If you have ideas for improvements or find bugs, feel free to open an issue or submit a pull request.

---

## Disclaimer

This tool is designed for educational and authorized security testing purposes only. Unauthorized use of this tool is prohibited. Use responsibly.


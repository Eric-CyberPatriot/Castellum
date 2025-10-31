#!/bin/bash

# --- UBUNTU HARDENING SCRIPT FOR CYBERPATRIOT ---

# Exit immediately if a command exits with a non-zero status.
# Treat unset variables as an error when substituting.
# Pipelines return the exit status of the last command to exit with a non-zero status,
# or zero if all commands in the pipeline exit successfully.
set -eo pipefail

LOG_FILE="/var/log/cyberpatriot_hardening_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "--- CyberPatriot Ubuntu Hardening Script ---"
echo "Starting system hardening at $(date)"
echo "Log file: ${LOG_FILE}"

# --- CHECK FOR ROOT PRIVILEGES ---
if [[ "${EUID}" -ne 0 ]]; then
  echo " (!) This script must be run as root. Exiting."
  exit 1
fi

# --- HELPER FUNCTIONS ---
add_or_update_line() {
  local file="$1"
  local line_content="$2"
  local pattern_to_grep="$3" # Unique part of the line to check for existence

  if ! grep -qF -- "$pattern_to_grep" "$file"; then
    echo " (+) Adding to ${file}: ${line_content}"
    echo "${line_content}" >> "${file}"
  else
    echo " (*) Line containing '${pattern_to_grep}' already exists in ${file}."
    # If you need to update, you'd use sed here. For now, we just ensure it's present.
    # Example: sudo sed -i "/${pattern_to_grep}/c\\${line_content}" "${file}"
  fi
}

add_or_update_sysctl() {
  local key="$1"
  local value="$2"
  local config_file="/etc/sysctl.conf"

  echo " (>) Configuring sysctl: ${key} = ${value}"
  # Remove any existing line with the key, then add the new one
  # This handles cases where the line might be commented out or have a different value
  if grep -qE "^\s*#?\s*${key}\s*=" "${config_file}"; then
    # If line exists (commented or not), replace it
    sed -i -e "s|^\s*#*\s*${key}\s*=.*|${key} = ${value}|g" "${config_file}"
  else
    # If line does not exist, append it
    echo "${key} = ${value}" >> "${config_file}"
  fi
}


# --- 1. SYSTEM UPDATES & ESSENTIAL TOOLS ---
echo ""
echo "--- SECTION 1: SYSTEM UPDATES & ESSENTIAL TOOLS ---"
echo " (>) Updating package lists..."
apt-get update -y

echo " (>) Upgrading installed packages..."
apt-get upgrade -y
apt-get dist-upgrade -y
apt-get autoremove -y
apt-get autoclean -y

echo " (>) Installing essential security tools..."
apt-get install -y ufw clamav clamav-daemon freshclam auditd audispd-plugins \
                   debsums libpam-pwquality libpam-apparmor apparmor-utils \
                   aide aide-common unattended-upgrades fail2ban openscap-scanner lynis

# --- 2. ANTIVIRUS (CLAMAV) ---
echo ""
echo "--- SECTION 2: ANTIVIRUS (CLAMAV) ---"
echo " (>) Updating ClamAV virus definitions..."
freshclam

echo " (>) Enabling and starting ClamAV daemon..."
systemctl enable clamav-daemon
systemctl start clamav-daemon
echo " (i) Consider running a full system scan with 'clamscan -r /' (can be time-consuming)."

# --- 3. FILE INTEGRITY CHECKER (AIDE) ---
echo ""
echo "--- SECTION 3: FILE INTEGRITY CHECKER (AIDE) ---"
echo " (>) Initializing AIDE database (this may take a while)..."
if [ ! -f /var/lib/aide/aide.db.gz ]; then
    aideinit
    # The new database is typically at /var/lib/aide/aide.db.new.gz or similar
    # The aideinit script should handle moving it correctly in modern versions
    # For older versions, you might need:
    # if [ -f /var/lib/aide/aide.db.new.gz ]; then
    #   mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    # fi
    echo " (i) AIDE database initialized. Run 'aide.wrapper --check' periodically."
else
    echo " (*) AIDE database already exists."
fi
# Ensure cron job for AIDE is set up (usually done by package install)
# Example: check /etc/cron.daily/aide

# --- 4. AUDITING (AUDITD) ---
echo ""
echo "--- SECTION 4: AUDITING (AUDITD) ---"
echo " (>) Configuring auditd..."
if [ -f /etc/audit/auditd.conf ]; then
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
    # Using your provided robust configuration
    cat > /etc/audit/auditd.conf <<EOF
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
max_log_file = 8
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
krb5_key_file = /etc/audit/audit.key
distribute_network = no
EOF
    echo " (i) Auditd configured. Setting rules..."
    # Basic rules - CIS Benchmarks provide more comprehensive sets
    # Consider using rules from /usr/share/doc/auditd-plugins/examples/rules/ or CIS
    cat > /etc/audit/rules.d/99-cyberpatriot.rules <<EOF
# CIS Level 1 - Auditd Rules (Example subset)
# Record events that modify date and time
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Record events that modify user/group information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Record events that modify system's network environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Record events that modify the system's mandatory access controls
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Ensure auditd cannot be stopped or configuration changed without logging
-w /etc/audit/auditd.conf -p wa -k auditconfig
-w /etc/audit/rules.d/ -p wa -k auditrules

# Collect login and logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins # Older systems

# Collect session initiation information
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session # On some systems wtmp is /var/log/wtmp
-w /var/log/btmp -p wa -k session # On some systems btmp is /var/log/btmp

# Collect discretionary access control permission modification events
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

# Collect successful and unsuccessful attempts to use the mount system call
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts

# Collect file deletion events by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=unset -k delete

# Make the audit configuration immutable (until reboot)
-e 2
EOF
    augenrules --load
    systemctl restart auditd
else
    echo " (!) /etc/audit/auditd.conf not found. Skipping auditd configuration."
fi
systemctl enable auditd
systemctl start auditd

# --- 5. APPLICATION ARMOR (APPARMOR) ---
echo ""
echo "--- SECTION 5: APPLICATION ARMOR (APPARMOR) ---"
echo " (>) Ensuring AppArmor is enabled and enforcing profiles..."
systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/*
echo " (i) AppArmor status: $(apparmor_status)"

# --- 6. UNATTENDED UPGRADES ---
echo ""
echo "--- SECTION 6: UNATTENDED UPGRADES ---"
echo " (>) Configuring unattended-upgrades for automatic security updates..."
dpkg-reconfigure --priority=low unattended-upgrades -f noninteractive
# Verify config in /etc/apt/apt.conf.d/50unattended-upgrades and /etc/apt/apt.conf.d/20auto-upgrades
# Ensure these are set in /etc/apt/apt.conf.d/20auto-upgrades:
# APT::Periodic::Update-Package-Lists "1";
# APT::Periodic::Unattended-Upgrade "1";
if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/20auto-upgrades
    sed -i 's/APT::Periodic::Unattended-Upgrade "0";/APT::Periodic::Unattended-Upgrade "1";/' /etc/apt/apt.conf.d/20auto-upgrades
    echo " (i) /etc/apt/apt.conf.d/20auto-upgrades updated."
else
    echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
    echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
    echo " (i) /etc/apt/apt.conf.d/20auto-upgrades created and configured."
fi

# --- 7. FIREWALL (UFW) ---
echo ""
echo "--- SECTION 7: FIREWALL (UFW) ---"
echo " (>) Configuring Uncomplicated Firewall (UFW)..."
ufw --force reset # Reset to defaults first
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh # Crucial: Allow SSH
ufw allow http  # If web server needed
ufw allow https # If web server needed
# ufw allow 53/tcp # DNS if running a DNS server
# ufw allow 53/udp # DNS if running a DNS server
# Add other necessary services before enabling
echo " (i) UFW configured with default deny incoming, allow outgoing. SSH allowed."
echo " (i) Add other rules as needed (e.g., 'ufw allow 80/tcp' for HTTP)."
ufw --force enable
echo " (i) UFW enabled. Status:"
ufw status verbose

# --- 8. REMOVE UNNECESSARY/INSECURE SERVICES & PACKAGES ---
echo ""
echo "--- SECTION 8: REMOVE UNNECESSARY/INSECURE SERVICES & PACKAGES ---"
# Services often found in CyberPatriot
INSECURE_SERVICES=(
  "avahi-daemon"    # Zeroconf networking
  "cups"            # Printing service (disable if not a print server)
  "rpcbind"         # RPC portmapper (often not needed, security risk)
  "telnetd"         # Telnet server (use SSH)
  "vsftpd"          # FTP server (use SFTP/SCP if needed, otherwise remove)
  "apache2"         # Web server (remove if not needed)
  "nginx"           # Web server (remove if not needed)
  "samba"           # SMB/CIFS file sharing (remove if not needed)
  "nfs-kernel-server" # NFS server (remove if not needed)
  "dovecot-core"    # IMAP/POP3 server
  "postfix"         # Mail server
  "isc-dhcp-server" # DHCP Server
  "slapd"           # LDAP Server
  "snmpd"           # SNMP Daemon
  "bind9"           # DNS Server
)
# Packages often found in CyberPatriot
INSECURE_PACKAGES=(
  "telnet"          # Telnet client (often scored)
  "rsh-client" "rsh-redone-client" "rsh-server"
  "talk" "talkd"
  "nis" "ypbind"
  "xinetd"
  "tftpd" "tftp-hpa"
  "openssh-server" # Only remove if SSH is absolutely not needed (rare for CP)
                   # But often you need to secure it, not remove it.
  "john" "nmap" "hydra" "wireshark" # Hacking tools - often planted
)

echo " (>) Disabling and/or removing unnecessary/insecure services..."
for service_name in "${INSECURE_SERVICES[@]}"; do
  if systemctl list-unit-files --type=service | grep -q "^${service_name}.service"; then
    echo " (>) Disabling and stopping ${service_name}..."
    systemctl stop "${service_name}" || true # Ignore error if already stopped
    systemctl disable "${service_name}" || true # Ignore error if not enabled
    # Optionally, remove the package too
    # if dpkg -s "${service_name}" &> /dev/null; then
    #   echo " (>) Removing package for ${service_name}..."
    #   apt-get purge -y "${service_name}"
    # fi
  else
    echo " (*) Service ${service_name} not found or not installed."
  fi
done

echo " (>) Removing unnecessary/insecure packages..."
for pkg_name in "${INSECURE_PACKAGES[@]}"; do
  if dpkg -s "${pkg_name}" &> /dev/null; then
    echo " (>) Removing package ${pkg_name}..."
    apt-get purge -y "${pkg_name}"
  else
    echo " (*) Package ${pkg_name} not installed."
  fi
done
apt-get autoremove -y # Clean up dependencies

# --- 9. SECURE SSH CONFIGURATION ---
echo ""
echo "--- SECTION 9: SECURE SSH CONFIGURATION ---"
SSH_CONFIG="/etc/ssh/sshd_config"
if [ -f "${SSH_CONFIG}" ]; then
  echo " (>) Securing ${SSH_CONFIG}..."
  cp "${SSH_CONFIG}" "${SSH_CONFIG}.bak"

  # Ensure these settings are present and set correctly
  declare -A ssh_settings=(
    ["LogLevel"]="VERBOSE"
    ["PermitRootLogin"]="no"
    ["StrictModes"]="yes"
    ["MaxAuthTries"]="3"
    ["MaxSessions"]="2" # Limit concurrent sessions per connection
    ["PasswordAuthentication"]="yes" # Often required for CP, as keys aren't pre-shared
    ["PermitEmptyPasswords"]="no"
    ["ChallengeResponseAuthentication"]="no"
    ["UsePAM"]="yes"
    ["X11Forwarding"]="no"
    ["PrintMotd"]="no" # Or yes, if you customize MOTD
    ["PrintLastLog"]="yes"
    ["TCPKeepAlive"]="yes"
    ["ClientAliveInterval"]="300" # Send null packet every 5 mins
    ["ClientAliveCountMax"]="2"  # Disconnect after 2 unanswered (total 10 mins)
    ["AllowAgentForwarding"]="no"
    ["AllowTcpForwarding"]="no"
    ["PermitTunnel"]="no"
    ["Banner"]="/etc/issue.net" # Make sure /etc/issue.net has an appropriate banner
    ["Protocol"]="2" # Already default but good to enforce
    ["HostbasedAuthentication"]="no"
    ["IgnoreRhosts"]="yes"
    ["UsePrivilegeSeparation"]="sandbox" # Modern default, was 'yes'
    ["Ciphers"]="aes256-ctr,aes192-ctr,aes128-ctr" # Strong ciphers
    ["MACs"]="hmac-sha2-512,hmac-sha2-256" # Strong MACs
    ["KexAlgorithms"]="diffie-hellman-group-exchange-sha256" # Strong Key Exchange
  )

  for key in "${!ssh_settings[@]}"; do
    value="${ssh_settings[$key]}"
    if grep -qE "^\s*#?\s*${key}\s+" "${SSH_CONFIG}"; then
      sed -i -e "s|^\s*#*\s*${key}\s+.*|${key} ${value}|g" "${SSH_CONFIG}"
    else
      echo "${key} ${value}" >> "${SSH_CONFIG}"
    fi
  done

  # Ensure /etc/issue.net exists for the banner
  if [ ! -f /etc/issue.net ]; then
    echo "Authorized uses only. All activity may be monitored and recorded." > /etc/issue.net
  fi

  echo " (i) Testing SSH configuration..."
  if sshd -t; then
    echo " (i) SSH configuration test successful. Restarting SSH service."
    systemctl restart sshd
  else
    echo " (!) SSH configuration test failed. Check ${SSH_CONFIG} and ${SSH_CONFIG}.bak"
    echo " (!) SSH service NOT restarted."
  fi
else
  echo " (!) ${SSH_CONFIG} not found. Skipping SSH hardening."
fi

# --- 10. FAIL2BAN ---
echo ""
echo "--- SECTION 10: FAIL2BAN ---"
echo " (>) Configuring Fail2Ban..."
JAIL_LOCAL="/etc/fail2ban/jail.local"
if [ ! -f "${JAIL_LOCAL}" ]; then
  cp /etc/fail2ban/jail.conf "${JAIL_LOCAL}"
  echo " (i) Copied jail.conf to jail.local."
fi

# Customize jail.local for SSH
# Ensure [sshd] section exists or add it
if ! grep -q "\[sshd\]" "${JAIL_LOCAL}"; then
  echo -e "\n[sshd]\nenabled = true\nport = ssh\nlogpath = %(sshd_log)s\nbackend = %(sshd_backend)s" >> "${JAIL_LOCAL}"
fi
sed -i '/^\[sshd\]/,/^\[/ s/^enabled\s*=\s*false/enabled = true/' "${JAIL_LOCAL}" # Ensure enabled under [sshd]
sed -i 's/bantime\s*=\s*10m/bantime  = 1h/g' "${JAIL_LOCAL}" # Global or under [DEFAULT]
sed -i 's/maxretry\s*=\s*5/maxretry = 3/g' "${JAIL_LOCAL}"  # Global or under [DEFAULT]
sed -i 's/findtime\s*=\s*10m/findtime = 30m/g' "${JAIL_LOCAL}" # Global or under [DEFAULT]

systemctl enable fail2ban
systemctl start fail2ban
echo " (i) Fail2Ban enabled and started. Status:"
fail2ban-client status sshd || echo " (i) sshd jail not active or fail2ban-client issue."

# --- 11. USER ACCOUNTS & PASSWORD POLICIES ---
echo ""
echo "--- SECTION 11: USER ACCOUNTS & PASSWORD POLICIES ---"

echo " (>) Locking root account..."
passwd -l root
usermod -L root # Alternative way to lock

echo " (>) Configuring password policies in /etc/login.defs..."
LOGIN_DEFS="/etc/login.defs"
cp "${LOGIN_DEFS}" "${LOGIN_DEFS}.bak"
sed -i 's/^\(PASS_MAX_DAYS\s*\)[0-9]*/\190/' "${LOGIN_DEFS}"
sed -i 's/^\(PASS_MIN_DAYS\s*\)[0-9]*/\17/' "${LOGIN_DEFS}"
sed -i 's/^\(PASS_WARN_AGE\s*\)[0-9]*/\114/' "${LOGIN_DEFS}"
sed -i 's/^\(FAILLOG_ENAB\s*\).*/\1yes/' "${LOGIN_DEFS}"
sed -i 's/^\(LOG_UNKFAIL_ENAB\s*\).*/\1yes/' "${LOGIN_DEFS}"
# Ensure login retries are set (handled by pam_faillock now)
# sed -i 's/^\(LOGIN_RETRIES\s*\)[0-9]*/\13/' "${LOGIN_DEFS}"

echo " (>) Configuring PAM for password quality and account lockout..."
# Password Quality
PWQUALITY_CONF="/etc/security/pwquality.conf"
cp "${PWQUALITY_CONF}" "${PWQUALITY_CONF}.bak" || true # Bak if exists
cat > "${PWQUALITY_CONF}" <<EOF
# Settings for libpwquality
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 3
retry = 3
enforce_for_root
EOF
echo " (i) Password quality set in ${PWQUALITY_CONF}."

# PAM common-password configuration
COMMON_PASSWORD="/etc/pam.d/common-password"
cp "${COMMON_PASSWORD}" "${COMMON_PASSWORD}.bak"
# Ensure pam_pwquality.so is present and configured BEFORE pam_unix.so
if ! grep -q "pam_pwquality.so" "${COMMON_PASSWORD}"; then
  sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3' "${COMMON_PASSWORD}"
else
  sed -i 's/pam_pwquality.so.*/pam_pwquality.so retry=3/' "${COMMON_PASSWORD}"
fi
# Add remember and sha512 to pam_unix.so
sed -i 's/\(pam_unix.so.*\)\(md5\|sha256\|bigcrypt\)/\1sha512 remember=5/' "${COMMON_PASSWORD}"
# If no hashing algorithm specified, add sha512 and remember
if ! grep -q "remember=" "${COMMON_PASSWORD}"; then
    sed -i 's/\(pam_unix.so.*\)/\1 sha512 remember=5/' "${COMMON_PASSWORD}"
fi
# Ensure `obscure` is used with pam_unix.so
if ! grep -q "obscure" "${COMMON_PASSWORD}"; then
    sed -i 's/\(pam_unix.so.*\)/\1 obscure/' "${COMMON_PASSWORD}"
fi

echo " (>) Configuring PAM for account lockout (pam_faillock)..."
# This needs to be done carefully. Add before pam_unix.so in auth section
# and before pam_permit.so in account section.
# /etc/pam.d/common-auth

# /etc/pam.d/common-account
COMMON_ACCOUNT="/etc/pam.d/common-account"
cp "${COMMON_ACCOUNT}" "${COMMON_ACCOUNT}.bak"
# Add faillock at the beginning
if ! grep -q "pam_faillock.so" "${COMMON_ACCOUNT}"; then
  sed -i '1i account     required      pam_faillock.so' "${COMMON_ACCOUNT}"
fi

echo " (!!!) MANUAL USER REVIEW REQUIRED (!!!)"
echo " (i) Review /etc/passwd for unauthorized users."
echo "     Command: cat /etc/passwd"
echo " (i) Review /etc/shadow for accounts with no passwords or suspicious entries (look for '::')."
echo "     Command: sudo cat /etc/shadow"
echo " (i) Review /etc/group for unauthorized users in privileged groups (root, sudo, adm)."
echo "     Command: cat /etc/group | grep -E 'root|sudo|adm'"
echo " (i) List users with UID 0 (should only be root):"
echo "     awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd"
echo " (i) List users with sudo privileges:"
echo "     getent group sudo"
echo " (i) Check home directories for suspicious files/ownership."
echo "     ls -la /home"
echo " (i) Remove unauthorized users with: sudo userdel -r <username>"
echo " (i) Change default/weak passwords for ALL users: sudo passwd <username>"
read -r -p "Press Enter to continue after reviewing users..."

# --- 12. LIGHTDM (LOGIN SCREEN) CONFIGURATION ---
echo ""
echo "--- SECTION 12: LIGHTDM (LOGIN SCREEN) CONFIGURATION ---"
LIGHTDM_CONF_PATHS=(
  "/etc/lightdm/lightdm.conf"
  "/etc/lightdm/lightdm.conf.d/50-ubuntu.conf"
  "/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
  "/usr/share/lightdm/lightdm.conf.d/60-lightdm-gtk-greeter.conf" # Common for GTK greeter
)
LIGHTDM_SETTINGS=(
  "allow-guest=false"
  "greeter-hide-users=true"
  "greeter-show-manual-login=true"
  "autologin-user=" # Set to empty to disable autologin
  "autologin-guest=false"
)
LIGHTDM_CONF_FOUND=false
for conf_file in "${LIGHTDM_CONF_PATHS[@]}"; do
  if [ -f "${conf_file}" ]; then
    echo " (>) Configuring ${conf_file}..."
    cp "${conf_file}" "${conf_file}.bak"
    # Ensure [SeatDefaults] or [Seat:*] section exists
    if ! grep -qE "\[SeatDefaults\]|\[Seat:\*\]" "${conf_file}"; then
        echo -e "\n[SeatDefaults]" >> "${conf_file}"
    fi
    for setting in "${LIGHTDM_SETTINGS[@]}"; do
      key="${setting%%=*}"
      value="${setting#*=}"
      # Check if key exists in any Seat section
      if grep -qE "^${key}=" "${conf_file}"; then
        sed -i -E "s/^(${key}=).*/\1${value}/" "${conf_file}"
      else
        # Add under [SeatDefaults] or the first Seat section found
        sed -i "/\[SeatDefaults\]/a ${key}=${value}" "${conf_file}" || \
        sed -i "/\[Seat:\*\]/a ${key}=${value}" "${conf_file}"
      fi
    done
    LIGHTDM_CONF_FOUND=true
    #break # Apply to first found, or let it apply to all if needed
  fi
done
if [ "$LIGHTDM_CONF_FOUND" = false ]; then
  echo " (!) No standard LightDM configuration file found. Manual check may be needed."
fi

# --- 13. KERNEL PARAMETERS (SYSCTL) ---
echo ""
echo "--- SECTION 13: KERNEL PARAMETERS (SYSCTL) ---"
echo " (>) Configuring kernel parameters in /etc/sysctl.conf..."
cp /etc/sysctl.conf /etc/sysctl.conf.bak

# Network Parameters
add_or_update_sysctl "net.ipv4.ip_forward" "0"                      # Disable IP forwarding
add_or_update_sysctl "net.ipv4.conf.all.send_redirects" "0"        # Disable sending ICMP redirects
add_or_update_sysctl "net.ipv4.conf.default.send_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.accept_redirects" "0"      # Disable accepting ICMP redirects (host)
add_or_update_sysctl "net.ipv4.conf.default.accept_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.secure_redirects" "0"      # Disable accepting secure ICMP redirects
add_or_update_sysctl "net.ipv4.conf.default.secure_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.accept_source_route" "0"   # Disable accepting source-routed packets
add_or_update_sysctl "net.ipv4.conf.default.accept_source_route" "0"
add_or_update_sysctl "net.ipv4.conf.all.log_martians" "1"          # Log packets with impossible addresses
add_or_update_sysctl "net.ipv4.conf.default.log_martians" "1"
add_or_update_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"   # Ignore ICMP broadcast requests
add_or_update_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1" # Ignore bogus ICMP error responses
add_or_update_sysctl "net.ipv4.conf.all.rp_filter" "1"             # Enable reverse path filtering
add_or_update_sysctl "net.ipv4.conf.default.rp_filter" "1"
add_or_update_sysctl "net.ipv4.tcp_syncookies" "1"                 # Enable SYN cookies (DoS protection)
add_or_update_sysctl "net.ipv4.tcp_max_syn_backlog" "2048"
add_or_update_sysctl "net.ipv4.tcp_synack_retries" "2"
add_or_update_sysctl "net.ipv4.tcp_syn_retries" "5"

# IPv6 (Disable if not needed - common for CP, but verify impact)
echo " (??) Do you want to disable IPv6? (yes/no) [Default: yes, can break things if IPv6 is used]"
read -r disable_ipv6_answer
disable_ipv6_answer=${disable_ipv6_answer:-yes}
if [[ "$disable_ipv6_answer" == "yes" || "$disable_ipv6_answer" == "y" ]]; then
  echo " (>) Disabling IPv6..."
  add_or_update_sysctl "net.ipv6.conf.all.disable_ipv6" "1"
  add_or_update_sysctl "net.ipv6.conf.default.disable_ipv6" "1"
  add_or_update_sysctl "net.ipv6.conf.lo.disable_ipv6" "1"
else
  echo " (*) IPv6 not disabled."
  # If keeping IPv6, secure it:
  # add_or_update_sysctl "net.ipv6.conf.all.accept_ra" "0"
  # add_or_update_sysctl "net.ipv6.conf.default.accept_ra" "0"
  # add_or_update_sysctl "net.ipv6.conf.all.accept_redirects" "0"
  # add_or_update_sysctl "net.ipv6.conf.default.accept_redirects" "0"
fi

# Other Security Parameters
add_or_update_sysctl "kernel.randomize_va_space" "2" # ASLR
add_or_update_sysctl "fs.suid_dumpable" "0"         # Disable SUID_DUMPABLE

echo " (>) Applying sysctl changes..."
sysctl -p /etc/sysctl.conf
echo " (i) Kernel parameters applied."

# --- 14. SECURE SHARED MEMORY & FILE PERMISSIONS ---
echo ""
echo "--- SECTION 14: SECURE SHARED MEMORY & FILE PERMISSIONS ---"
echo " (>) Securing /dev/shm (shared memory)..."
# Ensure this line is in /etc/fstab if not already present
FSTAB_SHM_LINE="tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec 0 0"
if ! grep -q "tmpfs /dev/shm" /etc/fstab; then
  echo "${FSTAB_SHM_LINE}" >> /etc/fstab
  echo " (i) Added /dev/shm configuration to /etc/fstab. A REBOOT or 'mount -o remount /dev/shm' is needed to apply."
elif ! grep -q "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec" /etc/fstab; then
  sed -i '/tmpfs \/dev\/shm/c\'"${FSTAB_SHM_LINE}" /etc/fstab
  echo " (i) Updated /dev/shm configuration in /etc/fstab. A REBOOT or 'mount -o remount /dev/shm' is needed to apply."
else
  echo " (*) /dev/shm already correctly configured in /etc/fstab."
fi
# Attempt to remount immediately
mount -o remount,nosuid,nodev,noexec /dev/shm || echo " (!) Could not remount /dev/shm. Reboot may be required."


echo " (>) Securing /tmp and /var/tmp (More advanced, may require partition changes or bind mounts)..."
echo " (i) Consider creating separate partitions for /tmp and /var/tmp and mounting them with noexec,nosuid,nodev."
echo " (i) Alternatively, use bind mounts or tmpfs for /tmp."
# Example for tmpfs /tmp (add to /etc/fstab, may need size adjustment):
# FSTAB_TMP_LINE="tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,size=2G 0 0"
# if ! grep -q "tmpfs /tmp" /etc/fstab; then
#   echo "${FSTAB_TMP_LINE}" >> /etc/fstab
#   echo " (i) Added tmpfs /tmp configuration to /etc/fstab. REBOOT REQUIRED."
# fi

echo " (>) Setting restrictive file permissions for critical files..."
chmod 600 /boot/grub/grub.cfg # Check path for your system
chmod 644 /etc/passwd
chown root:root /etc/shadow
chmod 640 /etc/shadow # More common approach allowing group 'shadow' to read
chgrp shadow /etc/shadow || true # Group shadow may not exist initially, create it if needed.
chmod 644 /etc/group
chmod 640 /etc/gshadow
chgrp shadow /etc/gshadow || true
chmod 600 /etc/ssh/sshd_config
chmod 700 /etc/cron.monthly /etc/cron.weekly /etc/cron.daily /etc/cron.hourly
chmod 600 /etc/crontab
# Sudoers file: use visudo to edit. Script sets permissions only.
chmod 440 /etc/sudoers
chmod 750 /etc/sudoers.d # Directory should be readable by root only, files 440.
find /etc/sudoers.d -type f -exec chmod 440 {} \;

# --- 15. DISABLE USB STORAGE & UNCOMMON FILESYSTEMS/MODULES ---
echo ""
echo "--- SECTION 15: DISABLE USB STORAGE & UNCOMMON MODULES ---"
echo " (>) Disabling USB Storage..."
add_or_update_line "/etc/modprobe.d/blacklist-usb-storage.conf" "blacklist usb_storage" "blacklist usb_storage"
echo " (i) USB storage blacklisted. A reboot might be needed or 'rmmod usb_storage'."

echo " (>) Disabling uncommon network protocols and filesystems (example)..."
# Add more as needed based on CIS benchmarks or requirements
cat > /etc/modprobe.d/blacklist-uncommon.conf <<EOF
# Uncommon network protocols
blacklist dccp
blacklist sctp
# Uncommon filesystems
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf
# RDS an TIPC protocols (often not needed)
blacklist rds
blacklist tipc
EOF
echo " (i) Uncommon modules blacklisted. A reboot might be needed."

# --- 16. SEARCH FOR PROHIBITED/SUSPICIOUS FILES ---
echo ""
echo "--- SECTION 16: SEARCH FOR PROHIBITED/SUSPICIOUS FILES ---"
echo " (>) Searching for prohibited files (e.g., .mp3, .mp4, .mov, .avi, .exe, .msi, .torrent)..."
PROHIBITED_EXTENSIONS=(
  "*.mp3" "*.wav" "*.aac"
  "*.mp4" "*.mov" "*.avi" "*.mkv" "*.flv"
  "*.exe" "*.msi" "*.bat" "*.com" "*.vbs"
  "*.torrent"
  "*.sh" # Be careful with .sh - review before deleting
  "*.pyc" # Compiled Python, often not needed by end-users
  "*.deb" "*.rpm" # Packages in user dirs might be unauthorized
  # Hacking tool names
  "*john*" "*nmap*" "*hydra*" "*wireshark*" "*kismet*" "*aircrack*" "*netcat*" "*nc*"
)
# Exclude system paths to speed up search and avoid false positives
EXCLUDE_PATHS="-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /snap -prune -o -path /var/lib/docker -prune -o -path /var/lib/snapd -prune -o"

echo " (!!!) REVIEW THE FOLLOWING FILES CAREFULLY BEFORE DELETION (!!!)"
for ext in "${PROHIBITED_EXTENSIONS[@]}"; do
  echo " (i) Searching for: ${ext}"
  # Use find with -iname for case-insensitive search
  # The find command will print files. Review them and delete manually or uncomment the rm part.
  # Be VERY careful with automatic deletion.
  # find / \( $EXCLUDE_PATHS \) -iname "${ext}" -type f -ls # Use -ls for more info
  find / \( ${EXCLUDE_PATHS} \) -iname "${ext}" -type f -print # Simpler output
  # To automatically delete (USE WITH EXTREME CAUTION):
  # find / \( $EXCLUDE_PATHS \) -iname "${ext}" -type f -print0 | xargs -0 --no-run-if-empty rm -f
done
echo " (i) Example command to delete (use with caution!): find /home -iname '*.mp3' -delete"
read -r -p "Press Enter to continue after reviewing/deleting prohibited files..."

echo " (>) Searching for SUID/SGID files..."
echo " (!!!) REVIEW SUID/SGID FILES. REMOVE BIT IF NOT NEEDED (chmod -s <file>) (!!!)"
find / \( ${EXCLUDE_PATHS} \) \( -perm -4000 -o -perm -2000 \) -type f -print -ls
read -r -p "Press Enter to continue after reviewing SUID/SGID files..."

echo " (>) Searching for world-writable files and directories..."
echo " (!!!) REVIEW WORLD-WRITABLE FILES/DIRS. FIX PERMISSIONS (!!!)"
find / \( ${EXCLUDE_PATHS} \) -type f -perm -0002 -print -ls
find / \( ${EXCLUDE_PATHS} \) -type d -perm -0002 -print -ls
read -r -p "Press Enter to continue after reviewing world-writable files/dirs..."

echo " (>) Searching for files not owned by any user/group..."
echo " (!!!) REVIEW ORPHANED FILES. INVESTIGATE OR REMOVE (!!!)"
find / \( ${EXCLUDE_PATHS} \) \( -nouser -o -nogroup \) -print -ls
read -r -p "Press Enter to continue after reviewing orphaned files..."


# --- 17. SYSTEM AND PACKAGE INTEGRITY ---
echo ""
echo "--- SECTION 17: SYSTEM AND PACKAGE INTEGRITY ---"
echo " (>) Checking integrity of installed packages (debsums)..."
debsums --changed # or debsums -c

# --- 18. REVIEW CRON JOBS ---
echo ""
echo "--- SECTION 18: REVIEW CRON JOBS ---"
echo " (!!!) MANUAL CRON JOB REVIEW REQUIRED (!!!)"
echo " (i) System-wide cron jobs:"
echo "     ls -la /etc/cron.* /etc/crontab"
echo "     cat /etc/crontab"
echo "     find /etc/cron.d -type f -print -exec cat {} \;"
echo " (i) User cron jobs (run as each user or root):"
echo "     for user in $(cut -f1 -d: /etc/passwd); do echo \"### Crontab for \$user ###\"; crontab -u \$user -l 2>/dev/null; done"
read -r -p "Press Enter to continue after reviewing cron jobs..."

# --- 19. REVIEW LISTENING SERVICES ---
echo ""
echo "--- SECTION 19: REVIEW LISTENING SERVICES ---"
echo " (!!!) MANUALLY REVIEW LISTENING NETWORK SERVICES (!!!)"
echo " (i) Command: ss -tulnp"
ss -tulnp
read -r -p "Press Enter to continue after reviewing listening services..."

# --- 20. OPTIONAL: IMMUTABLE BIT (ADVANCED - USE WITH CAUTION) ---
# echo ""
# echo "--- SECTION 20: IMMUTABLE BIT (ADVANCED) ---"
# echo " (CAUTION!) Making critical files immutable (chattr +i)..."
# echo " (CAUTION!) This makes files unchangeable even by root until 'chattr -i' is run."
# echo " (CAUTION!) Do this ONLY after all configurations are final."
# chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers
# chattr +i /etc/ssh/sshd_config
# chattr +i /etc/sysctl.conf
# echo " (i) To modify these files later, run 'chattr -i <file>' first."

# --- FINAL STEPS & REMINDERS ---
echo ""
echo "--- FINAL STEPS & REMINDERS ---"
echo " (>) Cleaning up apt cache..."
apt-get autoremove -y
apt-get clean

echo " (i) System hardening script completed at $(date)."
echo " (i) Log file: ${LOG_FILE}"
echo " (!!!) IMPORTANT REMINDERS (!!!)"
echo "   1.  REBOOT the system if significant changes like fstab or kernel modules were made."
echo "   2.  MANUALLY REVIEW all users, passwords, SUID/SGID files, cron jobs, and services."
echo "   3.  Regularly check logs in /var/log/ (auth.log, syslog, audit/audit.log, fail2ban.log)."
echo "   4.  Run 'lynis audit system' or 'oscap xccdf eval ...' for a comprehensive security audit."
echo "   5.  Test all critical services and applications after hardening."
echo "   6.  For CyberPatriot: Address any specific README vulnerabilities and scorebot items."
echo "   7.  Change ALL user passwords to strong, unique passwords."

exit 0

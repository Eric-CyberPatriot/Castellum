#!/bin/bash

# --- UBUNTU HARDENING SCRIPT FOR CYBERPATRIOT ---

# Removed 'set -e' to prevent the script from crashing if a single command fails (e.g., package not found).
# We want the script to attempt all hardening steps even if one fails.
set -o pipefail

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
  local pattern_to_grep="$3"

  if [ -f "$file" ]; then
      if ! grep -qF -- "$pattern_to_grep" "$file"; then
        echo " (+) Adding to ${file}: ${line_content}"
        echo "${line_content}" >> "${file}"
      else
        echo " (*) Line containing '${pattern_to_grep}' already exists in ${file}."
      fi
  else
      echo " (!) File ${file} not found. Creating it."
      echo "${line_content}" > "${file}"
  fi
}

add_or_update_sysctl() {
  local key="$1"
  local value="$2"
  local config_file="/etc/sysctl.conf"

  echo " (>) Configuring sysctl: ${key} = ${value}"
  if grep -qE "^\s*#?\s*${key}\s*=" "${config_file}"; then
    sed -i -e "s|^\s*#*\s*${key}\s*=.*|${key} = ${value}|g" "${config_file}"
  else
    echo "${key} = ${value}" >> "${config_file}"
  fi
}

# --- 1. SYSTEM UPDATES & ESSENTIAL TOOLS ---
echo ""
echo "--- SECTION 1: SYSTEM UPDATES & ESSENTIAL TOOLS ---"
# Check if internet is available before updating
if ping -c 1 8.8.8.8 &> /dev/null; then
    echo " (>) Updating package lists..."
    apt-get update -y
    echo " (>) Upgrading installed packages..."
    apt-get upgrade -y
    # apt-get dist-upgrade -y # Be careful with dist-upgrade in competition, can break GUI
    apt-get autoremove -y
    apt-get autoclean -y
else
    echo " (!) No internet connection detected. Skipping updates."
fi

echo " (>) Installing essential security tools..."
apt-get install -y ufw clamav clamav-daemon freshclam auditd audispd-plugins \
                   debsums libpam-pwquality libpam-apparmor apparmor-utils \
                   aide aide-common unattended-upgrades fail2ban openscap-scanner lynis || true

# --- 2. ANTIVIRUS (CLAMAV) ---
echo ""
echo "--- SECTION 2: ANTIVIRUS (CLAMAV) ---"
echo " (>) Stopping clamav-freshclam to update manually..."
systemctl stop clamav-freshclam || true
echo " (>) Updating ClamAV virus definitions..."
freshclam || echo " (!) Freshclam failed (possibly no internet or locked DB)."
echo " (>) Enabling and starting ClamAV daemon..."
systemctl enable clamav-daemon || true
systemctl start clamav-daemon || true

# --- 3. FILE INTEGRITY CHECKER (AIDE) ---
echo ""
echo "--- SECTION 3: FILE INTEGRITY CHECKER (AIDE) ---"
if [ ! -f /var/lib/aide/aide.db.gz ] && [ ! -f /var/lib/aide/aide.db ]; then
    echo " (>) Initializing AIDE database..."
    aideinit -y || echo " (!) aideinit failed."
    # Fix for common issue where aideinit creates .new file but doesn't rotate it
    if [ -f /var/lib/aide/aide.db.new.gz ]; then
        cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
else
    echo " (*) AIDE database already exists."
fi

# --- 4. AUDITING (AUDITD) ---
echo ""
echo "--- SECTION 4: AUDITING (AUDITD) ---"
if [ -d /etc/audit ]; then
    echo " (>) Configuring auditd..."
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak 2>/dev/null || true
    
    # We use a simplified safe config to ensure it works on most versions
    sed -i 's/^max_log_file_action.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action.*/space_left_action = SYSLOG/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = SUSPEND/' /etc/audit/auditd.conf
    
    echo " (>) Writing rules to /etc/audit/rules.d/99-cyberpatriot.rules..."
    cat > /etc/audit/rules.d/99-cyberpatriot.rules <<EOF
-D
-b 8192
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-e 2
EOF
    augenrules --load
    systemctl restart auditd || echo " (!) Failed to restart auditd"
fi

# --- 5. APPLICATION ARMOR (APPARMOR) ---
echo ""
echo "--- SECTION 5: APPLICATION ARMOR (APPARMOR) ---"
systemctl enable apparmor || true
systemctl start apparmor || true
# Only enforce if profiles exist
if ls /etc/apparmor.d/* &> /dev/null; then
    aa-enforce /etc/apparmor.d/* || true
fi

# --- 6. UNATTENDED UPGRADES ---
echo ""
echo "--- SECTION 6: UNATTENDED UPGRADES ---"
# Set standard config directly
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
echo " (i) Unattended upgrades configured."

# --- 7. FIREWALL (UFW) ---
echo ""
echo "--- SECTION 7: FIREWALL (UFW) ---"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
# Add common services if you know they are needed (e.g., HTTP)
# ufw allow http
echo " (>) Enabling UFW..."
ufw --force enable
ufw status verbose

# --- 8. REMOVE INSECURE SERVICES ---
echo ""
echo "--- SECTION 8: REMOVE INSECURE SERVICES & PACKAGES ---"
INSECURE_SERVICES=( "avahi-daemon" "cups" "rpcbind" "telnetd" "vsftpd" "pure-ftpd" "apache2" "nginx" "samba" "smbd" "nfs-kernel-server" "bind9" "snmpd" "pop3" "dovecot" )
INSECURE_PACKAGES=( "telnet" "rsh-client" "rsh-redone-client" "talk" "ypbind" "xinetd" "tftpd" "john" "nmap" "hydra" "wireshark" "netcat" "netcat-openbsd" "netcat-traditional" "ophcrack" "kismet" "minetest" )

for service in "${INSECURE_SERVICES[@]}"; do
  if systemctl is-active --quiet "$service"; then
    echo " (>) Stopping and disabling $service..."
    systemctl stop "$service" || true
    systemctl disable "$service" || true
  fi
done

echo " (>) Purging insecure packages..."
apt-get purge -y "${INSECURE_PACKAGES[@]}" || true
apt-get autoremove -y

# --- MINT SPECIFIC REMOVALS ---
echo " (>) Removing Mint-specific prohibited software..."
MINT_BAD_PKGS=(
    "transmission-gtk"       # Torrent client (Always remove)
    "transmission-common"
    "hexchat"                # IRC Client (Usually remove)
    "pidgin"                 # Chat client (Usually remove)
    # "thunderbird"            # Email client (Remove if not the mail server)
    "vino"                   # Remote desktop sharing (Dangerous)
    "remmina"                # Remote desktop client (Remove if not needed)
    "warpinator"             # Mint's file sharing tool (Often scored)
    "aMule"
    "Zangband"
)

apt-get purge -y "${MINT_BAD_PKGS[@]}" || true
apt-get autoremove -y

# --- SECTION 8.1: SECURE VSFTPD (FTP WITH SSL) ---
echo ""
echo "--- SECTION 8.1: SECURING VSFTPD (FTP) ---"

# Only run if vsftpd is actually installed
if dpkg -s vsftpd &> /dev/null; then
    echo " (>) vsftpd detected. Securing configuration..."
    VSFTPD_CONF="/etc/vsftpd.conf"
    cp "$VSFTPD_CONF" "${VSFTPD_CONF}.bak"

    # 1. Generate a self-signed certificate if one doesn't exist
    # vsftpd needs this to enable SSL.
    CERT_FILE="/etc/ssl/private/vsftpd.pem"
    if [ ! -f "$CERT_FILE" ]; then
        echo " (>) Generating self-signed SSL certificate for FTP..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$CERT_FILE" -out "$CERT_FILE" \
            -subj "/C=US/ST=CyberPatriot/L=Security/O=IT/CN=ftp.secure" 2>/dev/null
    fi

    # 2. Define the settings we want to ENFORCE
    # We use a loop to remove existing instances of these keys, then append the correct ones.
    # This guarantees the settings are active and not duplicated.
    
    # Basic Security
    sed -i '/^anonymous_enable/d' "$VSFTPD_CONF"
    echo "anonymous_enable=NO" >> "$VSFTPD_CONF"
    
    sed -i '/^local_enable/d' "$VSFTPD_CONF"
    echo "local_enable=YES" >> "$VSFTPD_CONF"
    
    sed -i '/^write_enable/d' "$VSFTPD_CONF"
    echo "write_enable=YES" >> "$VSFTPD_CONF"

    # SSL/TLS Enforcement
    sed -i '/^ssl_enable/d' "$VSFTPD_CONF"
    echo "ssl_enable=YES" >> "$VSFTPD_CONF"

    sed -i '/^allow_anon_ssl/d' "$VSFTPD_CONF"
    echo "allow_anon_ssl=NO" >> "$VSFTPD_CONF"

    sed -i '/^force_local_data_ssl/d' "$VSFTPD_CONF"
    echo "force_local_data_ssl=YES" >> "$VSFTPD_CONF"

    sed -i '/^force_local_logins_ssl/d' "$VSFTPD_CONF"
    echo "force_local_logins_ssl=YES" >> "$VSFTPD_CONF"

    # Encryption Protocols (Disable weak SSL, Enable TLS)
    sed -i '/^ssl_tlsv1/d' "$VSFTPD_CONF"
    echo "ssl_tlsv1=YES" >> "$VSFTPD_CONF"
    
    sed -i '/^ssl_sslv2/d' "$VSFTPD_CONF"
    echo "ssl_sslv2=NO" >> "$VSFTPD_CONF"
    
    sed -i '/^ssl_sslv3/d' "$VSFTPD_CONF"
    echo "ssl_sslv3=NO" >> "$VSFTPD_CONF"

    # Point to the certificate we generated/verified
    sed -i '/^rsa_cert_file/d' "$VSFTPD_CONF"
    echo "rsa_cert_file=$CERT_FILE" >> "$VSFTPD_CONF"
    
    sed -i '/^rsa_private_key_file/d' "$VSFTPD_CONF"
    echo "rsa_private_key_file=$CERT_FILE" >> "$VSFTPD_CONF"

    # 3. Restrict Users to Home Directory (Jail)
    # This prevents users from browsing /etc/ or other system folders
    sed -i '/^chroot_local_user/d' "$VSFTPD_CONF"
    echo "chroot_local_user=YES" >> "$VSFTPD_CONF"
    
    # Fix for writable root inside chroot (prevents login errors)
    sed -i '/^allow_writeable_chroot/d' "$VSFTPD_CONF"
    echo "allow_writeable_chroot=YES" >> "$VSFTPD_CONF"

    # --- SECTION: FIX FTP ROOT PERMISSIONS ---
echo " (>) Securing FTP Root Directories..."

# 1. Define common FTP root locations
# (Ubuntu/Debian usually uses /srv/ftp, older systems use /var/ftp)
FTP_ROOTS=("/srv/ftp" "/var/ftp")

for dir in "${FTP_ROOTS[@]}"; do
  if [ -d "$dir" ]; then
    echo " (>) Found FTP directory: $dir"
    
    # 2. Change ownership to root:root
    # The FTP root MUST NOT be owned by the user 'ftp' or the group 'ftp'.
    chown root:root "$dir"
    echo "     - Changed ownership to root:root"

    # 3. Change permissions to 755 (Read/Execute for everyone, Write ONLY for root)
    # This prevents the "500 OOPS: vsftpd: refusing to run with writable root inside chroot()" error
    # and secures the directory from tampering.
    chmod 755 "$dir"
    echo "     - Changed permissions to 755"
    
    # Optional: If you need an upload folder, create a 'blind' directory inside
    # mkdir -p "$dir/upload"
    # chown ftp:ftp "$dir/upload"
    # chmod 755 "$dir/upload"
  fi
done

echo " (i) FTP Root directory permissions fixed."

    echo " (>) Restarting vsftpd..."
    systemctl restart vsftpd || echo " (!) Failed to restart vsftpd. Check configuration."
else
    echo " (*) vsftpd is not installed. Skipping."
fi

# --- 9. SSH CONFIGURATION ---
echo ""
echo "--- SECTION 9: SECURE SSH CONFIGURATION ---"
SSH_CONFIG="/etc/ssh/sshd_config"
if [ -f "${SSH_CONFIG}" ]; then
  cp "${SSH_CONFIG}" "${SSH_CONFIG}.bak"
  
  # Basic sed replacements to ensure security
  sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
  sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
  
  sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
  sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
  
  sed -i 's/^Protocol.*/Protocol 2/' "$SSH_CONFIG"
  # If Protocol line doesn't exist, append it
  grep -q "^Protocol" "$SSH_CONFIG" || echo "Protocol 2" >> "$SSH_CONFIG"

  sed -i 's/^X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"
  sed -i 's/^#X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"

  # Ensure banner
  echo "Authorized uses only." > /etc/issue.net
  sed -i 's|^#Banner.*|Banner /etc/issue.net|' "$SSH_CONFIG"
  grep -q "^Banner" "$SSH_CONFIG" || echo "Banner /etc/issue.net" >> "$SSH_CONFIG"

  if sshd -t; then
    systemctl restart sshd
  else
    echo " (!) SSH Config check failed. Reverting..."
    cp "${SSH_CONFIG}.bak" "${SSH_CONFIG}"
  fi
fi

# --- 10. FAIL2BAN ---
echo ""
echo "--- SECTION 10: FAIL2BAN ---"
JAIL_LOCAL="/etc/fail2ban/jail.local"
if [ ! -f "${JAIL_LOCAL}" ]; then
  echo " (>) Creating jail.local..."
  # We append our config to the end of the file. This overrides defaults.
  # This is safer than replacing text that might change between versions.
  cat > "${JAIL_LOCAL}" <<EOF
[DEFAULT]
bantime = 1h
findtime = 30m
maxretry = 3

[sshd]
enabled = true
EOF
fi
systemctl enable fail2ban || true
systemctl restart fail2ban || true

# --- 11. USER ACCOUNTS & PASSWORD POLICIES ---
echo ""
echo "--- SECTION 11: USER ACCOUNTS & PASSWORD POLICIES ---"

# Lock root
passwd -l root || true

# Login definitions
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs

# PWQuality
PWQUALITY="/etc/security/pwquality.conf"
echo "minlen = 14" > "$PWQUALITY"
echo "dcredit = -1" >> "$PWQUALITY"
echo "ucredit = -1" >> "$PWQUALITY"
echo "lcredit = -1" >> "$PWQUALITY"
echo "ocredit = -1" >> "$PWQUALITY"
echo "difok = 3" >> "$PWQUALITY"
echo "enforce_for_root" >> "$PWQUALITY"

# PAM Configuration - SAFER METHOD
echo " (>) Applying PAM updates..."
# Enable pwquality
pam-auth-update --enable pwquality || true

# PAM Faillock/Tally logic
COMMON_AUTH="/etc/pam.d/common-auth"
cp "$COMMON_AUTH" "${COMMON_AUTH}.bak"

# Check OS version for faillock vs tally2
# Ubuntu 22.04+ uses faillock. 20.04 and older uses tally2.
if grep -q "pam_tally2.so" /lib/x86_64-linux-gnu/security/pam_tally2.so 2>/dev/null || [ -f /lib/security/pam_tally2.so ]; then
    echo " (i) Detected pam_tally2."
    if ! grep -q "pam_tally2.so" "$COMMON_AUTH"; then
        sed -i '1i auth required pam_tally2.so deny=3 unlock_time=1200 onerr=fail' "$COMMON_AUTH"
    fi
else
    echo " (i) Assuming pam_faillock (Newer Ubuntu)."
    # Basic check to avoid double entry
    if ! grep -q "pam_faillock.so" "$COMMON_AUTH"; then
        sed -i '1i auth required pam_faillock.so preauth silent audit deny=3 unlock_time=900' "$COMMON_AUTH"
        # faillock also needs an entry at the end usually, or just rely on common-account
        echo "auth [default=die] pam_faillock.so authfail" >> "$COMMON_AUTH"
        echo "auth sufficient pam_faillock.so authsucc" >> "$COMMON_AUTH"
    fi
fi

# --- FIX NOPASSWDLOGIN GROUP ---
echo " (>) Checking for users in 'nopasswdlogin' group..."
if grep -q "nopasswdlogin" /etc/group; then
    # Find users in the group
    BAD_USERS=$(grep "nopasswdlogin" /etc/group | cut -d: -f4)
    if [ -n "$BAD_USERS" ]; then
        echo " (!) FOUND USERS IN nopasswdlogin: $BAD_USERS"
        # Split by comma and loop
        IFS=',' read -ra ADDR <<< "$BAD_USERS"
        for user in "${ADDR[@]}"; do
            echo "     - Removing $user from nopasswdlogin..."
            gpasswd -d "$user" nopasswdlogin
        done
    else
        echo " (*) No users found in nopasswdlogin group."
    fi
fi

# --- SECTION 11.1: FIREFOX SECURITY ---
echo " (>) Applying Firefox Security Policies..."
mkdir -p /usr/lib/firefox/distribution
mkdir -p /etc/firefox/policies

# Define the policy content
cat > /tmp/policies.json <<EOF
{
  "policies": {
    "DisableAppUpdate": false,
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DisablePasswordReveal": true,
    "OfferToSaveLogins": false,
    "PasswordManagerEnabled": false,
    "BlockAboutConfig": true,
    "PopupBlocking": {
      "Default": true,
      "Locked": true
    },
    "Phishing": {
      "Enabled": true,
      "Locked": true
    }
  }
}
EOF

# Copy to both possible locations to be safe
cp /tmp/policies.json /usr/lib/firefox/distribution/policies.json
cp /tmp/policies.json /etc/firefox/policies/policies.json
echo " (i) Firefox policies applied (Popups blocked, Passwords disabled)."

# --- 12. LIGHTDM ---
echo ""
echo "--- SECTION 12: LIGHTDM ---"
LIGHTDM_CONF="/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
if [ -f "$LIGHTDM_CONF" ]; then
    echo "allow-guest=false" >> "$LIGHTDM_CONF"
    echo "greeter-hide-users=true" >> "$LIGHTDM_CONF"
    echo "greeter-show-manual-login=true" >> "$LIGHTDM_CONF"
fi

# --- 12. LIGHTDM (LINUX MINT 21 FIX) ---
echo ""
echo "--- SECTION 12: LIGHTDM ---"

# Create the configuration directory if it doesn't exist
mkdir -p /etc/lightdm/lightdm.conf.d

# Create a new config file with high priority (99) to override defaults
# This works for both Ubuntu and Linux Mint 21
echo "[Seat:*]" > /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf
echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf
echo "greeter-show-manual-login=true" >> /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf

echo " (i) Guest account disabled via /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf"

# --- SECTION 12.1: SECURE CINNAMON DESKTOP (MINT) ---
echo " (>) Configuring Cinnamon Screensaver & Lock Policies..."

# 1. Create a Dconf profile if it doesn't exist
mkdir -p /etc/dconf/profile
if [ ! -f /etc/dconf/profile/user ]; then
    echo "user-db:user" > /etc/dconf/profile/user
    echo "system-db:local" >> /etc/dconf/profile/user
fi

# 2. Create the security settings database
mkdir -p /etc/dconf/db/local.d
cat > /etc/dconf/db/local.d/00-cyberpatriot-hardening <<EOF
[org/cinnamon/desktop/screensaver]
# Lock the screen when the screensaver activates
lock-enabled=true
# Activate screensaver when idle
idle-activation-enabled=true
# Time before locking (900 seconds = 15 minutes)
delay-time=900
# Lock immediately when screensaver starts
lock-delay=0

[org/cinnamon/settings-daemon/plugins/power]
# Lock screen when suspending
lock-on-suspend=true

[org/cinnamon/desktop/session]
# Idle delay (15 mins)
idle-delay=900
EOF

# 3. Lock these settings so users cannot change them
mkdir -p /etc/dconf/db/local.d/locks
cat > /etc/dconf/db/local.d/locks/00-cyberpatriot-hardening <<EOF
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/desktop/screensaver/idle-activation-enabled
/org/cinnamon/desktop/screensaver/delay-time
/org/cinnamon/desktop/screensaver/lock-delay
/org/cinnamon/settings-daemon/plugins/power/lock-on-suspend
/org/cinnamon/desktop/session/idle-delay
EOF

# 4. Update the Dconf database to apply changes
dconf update
echo " (i) Cinnamon desktop security enforced."

# --- DISABLE CTRL+ALT+BACKSPACE ---
# Prevents users from killing the GUI session
localedef -v -c -i en_US -f UTF-8 en_US.UTF-8 2>/dev/null || true
if [ -f /etc/default/keyboard ]; then
    sed -i 's/XKBOPTIONS=".*"/XKBOPTIONS=""/' /etc/default/keyboard
    dpkg-reconfigure -f noninteractive keyboard-configuration
fi

# --- 13. KERNEL PARAMETERS ---
echo ""
echo "--- SECTION 13: KERNEL PARAMETERS ---"
# Apply basic hardening
add_or_update_sysctl "net.ipv4.ip_forward" "0"
add_or_update_sysctl "net.ipv4.conf.all.accept_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.log_martians" "1"
add_or_update_sysctl "net.ipv4.tcp_syncookies" "1"
add_or_update_sysctl "fs.suid_dumpable" "0"
add_or_update_sysctl "kernel.randomize_va_space" "2"
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

echo " (>) Applying sysctl changes..."
sysctl -p /etc/sysctl.conf || true

# --- 14. SECURE SHARED MEMORY ---
if ! grep -q "tmpfs /dev/shm" /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec 0 0" >> /etc/fstab
    mount -o remount /dev/shm || true
fi

# --- 15. PERMISSIONS ---
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true

# --- 16. MEDIA & HACKING FILES ---
echo ""
echo "--- SECTION 16: PROHIBITED FILES ---"
# Only finding, NOT deleting automatically to prevent accidents.
# User should review the log.
echo " (i) Searching for media files (check log)..."
find /home -type f \( -name "*.mp3" -o -name "*.mp4" -o -name "*.avi" \) -print

echo " (i) Searching for hacking tools..."
find /home -type f \( -name "*.pcap" -o -name "john" -o -name "hydra" \) -print

# --- 17. FINAL CLEANUP ---
echo ""
echo "--- FINAL CLEANUP ---"
apt-get autoremove -y
apt-get clean

echo "Hardening complete. Please REBOOT the system."
echo "Don't forget to manually check:"
echo "1. Users in /etc/passwd and /etc/group (sudo group)"
echo "2. Cron jobs (crontab -e)"
echo "3. Firefox settings"
echo "4. The README for specific services required!"

exit 0

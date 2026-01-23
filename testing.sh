#!/bin/bash

# --- UBUNTU HARDENING SCRIPT FOR CYBERPATRIOT ---

# Removed 'set -e' to prevent the script from crashing if a single command fails (e.g., package not found).
# We want the script to attempt all hardening steps even if one fails.
set -o pipefail
export DEBIAN_FRONTEND=noninteractive

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
echo " (>) Setting default account inactivity to 30 days..."
useradd -D -f 30
echo " (>) Setting global shell timeout (900 seconds)..."
if ! grep -q "TMOUT=" /etc/profile; then
    echo "readonly TMOUT=900" >> /etc/profile
    echo "export TMOUT" >> /etc/profile
fi
echo " (>) Enforcing sticky bits on world-writable directories..."
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod +t {} + 2>/dev/null
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

echo " (>) Hardening Sudoers policy..."
# Ensure sudo requires a password every time (short timeout)
# and use a separate TTY for each sudo command
cat > /etc/sudoers.d/99-cyberpatriot <<EOF
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        use_pty
Defaults        passwd_timeout=0
Defaults        timestamp_timeout=0
EOF
chmod 440 /etc/sudoers.d/99-cyberpatriot
# --- 5. APPLICATION ARMOR (APPARMOR) ---
echo ""
echo "--- SECTION 5: APPLICATION ARMOR (APPARMOR) ---"
systemctl enable apparmor || true
systemctl start apparmor || true
# Only enforce if profiles exist
echo " (>) Putting AppArmor profiles into enforce mode..."
aa-enforce /etc/apparmor.d/* 2>/dev/null || true


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
INSECURE_SERVICES=( "avahi-daemon" "cups" "rpcbind" "telnetd" "vsftpd" "pure-ftpd" "apache2" "nginx" "samba" "smbd" "nfs-kernel-server" "bind9" "snmpd" "pop3" "dovecot" "fingerd" "rstatd" "ruserd" "rwalld" "squid" "snmpd" "xrdp" "vncserver" "inetd")
INSECURE_PACKAGES=( "telnet" "rsh-client" "rsh-redone-client" "talk" "ypbind" "xinetd" "tftpd" "john" "nmap" "hydra" "wireshark" "netcat" "netcat-openbsd" "netcat-traditional" "ophcrack" "kismet" "minetest" "aircrack-ng" "metasploit-framework" "nikto" "sqlmap" "burpsuite" "medusa" "hashcat" 
    "tcpdump" "zenmap" "ettercap-common" "dsniff" "wireshark" "tshark" 
    "teamviewer" "anydesk" "tightvncserver" "vnc4server" "x11vnc" "rdesktop"
    "steam" "steam-launcher" "minecraft-launcher" "wesnoth" "vlc" "spotify-client"
    "discord" "zoom" "frozen-bubble" "rsh-client" "rsh-server" "nis" "yp-tools" 
    "tftp" "atftpd" "snmp" "snmpd" "ldap-utils" "slapd" "doona" "finger" "rlogin" "rexec" "wine" "wine32" "wine64" 
    "aisleriot" "gnome-games" "kmines" "quadrapassel" "tali" "iagno" "lightsoff"
    "qbittorrent" "deluge" "frostwire" "nicotine" 
    "skypeforlinux" "slack-desktop" "telegram-desktop"
    "gcc" "make" "git" "nmap" "zenmap" "wireshark" "tshark" 
    "beef-xss" "maltego" "aircrack-ng" "crunch" "hashcat")

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

# --- DISABLE SMTP (EMAIL) ---
echo " (>) Disabling SMTP services..."
# Disable Postfix (Standard Ubuntu Mail Server)
if systemctl is-active --quiet postfix; then
    systemctl stop postfix
    systemctl disable postfix
    echo "     - Postfix stopped and disabled."
fi
# Disable Exim4 (Alternative Mail Server)
if systemctl is-active --quiet exim4; then
    systemctl stop exim4
    systemctl disable exim4
    echo "     - Exim4 stopped and disabled."
fi
# --- MYSQL HARDENING ---
if [ -d "/etc/mysql" ]; then
    echo " (>) Securing MySQL..."
    # Ensure MySQL only listens on localhost
    find /etc/mysql -name "*.cnf" -exec sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' {} \;
    # Disable symbolic links
    find /etc/mysql -name "*.cnf" -exec sed -i '/\[mysqld\]/a skip-symbolic-links' {} \;
    # Restart
    systemctl restart mysql 2>/dev/null || true
fi

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

# --- PHP SECURITY HARDENING ---
if [ -d "/etc/php" ]; then
    echo " (>) Hardening PHP configuration..."
    # Find all php.ini files
    PHP_INIS=$(find /etc/php -name "php.ini")
    
    for ini in $PHP_INIS; do
        echo "     - Editing $ini"
        # Disable remote file opening (prevents RFI attacks)
        sed -i 's/^allow_url_fopen.*/allow_url_fopen = Off/' "$ini"
        sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$ini"
        # Disable script execution time limit (prevents DoS)
        sed -i 's/^max_execution_time.*/max_execution_time = 30/' "$ini"
        # Hide PHP version (Information Disclosure)
        sed -i 's/^expose_php.*/expose_php = Off/' "$ini"
        # Disable dangerous functions
        sed -i 's/^disable_functions.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' "$ini"
        # Enable logging
        sed -i 's/^log_errors.*/log_errors = On/' "$ini"
    done
    
    # Restart Apache if present
    systemctl restart apache2 2>/dev/null || true
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
echo " (>) Enforcing password history (remember=5)..."
# Look for pam_unix.so in common-password and add remember=5
if grep -q "pam_unix.so" /etc/pam.d/common-password; then
    # Remove existing remember setting if it exists, then add it
    sed -i 's/\(pam_unix.so.*\)\sremember=[0-9]*/\1/' /etc/pam.d/common-password
    sed -i 's/pam_unix.so.*/& remember=5/' /etc/pam.d/common-password
fi
# Lock root
passwd -l root || true

# Login definitions
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 2/' /etc/login.defs
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
pam-auth-update --enable faillock
# Set specific values often required by CyberPatriot
echo "deny = 3" > /etc/security/faillock.conf
echo "unlock_time = 900" >> /etc/security/faillock.conf
echo "silent" >> /etc/security/faillock.conf
echo "audit" >> /etc/security/faillock.conf
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
    
fi
# This ensures even if pam-auth-update used defaults, we overwrite them with our target values
sed -i 's/pam_faillock.so.*/pam_faillock.so preauth silent audit deny=3 unlock_time=900/' /etc/pam.d/common-auth

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

# --- CHECK FOR NON-ROOT UID 0 ---
echo " (>) Checking for non-root users with UID 0..."
# Get all users with UID 0
UID0_USERS=$(awk -F: '($3 == "0") {print $1}' /etc/passwd)

for user in $UID0_USERS; do
    if [ "$user" != "root" ]; then
        echo " (!!!) SECURITY ALERT: User $user has UID 0! Changing to UID 1000+..."
        # Change UID to something safe (incrementing to avoid conflict)
        usermod -u $(shuf -i 2000-5000 -n 1) "$user"
        echo "     - $user UID changed. Verify user is still needed."
    fi
done

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
echo " (>) Disabling IPv6..."
add_or_update_sysctl "net.ipv6.conf.all.disable_ipv6" "1"
add_or_update_sysctl "net.ipv6.conf.default.disable_ipv6" "1"
add_or_update_sysctl "net.ipv6.conf.lo.disable_ipv6" "1"
sysctl -p
# Apply basic hardening
# Prevent core dumps (can contain sensitive info)
add_or_update_sysctl "fs.suid_dumpable" "0"

# IP Spoofing protection
add_or_update_sysctl "net.ipv4.conf.all.rp_filter" "1"
add_or_update_sysctl "net.ipv4.conf.default.rp_filter" "1"

# Ignore Bogus ICMP Errors
add_or_update_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"
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

# --- SECURE WEB SERVER ROOT ---
if [ -d "/var/www/html" ]; then
    echo " (>) Securing /var/www/html permissions..."
    # 1. Set ownership to root:root (or root:www-data)
    # This prevents the web user from modifying files if compromised.
    chown -R root:root /var/www/html
    
    # 2. Set directories to 755 (Read/Execute for everyone, Write for Owner only)
    find /var/www/html -type d -exec chmod 755 {} \;
    
    # 3. Set files to 644 (Read/Write for Owner, Read for everyone)
    find /var/www/html -type f -exec chmod 644 {} \;
    
    echo " (i) Web root permissions fixed."
fi
# --- SECURE ROOT HOME ---
echo " (>) Securing /root directory..."
chown root:root /root
chmod 700 /root
# --- SECURE SHELL CONFIGS ---
echo " (>) Securing global shell configuration files..."
SHELL_CONFIGS=("/etc/profile" "/etc/bash.bashrc" "/etc/environment" "/etc/profile.d")

for config in "${SHELL_CONFIGS[@]}"; do
  if [ -e "$config" ]; then
    chown root:root "$config"
    chmod 644 "$config"
  fi
done
# --- SECURE SUDOERS DIRECTORY ---
echo " (>) Securing /etc/sudoers.d..."
# The directory itself needs to be 750 (root:root or root:sudo)
chmod 755 /etc/sudoers.d
# Files inside must be 440
chmod 440 /etc/sudoers.d/* 2>/dev/null || true
# --- SECURE APT SOURCES ---
echo " (>) Securing apt sources..."
chown root:root /etc/apt/sources.list
chmod 644 /etc/apt/sources.list
chown root:root /etc/apt/sources.list.d
chmod 755 /etc/apt/sources.list.d
# --- SECURE CRON DIRECTORIES ---
echo " (>) Securing cron directories..."
# Set ownership to root:root and permissions to 700 (or 755)
# 700 is safer so only root can see what jobs are running.
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
chown -R root:root /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
chmod 600 /etc/crontab
# --- SECURE LOG FILES ---
echo " (>) Securing log files..."
# wtmp logs login/logout history
if [ -f /var/log/wtmp ]; then
    chmod 660 /var/log/wtmp
    chown root:utmp /var/log/wtmp
fi
# btmp logs failed login attempts
if [ -f /var/log/btmp ]; then
    chmod 660 /var/log/btmp
    chown root:utmp /var/log/btmp
fi
# lastlog
if [ -f /var/log/lastlog ]; then
    chmod 660 /var/log/lastlog
    chown root:utmp /var/log/lastlog
fi

# --- CLEAN ETC/HOSTS ---
echo " (>) Checking /etc/hosts for malicious redirects..."
# Backup first
cp /etc/hosts /etc/hosts.bak
# Remove lines redirecting security sites to localhost
sed -i '/security.ubuntu.com/d' /etc/hosts
sed -i '/archive.ubuntu.com/d' /etc/hosts
echo " (i) Hosts file cleaned."

# --- SUDOERS NOPASSWD SCRUB ---
echo " (>) Checking sudoers for NOPASSWD entries..."
# This finds lines containing NOPASSWD and comments them out
if grep -q "NOPASSWD" /etc/sudoers; then
    sed -i 's/\(.*NOPASSWD.*\)/# \1/' /etc/sudoers
    echo "     - Commented out NOPASSWD in /etc/sudoers"
fi

# Check included files as well
grep -r "NOPASSWD" /etc/sudoers.d/ | while read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    sed -i 's/\(.*NOPASSWD.*\)/# \1/' "$file"
    echo "     - Commented out NOPASSWD in $file"
done

echo " (>) Locking shells for system accounts..."
# This finds system accounts (UID < 1000) that have a shell and changes it to nologin
awk -F: '($3 < 1000 && $1 != "root" && $7 != "/usr/sbin/nologin" && $7 != "/bin/false") {print $1}' /etc/passwd | while read user; do
    usermod -s /usr/sbin/nologin "$user"
done



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

echo " (>) Hardening resource limits..."
cat <<EOF >> /etc/security/limits.conf
* hard core 0
* soft nproc 100
* hard nproc 150
EOF
# --- ADVANCED PERSISTENCE CHECK ---
echo " (>) Checking for suspicious startup scripts..."
# Look for scripts in init.d that are not official services
# This is a heuristic scan (might have false positives, just prints them)
ls -la /etc/init.d/ | grep -v "root"
ls -la /etc/rc.local 2>/dev/null

echo " (>) Checking for 'hidden' cron jobs (files starting with .)..."
find /etc/cron* -name ".*" -print
find /var/spool/cron -name ".*" -print

echo "Hardening complete. Please REBOOT the system."
echo "Don't forget to manually check:"
echo "1. Users in /etc/passwd and /etc/group (sudo group)"
echo "2. Cron jobs (crontab -e)"
echo "3. Firefox settings"
echo "4. The README for specific services required!"

echo ""
echo "=================================================="
echo "   CURRENT USER AUDIT (COMPARE WITH README!)"
echo "=================================================="
echo "ADMINS (sudo group):"
grep -Po '^sudo:.*:\K.*$' /etc/group
echo "--------------------------------------------------"
echo "ALL USERS (UID >= 1000):"
awk -F: '($3 >= 1000 && $3 < 60000) {print $1, $3}' /etc/passwd
echo "=================================================="
echo ""
echo " (>) Scanning for suspicious usernames..."
SUSPICIOUS_NAMES=("backdoor" "hacker" "attacker" "shadow" "temp" "test" "root2" "admin2")
for name in "${SUSPICIOUS_NAMES[@]}"; do
    if id "$name" &>/dev/null; then
        echo " [!!!] SUSPICIOUS USER FOUND: $name. Check README immediately!"
    fi
done
echo " (>) Checking for accounts with empty passwords..."
EMPTY_PW=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
for user in $EMPTY_PW; do
    echo " [!] Account $user has NO PASSWORD!"
done
echo " (>) Verifying integrity of password files..."
pwck -r || echo " [!!!] Potential issues found in /etc/passwd or /etc/shadow!"
grpck -r || echo " [!!!] Potential issues found in /etc/group or /etc/gshadow!"
echo "--- CRON JOB AUDIT ---"
for user in $(awk -F: '{print $1}' /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v "^#" && echo " (!!!) Above cron job found for user: $user"
done

exit 0

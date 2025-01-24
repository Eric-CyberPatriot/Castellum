#!/bin/bash

# --- LINUX HARDENING ---

echo "Starting system hardening..."

# 1. Update the machine
apt-get update -y
apt-get upgrade -y
apt-get dist-upgrade -y

# 2. Install and run ClamAV and other tools/packages
apt-get install clamtk -y
freshclam
apt install -y aide auditd debsums apparmor apparmor-utils clamav clamav-daemon unattended-upgrades ufw openscap-scanner

# Initialize AIDE
echo "Initializing AIDE, the file integrity checker..."
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configure Auditd
echo "Configuring auditd..."
cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup
echo "
log_file = /var/log/audit/audit.log
log_group = root
log_format = ENRICHED
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 20
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
" > /etc/audit/auditd.conf
service auditd restart

# Configure AppArmor
echo "Configuring AppArmor..."
aa-enforce /etc/apparmor.d/*

# Configure Unattended-Upgrades
echo "Configuring automatic security updates..."
dpkg-reconfigure --priority=low unattended-upgrades

# 3. Set automatic updates (GUI interaction required for this step)
echo "Please enable automatic updates in System Settings > Software & Updates > Updates."
echo "Select 'Automatically check for updates' and 'Important security updates'."
read -r -p "Press Enter to continue after configuring automatic updates..."

# 4. Search for prohibited files (Example: *.mp3)
# Replace *.mp3 with the desired extensions
find / -name "*.mp3" -type f -print0 | xargs -0 rm -f  # Use -print0 and xargs -0 for safe filename handling

# 5. Configure the firewall & disable unsecure services
apt-get install ufw -y
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable
ufw status

systemctl disable avahi-daemon
systemctl disable cups
systemctl disable rpcbind

# 6. Edit lightdm.conf
if [ -f /etc/lightdm/lightdm.conf ]; then
    sed -i 's/^\(allow-guest=\).*/\1false/' /etc/lightdm/lightdm.conf
    sed -i 's/^\(greeter-hide-users=\).*/\1true/' /etc/lightdm/lightdm.conf
    sed -i 's/^\(greeter-show-manual-login=\).*/\1true/' /etc/lightdm/lightdm.conf
    sed -i 's/^\(autologin-user=\).*/\1none/' /etc/lightdm/lightdm.conf
elif [ -f /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf ]; then  # Ubuntu specific path
    sed -i 's/^\(allow-guest=\).*/\1false/' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    sed -i 's/^\(greeter-hide-users=\).*/\1true/' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    sed -i 's/^\(greeter-show-manual-login=\).*/\1true/' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    sed -i 's/^\(autologin-user=\).*/\1none/' /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
fi

# 9. Edit /etc/login.defs
sudo apt install libpam-cracklib
sed -i 's/^\(FAILLOG_ENAB\).*/\1 YES/' /etc/login.defs
sed -i 's/^\(LOG_UNKFAIL_ENAB\).*/\1 YES/' /etc/login.defs
sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t2/' /etc/login.defs
sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t7/' /etc/login.defs
sed -i '1s/^/password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1\n/' /etc/pam.d/common-password

# ... (similarly for other settings)

sed -i 's/pam_unix.so.*/pam_unix.so obscure ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

# 11/12/13. Check /etc/passwd, /etc/group, disable root (Manual checks recommended)
echo "Manually review /etc/passwd and /etc/group for inconsistencies and security issues."
echo "Ensure root is disabled (passwd -l root)."
usermod -L root
passwd -l root  # Lock root account

# 14. Secure SSH
sed -i 's/^\(LoginGraceTime\).*/\1 60/' /etc/ssh/sshd_config
sed -i 's/^\(PermitRootLogin\).*/\1 no/' /etc/ssh/sshd_config
sed -i 's/^\(Protocol\).*/\1 2/' /etc/ssh/sshd_config
sed -i 's/^\(PermitEmptyPasswords\).*/\1 no/' /etc/ssh/sshd_config
sed -i 's/^\(PasswordAuthentication\).*/\1 yes/' /etc/ssh/sshd_config
sed -i 's/^\(X11Forwarding\).*/\1 no/' /etc/ssh/sshd_config  # Note: X11Forwarding, not X11Fowarding
sed -i 's/^\(UsePAM\).*/\1 yes/' /etc/ssh/sshd_config
sed -i 's/^\(UsePrivilegeSeparation\).*/\1 yes/' /etc/ssh/sshd_config
systemctl restart ssh
systemctl restart sshd

# Install and Configure Fail2Ban
apt install fail2ban -y
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local
sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl start fail2ban

# 7. Remove Unnecessary Packages
apt remove telnet rsh-client rsh-redone-client -y

# 8. Enable and Configure auditd
apt install auditd -y
systemctl enable auditd
systemctl start auditd

# 9. Disable USB Storage
echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-usb-storage.conf

# 10. Secure Shared Memory
echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab

# 15. Secure directories
chmod 700 /boot /etc/cron.monthly /etc/cron.weekly /etc/cron.daily /etc/cron.hourly
chmod 600 /etc/crontab /etc/ssh/sshd_config
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
chmod 640 /etc/gshadow
chmod 640 /etc/sudoers
chmod 640 /etc/sudoers.d/
echo "tmpfs     /run/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab

# ... (Continue similarly for the rest of the checklist) ...

# 16. Configure /etc/sysctl.conf

# Function to add or update a setting in sysctl.conf 
add_or_update_setting() {
  setting="$1"
  value="$2"

  if grep -q "^$setting" "/etc/sysctl.conf"; then
    sed -i "s/^$setting.*/$setting = $value/" "/etc/sysctl.conf"
  else
    echo "$setting = $value" >> "/etc/sysctl.conf"
  fi
}

# Disable ICMP redirects
add_or_update_setting "net.ipv4.conf.all.accept_redirects" "0"

# Disable IP forwarding (redirecting)
add_or_update_setting "net.ipv4.ip_forward" "0"
add_or_update_setting "net.ipv4.conf.all.send_redirects" "0"
add_or_update_setting "net.ipv4.conf.default.send_redirects" "0"

# Disable IP spoofing
add_or_update_setting "net.ipv4.conf.all.rp_filter" "1"

# Disable IP source routing
add_or_update_setting "net.ipv4.conf.all.accept_source_route" "0"

# SYN Flood Protection
add_or_update_setting "net.ipv4.tcp_max_syn_backlog" "2048"
add_or_update_setting "net.ipv4.tcp_synack_retries" "2"
add_or_update_setting "net.ipv4.tcp_syn_retries" "5"
add_or_update_setting "net.ipv4.tcp_syncookies" "1"

# Disable IPv6 (Consider carefully - might break some applications)
add_or_update_setting "net.ipv6.conf.all.disable_ipv6" "1"
add_or_update_setting "net.ipv6.conf.default.disable_ipv6" "1"
add_or_update_setting "net.ipv6.conf.lo.disable_ipv6" "1"

# Apply sysctl changes
sysctl -p

echo "System hardening script completed. Remember to check the users to see if there are any unauthorized users or administrators."

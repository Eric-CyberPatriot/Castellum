#!/bin/bash

# --- CYBERPATRIOT FILESYSTEM PERMISSION HARDENER (SAFE VERSION) ---
# TARGETS: Linux Mint 21, Ubuntu 22.04/24.04
# FIXES: Removed recursive chown/chmod that breaks SUID and Services.

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "(!) STARTING SAFE PERMISSION HARDENING..."

# 1. FIX CRITICAL "STICKY BIT" DIRECTORIES
# Essential for OS stability.
echo " (>) Fixing /tmp and /var/tmp permissions..."
chmod 1777 /tmp
chmod 1777 /var/tmp
chown root:root /tmp
chown root:root /var/tmp

# 2. SECURE SYSTEM BINARIES (REMOVE WORLD WRITE ONLY)
# ! CRITICAL FIX: Do NOT chown these recursively, or you lose SUID (sudo/passwd).
# ! CRITICAL FIX: Do NOT chmod 755 recursively. Only remove "o-w" (Others-Write).
echo " (>) Removing world-write access from system binaries..."
SYS_DIRS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/lib" "/lib64" "/usr/lib")

for dir in "${SYS_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        # Only remove 'write' for 'others'. 
        # -perm /0002 checks if write bit is set for others.
        find "$dir" -type f -perm /0002 -exec chmod o-w {} + 2>/dev/null
    fi
done

# 3. SECURE CONFIGURATION (/etc)
# ! CRITICAL FIX: Do NOT chown -R root:root /etc. It breaks MySQL/DNS/Mail.
echo " (>) Removing world-write access from /etc..."
find /etc -type f -perm /0002 -exec chmod o-w {} + 2>/dev/null

# Fix specific critical files securely
echo " (>) Locking down shadow and passwd..."
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow   # 640 is standard, 600 is tighter (root only)
chmod 600 /etc/gshadow
chown root:root /etc/passwd /etc/group /etc/shadow /etc/gshadow

# 4. SECURE HOME DIRECTORIES
echo " (>) Securing User Home Directories..."
# Iterate through standard users (UID 1000+)
awk -F: '($3 >= 1000 && $3 < 60000) {print $1 ":" $6}' /etc/passwd | while read -r line; do
    user_name=$(echo "$line" | cut -d: -f1)
    user_home=$(echo "$line" | cut -d: -f2)

    if [ -d "$user_home" ]; then
        # Ensure user owns their home
        chown "$user_name":"$user_name" "$user_home"
        
        # 750: User RWX, Group RX, World None. 
        # This prevents users from snooping inside other home folders.
        chmod 750 "$user_home"
        
        # Secure SSH if exists
        if [ -d "$user_home/.ssh" ]; then
            chmod 700 "$user_home/.ssh"
            chmod 600 "$user_home/.ssh/"* 2>/dev/null
        fi
    fi
done

# Secure Root's home
chmod 700 /root
chown root:root /root

# 5. SECURE BOOT
echo " (>) Securing /boot..."
# /boot files should be owned by root, this is generally safe.
chown -R root:root /boot
# Remove world and group permissions (Read/Write/Execute) for boot files
chmod -R og-rwx /boot

# 6. GLOBAL WORLD-WRITABLE SEARCH & DESTROY (SAFE MODE)
echo " (>) Hunting for World-Writable files..."

# ! FIX: Exclude symlinks (-type l). Changing perms on symlinks often fails or affects target.
# ! FIX: Added /proc /sys /dev /run /snap to excludes.
find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /snap -prune -o -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null

echo " (i) World-writable files patched."

# 7. FIX UNOWNED FILES
echo " (>) Fixing unowned files..."
# Only look in /home and /var/www to avoid breaking weird system files in /var/lib
find /home /var/www -nouser -o -nogroup -exec chown root:root {} + 2>/dev/null

# 8. RESTORE SUDO (SAFETY NET)
# Even with the fixes, we force-restore sudo just in case previous scripts broke it.
echo " (>) Verifying critical SUID binaries..."

# Fix Sudo
if [ -f /usr/bin/sudo ]; then
    chown root:root /usr/bin/sudo
    chmod 4755 /usr/bin/sudo
fi

# Fix Passwd (so users can change passwords)
if [ -f /usr/bin/passwd ]; then
    chown root:root /usr/bin/passwd
    chmod 4755 /usr/bin/passwd
fi

# Fix Su
if [ -f /usr/bin/su ]; then
    chown root:root /usr/bin/su
    chmod 4755 /usr/bin/su
fi

# 9. SUDOERS PERMISSIONS
echo " (>) Securing sudoers..."
chmod 440 /etc/sudoers
# Ensure the directory is root-only access
chmod 750 /etc/sudoers.d
chmod 440 /etc/sudoers.d/* 2>/dev/null

echo "(!) PERMISSION HARDENING COMPLETE."
echo "(!) SUID bits for sudo, passwd, and su have been verified."

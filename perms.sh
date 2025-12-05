#!/bin/bash

# --- CYBERPATRIOT FILESYSTEM PERMISSION HARDENER ---
# TARGETS: Linux Mint 21, Ubuntu 22.04/24.04
# USE WITH CAUTION.

echo "(!) STARTING PERMISSION HARDENING..."
echo "(!) This script removes world-write access and secures critical paths."

# 1. FIX CRITICAL "STICKY BIT" DIRECTORIES FIRST
# If these are wrong, the system breaks. We fix them to standard secure defaults.
echo " (>) Fixing /tmp and /var/tmp (1777)..."
chmod 1777 /tmp
chmod 1777 /var/tmp
chown root:root /tmp
chown root:root /var/tmp

# 2. SECURE SYSTEM BINARIES (Binaries should typically be 755, root:root)
# Attackers often make /bin/ls world writable to replace it with malware.
echo " (>) Locking down system binary directories..."
SYS_DIRS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/lib" "/lib64" "/usr/lib")

for dir in "${SYS_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        # Ensure root ownership
        chown -R root:root "$dir"
        # Remove write access for Group and Others (go-w)
        # We use 'chmod -R go-w' instead of setting specific numbers to preserve existing execute bits.
        chmod -R go-w "$dir"
    fi
done

# 3. SECURE CONFIGURATION (/etc)
echo " (>) Locking down /etc configuration..."
# /etc should be readable, but ONLY root should write to it.
chown -R root:root /etc
chmod -R go-w /etc

# Fix specific critical files that need tighter permissions
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 640 /etc/shadow   # Shadow must be 640 (root:shadow)
chmod 640 /etc/gshadow
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || chown root:root /etc/shadow

# 4. SECURE HOME DIRECTORIES
echo " (>) Securing User Home Directories..."
# Users should not be able to write to other users' folders.
# Loop through all real users in /home
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        user_name=$(basename "$user_home")
        
        # 1. Ensure the user owns their own home
        chown -R "$user_name":"$user_name" "$user_home"
        
        # 2. Lock the directory itself (750: User RWX, Group RX, World None)
        chmod 750 "$user_home"
        
        # 3. Recursively remove World permissions inside the home folder
        # This fixes "777" files users might have created
        chmod -R o-rwx "$user_home"
        
        echo "     - Secured /home/$user_name"
    fi
done

# Secure Root's home
chmod 700 /root
chown root:root /root

# 5. SECURE BOOT (Kernel & Grub)
echo " (>) Securing /boot..."
chown -R root:root /boot
chmod -R go-w /boot
chmod 700 /boot/grub 2>/dev/null || true
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

# 6. GLOBAL WORLD-WRITABLE SEARCH & DESTROY
# This finds ANY file on the system (excluding special dirs) that is World Writable and fixes it.
echo " (>) Hunting for World-Writable files (0002)..."

# Exclude /proc, /sys, /dev (virtual FS), /run, /tmp, /var/tmp, /var/lib (often needs write), /snap
EXCLUDES="( -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /tmp -prune -o -path /var/tmp -prune -o -path /var/lib -prune -o -path /var/crash -prune -o -path /snap -prune )"

# Find files (-type f) that are world writable (-perm -0002) and remove that permission
find / $EXCLUDES -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null
# Do the same for directories, but keep execute bit if it exists
find / $EXCLUDES -type d -perm -0002 -exec chmod o-w {} + 2>/dev/null

echo " (i) World-writable files patched."

# 7. FIX UNOWNED FILES
# Files with no user are often artifacts of deleted malicious users. Give them to root.
echo " (>) Fixing unowned files..."
find / $EXCLUDES \( -nouser -o -nogroup \) -exec chown root:root {} + 2>/dev/null

# 8. RESTORE SUDO (The one thing we might have broken)
# Sudo needs the SUID bit (4755). If we accidentally stripped it, we put it back.
echo " (>) Verifying sudo permissions..."
chmod 4755 /usr/bin/sudo 2>/dev/null || chmod 4755 /bin/sudo
chown root:root /usr/bin/sudo 2>/dev/null || chown root:root /bin/sudo

# 9. SPECIAL UBUNTU 24 / MINT 21 FIXES
echo " (>) Applying distro-specific hardening..."
# Secure profile.d (often target of persistence)
chmod 644 /etc/profile.d/* 2>/dev/null
chown root:root /etc/profile.d/* 2>/dev/null

# Secure sudoers
chmod 440 /etc/sudoers
chmod 750 /etc/sudoers.d
chmod 440 /etc/sudoers.d/* 2>/dev/null

echo "(!) FILESYSTEM PERMISSION RESET COMPLETE."
echo "(!) Please reboot to ensure all services handle the changes correctly."

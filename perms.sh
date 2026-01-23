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

echo " (>) Securing binaries safely (preserving SUID)..."
for dir in "${SYS_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        # Remove world-write, but DO NOT touch SUID (4000) or SGID (2000) bits
        find "$dir" -perm /0002 -type f -exec chmod o-w {} +
        find "$dir" -perm /0020 -type f -exec chmod g-w {} +
        chown -R root:root "$dir"
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
echo " (>) Fixing Shadow integrity..."
chown root:shadow /etc/shadow /etc/gshadow
chmod 640 /etc/shadow /etc/gshadow

# 4. SECURE HOME DIRECTORIES
echo " (>) Securing User Home Directories..."
# Get only users with UID 1000-60000
awk -F: '($3 >= 1000 && $3 < 60000) {print $1 ":" $6}' /etc/passwd | while read -r line; do
    user_name=$(echo "$line" | cut -d: -f1)
    user_home=$(echo "$line" | cut -d: -f2)

    if [ -d "$user_home" ]; then
        chown -R "$user_name":"$user_name" "$user_home"
        chmod 750 "$user_home"
        # Secure ssh folders if they exist
        if [ -d "$user_home/.ssh" ]; then
            chmod 700 "$user_home/.ssh"
            chmod 600 "$user_home/.ssh/"* 2>/dev/null
        fi
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
echo "--- SUID/SGID AUDIT (Potential Backdoors) ---"
# List all SUID/SGID files. Standard ones are in /bin, /sbin, /usr. 
# Anything in /tmp, /var, or /home is 99% a backdoor.
find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/snap/*" 2>/dev/null | while read -r file; do
    case "$file" in
        /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/lib/*|/usr/lib/*)
            # Likely legitimate, but check for weird names
            ;;
        *)
            echo " [!!!] SUSPICIOUS SUID FILE: $file"
            # Optional: Remove SUID bit automatically
            # chmod u-s "$file"
            ;;
    esac
done
# Secure sudoers
chmod 440 /etc/sudoers
chmod 750 /etc/sudoers.d
chmod 440 /etc/sudoers.d/* 2>/dev/null

echo "(!) FILESYSTEM PERMISSION RESET COMPLETE."
echo "(!) Please reboot to ensure all services handle the changes correctly."

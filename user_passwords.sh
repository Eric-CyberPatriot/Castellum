#!/bin/bash

# ===============================================
# CYBERPATRIOT LINUX PASSWORD HARDENING SCRIPT
# Sets a strong, uniform password for a list of users.
#
# USAGE: Run as root: sudo ./harden_passwords.sh
# ===============================================

# --- Configuration Section ---

# The strong password to be set for all specified users.
# Hardening Tip: For full CyberPatriot points, ensure your password is 14+ characters long!
NEW_PASSWORD="Cyb3rPatri0tsPass!"

# List of users whose passwords you want to change.
# Add or remove usernames as required by the competition image.
# Example: root, administrator, and any unsecure users found.
USER_LIST=(
    "user1"
    "unsecureuser"
    "student"
    "backup_admin"
    "root" # Always secure the root account
)

# --- Script Execution ---

echo "--- CyberPatriot User Password Reset Utility ---"

# Check if the script is being run as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root. Please use 'sudo ./harden_passwords.sh'"
    exit 1
fi

echo "The new password for all specified users will be: ${NEW_PASSWORD}"
echo "------------------------------------------------"

# Loop through the list of users and check if they exist
for USER in "${USER_LIST[@]}"; do
    if id "$USER" &>/dev/null; then
        # If the user exists, change their password
        echo "Resetting password for user: ${USER}"
        echo "${NEW_PASSWORD}" | passwd --stdin "$USER"
        
        # Check the exit status of the passwd command
        if [ $? -eq 0 ]; then
            echo "SUCCESS: Password for ${USER} has been set successfully."
        else
            echo "ERROR: Failed to set password for ${USER}. This could be due to password complexity policies."
        fi
    else
        echo "WARNING: User '${USER}' does not exist on this system. Skipping."
    fi
done

echo "------------------------------------------------"
echo "--- Script Complete ---"

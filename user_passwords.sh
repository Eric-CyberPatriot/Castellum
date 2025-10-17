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

# Create a temporary file to hold the username:password pairs
# The mktemp command creates a secure, temporary filename
PASSWORD_FILE=$(mktemp)

# Loop through the list of users and check if they exist
for USER in "${USER_LIST[@]}"; do
    if id "$USER" &>/dev/null; then
        # If the user exists, add the username:password pair to the file
        echo "Preparing to reset password for user: ${USER}"
        echo "${USER}:${NEW_PASSWORD}" >> "$PASSWORD_FILE"
    else
        echo "WARNING: User '${USER}' does not exist on this system. Skipping."
    fi
done

echo "------------------------------------------------"

# Use 'chpasswd' to non-interactively set the passwords from the file.
# NOTE: The problematic '-c' flag was removed for compatibility.
echo "Applying passwords using chpasswd..."
chpasswd < "$PASSWORD_FILE"

# Check the exit status of the chpasswd command
if [ $? -eq 0 ]; then
    echo "SUCCESS: Passwords have been set successfully for all existing users."
else
    echo "ERROR: An error occurred while running chpasswd. Please check the logs."
fi

# Clean up the temporary file containing the plaintext passwords (Crucial Security Step)
rm -f "$PASSWORD_FILE"

echo "--- Script Complete ---"

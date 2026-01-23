#!/bin/bash

# --- CONFIGURE THESE VALUES ---
USERS=("alice" "bob" "charlie")   # Put your usernames here
NEWPASS="Cyb3rPatri0tsPass!"         # Password you want all users to have
# --------------------------------

# Require root
if [[ $EUID -ne 0 ]]; then
    echo "You must run this script with sudo or as root."
    exit 1
fi

# Loop through the users
for user in "${USERS[@]}"; do

    # Check if user exists
    if id "$user" &>/dev/null; then
        echo "$user:$NEWPASS" | chpasswd
        chage -d 0 "$user"    # Forces password change at next login
        echo "Updated password and forced reset for: $user"
    else
        echo "User does not exist: $user"
    fi

done

echo "All done!"

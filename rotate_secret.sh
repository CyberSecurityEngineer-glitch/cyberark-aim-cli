#!/bin/bash
# Simulated PAM credential rotation script

VAULT_FILE="vault.enc"
LOG_FILE="rotation.log"
PASSPHRASE="demo-passphrase"

# Generate a new random password
NEW_PASS=$(openssl rand -base64 16)

# Encrypt and store it (simulates vault storage)
echo "$NEW_PASS" | openssl enc -aes-256-cbc -salt -pbkdf2 \
  -pass pass:"$PASSPHRASE" -out "$VAULT_FILE"

# Audit log entry
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") - credential rotated" >> "$LOG_FILE"

echo "Rotation complete. New secret stored in $VAULT_FILE"

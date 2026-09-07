#!/bin/bash

# Configuration
REPO_API="https://api.github.com/repos/rf-peixoto/phishing_pot/contents/email"
RAW_BASE_URL="https://raw.githubusercontent.com/rf-peixoto/phishing_pot/main/email"
HISTORY_FILE="/var/log/phish_sim_history.txt"
TARGET_DIR="/home/client01/Maildir/new"

# Ensure history file exists
sudo touch "$HISTORY_FILE"

echo "[*] Querying GitHub API for available .eml samples..."
ALL_SAMPLES=$(curl -sSL "$REPO_API" | jq -r '.[].name | select(endswith(".eml"))')

if [ -z "$ALL_SAMPLES" ]; then
echo "[-] Error: Unable to fetch repository contents or no .eml files found."
exit 1
fi

# Filter out previously delivered files
UNSENT_SAMPLES=()
for file in $ALL_SAMPLES; do
if ! grep -qxE "$file" "$HISTORY_FILE"; then
    UNSENT_SAMPLES+=("$file")
fi
done

TOTAL_AVAILABLE=${#UNSENT_SAMPLES[@]}

if [ "$TOTAL_AVAILABLE" -eq 0 ]; then
echo "[!] All available .eml samples in the repository have already been injected!"
echo "[!] Reset history with: sudo > $HISTORY_FILE"
exit 0
fi

# Select a random sample from remaining uninspected pool
SELECTED_SAMPLE=$(printf "%s\n" "${UNSENT_SAMPLES[@]}" | shuf -n 1)

echo "[+] Selected unread sample: ${SELECTED_SAMPLE} (${TOTAL_AVAILABLE} remaining in pool)"

# Download and deliver
TMP_FILE="/tmp/${SELECTED_SAMPLE}"
curl -sSL -o "$TMP_FILE" "${RAW_BASE_URL}/${SELECTED_SAMPLE}"

if [ ! -s "$TMP_FILE" ]; then
echo "[-] Error: Failed to download ${SELECTED_SAMPLE}."
rm -f "$TMP_FILE"
exit 1
fi

# Set ownership and permissions before moving into place
chown client01:client01 "$TMP_FILE"
chmod 600 "$TMP_FILE"

MSG_ID="$(date +%s).Vfc00I1605f6M$(shuf -i 100000-999999 -n 1).wazuhserver"
mv "$TMP_FILE" "${TARGET_DIR}/${MSG_ID}"

# Log to history
echo "$SELECTED_SAMPLE" >> "$HISTORY_FILE"

echo "[+] Successfully injected ${SELECTED_SAMPLE} into client01's Inbox!"
EOF
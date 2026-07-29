#!/bin/bash

set -e

RED="\033[0;31m"
GREEN="\033[0;32m"
NC="\033[0m"

echo "[+] Checking dependencies..."

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}[ERROR] $1 is not installed.${NC}"
        return 1
    else
        echo -e "${GREEN}[OK] $1 is installed.${NC}"
    fi
}

DEPENDENCIES=("git" "bash" "ping")
MISSING=0

for dep in "${DEPENDENCIES[@]}"; do
    if ! check_command "$dep"; then
        MISSING=1
    fi
done

if [ $MISSING -eq 1 ]; then
    exit 1
fi

echo "[+] Checking internet connection..."
if ! ping -c 1 github.com &> /dev/null; then
    echo -e "${RED}[ERROR] No internet connection or github.com unreachable.${NC}"
    exit 1
fi
echo -e "${GREEN}[OK] Internet available.${NC}"

TARGET_DIR="/data"
git config --global --add safe.directory "$TARGET_DIR"

# If data already exists, skip cloning
if [ -d "$TARGET_DIR/CVE-2025" ] || [ -d "$TARGET_DIR/CVE-2026" ]; then
    echo "[+] CVE data already exists in $TARGET_DIR. Skipping clone."
    exit 0
fi

# Clean up broken/partial Git clones if present
if [ -d "$TARGET_DIR/.git" ]; then
    echo "[!] Cleaning up previous incomplete git checkout..."
    rm -rf "$TARGET_DIR/.git"
fi

echo "[+] Cloning NVD JSON feeds into $TARGET_DIR..."

cd "$TARGET_DIR"

git clone --depth 1 --filter=blob:none --no-checkout \
https://github.com/fkie-cad/nvd-json-data-feeds.git .

echo "[+] Configuring sparse checkout..."
git sparse-checkout init --cone
git sparse-checkout set CVE-2025 CVE-2026

echo "[+] Downloading selected CVE files..."
git checkout main

echo -e "${GREEN}[DONE] NVD CVE files downloaded successfully.${NC}"
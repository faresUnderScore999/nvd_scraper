#!/bin/bash

set -e

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
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

# ---------------------------------------------------------------------------
# Configure git for stable large transfers.
# The nvd-json-data-feeds repo is huge; HTTP/2 often causes
# "curl 16 Error in the HTTP2 framing layer" / broken pipe failures.
# HTTP/1.1 with a large post buffer is far more reliable for this.
# ---------------------------------------------------------------------------
echo "[+] Configuring git for reliable large transfers..."
git config --global http.version HTTP/1.1
git config --global http.postBuffer 524288000
git config --global http.lowSpeedLimit 1000
git config --global http.lowSpeedTime 60
echo -e "${GREEN}[OK] Git configured (HTTP/1.1, postBuffer=500MB).${NC}"

# ---------------------------------------------------------------------------
# Configurable CVE years (space-separated), e.g.:
#   NVD_YEARS="2005 2006 2026"
# Default: "2024 2025 2026"
# ---------------------------------------------------------------------------
DEFAULT_YEARS="2024 2025 2026"
NVD_YEARS="${NVD_YEARS:-$DEFAULT_YEARS}"

# Normalize: ensure no leading/trailing whitespace, single spaces between years
NVD_YEARS=$(echo "$NVD_YEARS" | tr -s '[:space:]' ' ' | sed 's/^ //; s/ $//')

# Build the list of CVE directory names, e.g. "CVE-2024 CVE-2025 CVE-2026"
CVE_DIRS=""
for year in $NVD_YEARS; do
    CVE_DIRS="$CVE_DIRS CVE-$year"
done
CVE_DIRS=$(echo "$CVE_DIRS" | sed 's/^ //')

echo -e "${YELLOW}[+] Selected CVE years: ${NVD_YEARS}${NC}"
echo -e "${YELLOW}[+] Expected directories: ${CVE_DIRS}${NC}"

# ---------------------------------------------------------------------------
# Determine whether to (re)use the existing git repo or do a fresh clone
# ---------------------------------------------------------------------------
NEED_CLONE=0
if [ ! -d "$TARGET_DIR/.git" ]; then
    NEED_CLONE=1
    echo "[+] No existing git repo found. Will perform a fresh clone."
else
    echo "[+] Existing git repo found. Will reuse it and just update the sparse-checkout."
fi

# If we need a fresh clone, clean up any partial data first
if [ $NEED_CLONE -eq 1 ]; then
    echo "[!] Cleaning up previous incomplete data..."
    if [ -d "$TARGET_DIR" ]; then
        find "$TARGET_DIR" -mindepth 1 -maxdepth 1 ! -name '.' ! -name '..' -exec rm -rf {} +
    fi
    echo "[+] Cloning NVD JSON feeds into $TARGET_DIR..."
    cd "$TARGET_DIR"
    git clone --depth 1 --filter=blob:none --no-checkout \
    https://github.com/fkie-cad/nvd-json-data-feeds.git .
fi

cd "$TARGET_DIR"

echo "[+] Configuring sparse checkout..."
git sparse-checkout init --cone
git sparse-checkout set $CVE_DIRS

echo "[+] Downloading selected CVE files..."
MAX_RETRIES=3
ATTEMPT=1
CHECKOUT_OK=0

while [ $ATTEMPT -le $MAX_RETRIES ]; do
    echo "[+] git checkout attempt $ATTEMPT/$MAX_RETRIES..."
    if git checkout main; then
        CHECKOUT_OK=1
        break
    fi
    echo "[!] Checkout failed (attempt $ATTEMPT/$MAX_RETRIES). Retrying in $((ATTEMPT * 10))s..."
    sleep $((ATTEMPT * 10))
    ATTEMPT=$((ATTEMPT + 1))
done

if [ $CHECKOUT_OK -ne 1 ]; then
    echo -e "${RED}[ERROR] git checkout failed after $MAX_RETRIES attempts.${NC}"
    exit 1
fi

# Verify that all requested year directories exist after checkout
echo "[+] Verifying downloaded directories..."
MISSING_DIRS=""
for dir in $CVE_DIRS; do
    if [ ! -d "$TARGET_DIR/$dir" ]; then
        MISSING_DIRS="$MISSING_DIRS $dir"
    fi
done

if [ -n "$MISSING_DIRS" ]; then
    echo -e "${RED}[ERROR] The following directories were not found after checkout:${MISSING_DIRS}${NC}"
    exit 1
fi

echo -e "${GREEN}[DONE] NVD CVE files downloaded successfully.${NC}"
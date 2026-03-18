#!/usr/bin/env bash
# Download / update the t4d PhishingKit-Yara-Rules into rules/t4d/.
#
# Source: https://github.com/t4d/PhishingKit-Yara-Rules
#
# Usage:
#   ./scripts/update_yara_rules.sh          # fresh clone or pull update
#   ./scripts/update_yara_rules.sh --force  # delete and re-clone
#
set -euo pipefail

REPO_URL="https://github.com/t4d/PhishingKit-Yara-Rules.git"
RULES_DIR="$(cd "$(dirname "$0")/.." && pwd)/rules/t4d"

if [[ "${1:-}" == "--force" ]] && [[ -d "$RULES_DIR" ]]; then
    echo "[*] Removing existing rules at $RULES_DIR"
    rm -rf "$RULES_DIR"
fi

if [[ -d "$RULES_DIR/.git" ]]; then
    echo "[*] Updating existing t4d rules in $RULES_DIR"
    git -C "$RULES_DIR" pull --ff-only
else
    echo "[*] Cloning t4d PhishingKit-Yara-Rules into $RULES_DIR"
    git clone --depth 1 "$REPO_URL" "$RULES_DIR"
fi

RULE_COUNT=$(find "$RULES_DIR" -name '*.yar' | wc -l)
echo "[+] Done — $RULE_COUNT YARA rules available in $RULES_DIR"

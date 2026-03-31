#!/usr/bin/env sh
set -eu

REPO_RAW="https://raw.githubusercontent.com/noahsark/axios-compromise-scanner/main"
TARGET_DIR="${HOME}/.local/bin"
TARGET_FILE="${TARGET_DIR}/axios-scan"

mkdir -p "${TARGET_DIR}"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "${REPO_RAW}/scan.py" -o "${TARGET_FILE}"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "${TARGET_FILE}" "${REPO_RAW}/scan.py"
else
  printf "Error: curl or wget is required.\n" >&2
  exit 1
fi

chmod +x "${TARGET_FILE}"

printf "Installed axios-scan to %s\n" "${TARGET_FILE}"
printf "Run: axios-scan\n"
printf "If command is not found, add %s to PATH.\n" "${TARGET_DIR}"

#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/azul_plugin_retrohunt"
OUTPUT_BINARY="${OUTPUT_DIR}/yr"

echo "[+] Installing/updating Rust toolchain"

if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
fi

rustup self update
rustup update stable
rustup default stable

echo "[+] Querying latest YARA-X release"

LATEST_TAG=$(
    curl -fsSL \
        https://api.github.com/repos/VirusTotal/yara-x/releases/latest \
    | grep '"tag_name"' \
    | sed -E 's/.*"([^"]+)".*/\1/'
)

if [[ -z "${LATEST_TAG}" ]]; then
    echo "[!] Failed to determine latest release"
    exit 1
fi

echo "[+] Latest release: ${LATEST_TAG}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

cd "$WORKDIR"

echo "[+] Cloning YARA-X"
git clone \
    --branch "${LATEST_TAG}" \
    --depth 1 \
    https://github.com/VirusTotal/yara-x.git

cd yara-x

echo "[+] Building YARA-X CLI with debug-cmd feature"

cargo build \
    --release \
    -p yara-x-cli \
    --features debug-cmd

BIN_PATH="target/release/yr"

if [[ ! -f "${BIN_PATH}" ]]; then
    echo "[!] Binary not found at ${BIN_PATH}"
    exit 1
fi

echo "[+] Copying binary to ${OUTPUT_BINARY}"
cp "${BIN_PATH}" "${OUTPUT_BINARY}"
chmod +x "${OUTPUT_BINARY}"

echo
echo "[+] Done"
echo "[+] Binary location: ${OUTPUT_BINARY}"
echo "[+] Version:"
"${OUTPUT_BINARY}" --version || true
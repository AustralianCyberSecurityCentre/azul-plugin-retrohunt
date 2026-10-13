#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/azul_plugin_retrohunt"
OUTPUT_BINARY="${OUTPUT_DIR}/yr"

# Pinned YARA-X version for reproducible builds.
# Update this manually after reviewing upstream changes.
# Anything before v1.21.0 does not have the debug command to view atoms so will not work.
YARAX_VERSION="v1.21.0"

echo "[+] Checking Rust toolchain"

if ! command -v cargo >/dev/null 2>&1; then
    echo "[!] Rust toolchain not found"
    echo
    echo "Install Rust before running this script."
    echo "Recommended:"
    echo "  https://www.rust-lang.org/tools/install"
    echo
    echo "Verify installation:"
    echo "  cargo --version"
    echo "  rustc --version"
    exit 1
fi

echo "[+] Using pinned YARA-X version: ${YARAX_VERSION}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

cd "$WORKDIR"

echo "[+] Cloning YARA-X"

git clone \
    --branch "${YARAX_VERSION}" \
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

mkdir -p "${OUTPUT_DIR}"

echo "[+] Copying binary to ${OUTPUT_BINARY}"

cp "${BIN_PATH}" "${OUTPUT_BINARY}"
chmod +x "${OUTPUT_BINARY}"

echo
echo "[+] Done"
echo "[+] Binary location: ${OUTPUT_BINARY}"
echo "[+] Version:"
"${OUTPUT_BINARY}" --version || true
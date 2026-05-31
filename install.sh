#!/usr/bin/env bash
# Pentora install script — installs all required tools on Kali/Debian/Ubuntu
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

ok()   { echo -e "${GREEN}[ok]${RESET} $1"; }
fail() { echo -e "${RED}[fail]${RESET} $1"; }
info() { echo -e "${BOLD}[info]${RESET} $1"; }

# --- Python / pip ---
info "Installing Pentora Python package..."
pip3 install --break-system-packages -e . 2>/dev/null || pip3 install -e .
ok "pentora installed"

# --- Go tools ---
info "Installing Go tools..."
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/PentestPad/subzy@latest"
)
if command -v go &>/dev/null; then
    for pkg in "${GO_TOOLS[@]}"; do
        name=$(basename "${pkg%%@*}")
        if command -v "$name" &>/dev/null; then
            ok "$name already installed"
        else
            go install "$pkg" && ok "$name" || fail "$name"
        fi
    done
else
    fail "go not found — skipping Go tools (install Go 1.21+)"
fi

# --- Pip tools ---
info "Installing pip tools..."
PIP_TOOLS=(arjun paramspider xsstrike commix wafw00f Sublist3r theHarvester tplmap)
for tool in "${PIP_TOOLS[@]}"; do
    pip3 install --break-system-packages "$tool" 2>/dev/null || pip3 install "$tool" || fail "$tool"
done
ok "pip tools installed"

# --- nuclei templates ---
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates && ok "nuclei templates updated" || fail "nuclei templates update"
fi

info "Run 'pentora doctor' to verify all tools are accessible."

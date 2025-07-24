#!/bin/bash

# ShadowMadow Quick Deploy
# Ultra-fast deployment script for immediate setup

set -e

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         ShadowMadow Quick Deploy         ║${NC}"
echo -e "${BLUE}║        Instant Secure WiFi Hotspot       ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
echo ""

# Check if install.sh exists
if [[ ! -f "install.sh" ]]; then
    echo -e "${YELLOW}install.sh not found. Downloading...${NC}"
    curl -fsSL https://raw.githubusercontent.com/yourusername/shadowmadow/main/install.sh -o install.sh
    chmod +x install.sh
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}Elevating to root privileges...${NC}"
    sudo bash install.sh
else
    bash install.sh
fi

echo ""
echo -e "${GREEN}🚀 Quick Deploy Complete!${NC}"
echo ""
echo -e "${YELLOW}Your secure WiFi hotspot is ready:${NC}"
echo -e "  📶 Network: ${GREEN}ShadowMadow-Hotspot${NC}"
echo -e "  🔐 Password: ${GREEN}ShadowMadow123${NC}"
echo -e "  🌐 Gateway: ${GREEN}192.168.4.1${NC}"
echo ""
echo -e "${YELLOW}Management commands:${NC}"
echo -e "  ${GREEN}shadowmadow status${NC}  - Check system status"
echo -e "  ${GREEN}shadowmadow restart${NC} - Restart if needed"
echo ""
echo -e "${BLUE}🔒 All connected device traffic is now encrypted via Shadowsocks!${NC}"

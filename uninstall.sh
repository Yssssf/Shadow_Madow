#!/bin/bash

# ShadowMadow Uninstaller
# Completely removes ShadowMadow and restores system to original state

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                 ShadowMadow Uninstaller                      ║${NC}"
echo -e "${BLUE}║            Removing all components and configs               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Confirm uninstallation
echo -e "${YELLOW}This will completely remove ShadowMadow and all its components.${NC}"
echo -e "${YELLOW}Are you sure you want to continue? (yes/no)${NC}"
read -r response

if [[ "$response" != "yes" ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

print_status "Stopping all ShadowMadow services..."

# Stop services
SERVICES=("shadowmadow-server" "shadowmadow-client" "shadowmadow-proxy" "hostapd" "dnsmasq")
for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$service"; then
        systemctl stop "$service"
        print_success "Stopped $service"
    fi
done

print_status "Disabling services..."

# Disable services
for service in "${SERVICES[@]}"; do
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        systemctl disable "$service"
        print_success "Disabled $service"
    fi
done

print_status "Removing service files..."

# Remove systemd service files
rm -f /etc/systemd/system/shadowmadow-*.service
systemctl daemon-reload
print_success "Removed systemd service files"

print_status "Removing configuration files..."

# Remove configuration directories and files
rm -rf /etc/shadowsocks
rm -f /etc/hostapd/hostapd.conf.shadowmadow
rm -f /etc/dnsmasq.conf.shadowmadow
print_success "Removed configuration files"

print_status "Removing scripts and binaries..."

# Remove scripts
rm -f /opt/shadowmadow-proxy.py
rm -f /usr/local/bin/shadowmadow
rm -f /etc/init.d/shadowmadow-routing
print_success "Removed scripts and binaries"

print_status "Cleaning up network configuration..."

# Remove static IP configuration from dhcpcd.conf
if grep -q "# ShadowMadow hotspot interface" /etc/dhcpcd.conf; then
    sed -i '/# ShadowMadow hotspot interface/,/nohook wpa_supplicant/d' /etc/dhcpcd.conf
    print_success "Removed static IP configuration"
fi

# Restore original dnsmasq and hostapd configs if they exist
if [[ -f /etc/dnsmasq.conf.orig ]]; then
    mv /etc/dnsmasq.conf.orig /etc/dnsmasq.conf
    print_success "Restored original dnsmasq configuration"
fi

if [[ -f /etc/hostapd/hostapd.conf.orig ]]; then
    mv /etc/hostapd/hostapd.conf.orig /etc/hostapd/hostapd.conf
    print_success "Restored original hostapd configuration"
fi

print_status "Clearing iptables rules..."

# Clear iptables rules
iptables -t nat -F
iptables -F
iptables -X

# Remove IP forwarding (optional - user may want to keep this)
echo -e "${YELLOW}Do you want to disable IP forwarding? (yes/no)${NC}"
read -r forward_response

if [[ "$forward_response" == "yes" ]]; then
    sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=0
    print_success "Disabled IP forwarding"
fi

print_status "Resetting network interfaces..."

# Reset WiFi interface
WIFI_INTERFACE=""
for iface in wlan0 wlan1; do
    if ip link show $iface 2>/dev/null | grep -q "state"; then
        WIFI_INTERFACE=$iface
        break
    fi
done

if [[ -n "$WIFI_INTERFACE" ]]; then
    # Remove the static IP
    ip addr del 192.168.4.1/24 dev $WIFI_INTERFACE 2>/dev/null || true
    print_success "Reset $WIFI_INTERFACE interface"
fi

print_status "Cleaning up packages (optional)..."

echo -e "${YELLOW}Do you want to remove Shadowsocks and hostapd packages? (yes/no)${NC}"
read -r package_response

if [[ "$package_response" == "yes" ]]; then
    apt remove --purge -y shadowsocks-libev hostapd dnsmasq
    apt autoremove -y
    print_success "Removed packages"
fi

print_status "Restarting network services..."

# Restart networking
systemctl restart networking
systemctl restart dhcpcd

print_success "Network services restarted"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                 Uninstallation Complete                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}✅ ShadowMadow has been completely removed from your system.${NC}"
echo ""
echo -e "${YELLOW}What was removed:${NC}"
echo "  - All ShadowMadow services and configurations"
echo "  - Custom scripts and binaries"
echo "  - Network configuration changes"
echo "  - iptables rules"
echo ""
echo -e "${YELLOW}System state:${NC}"
echo "  - Your WiFi interface is back to normal operation"
echo "  - Original network configurations restored (if backups existed)"
echo "  - Standard system networking resumed"
echo ""
echo -e "${BLUE}Thank you for using ShadowMadow!${NC}"

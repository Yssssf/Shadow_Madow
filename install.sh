#!/bin/bash

# ShadowMadow - Complete Shadowsocks WiFi Hotspot Setup
# Single script installation for Raspberry Pi
# Version: 2.0 - Streamlined Edition

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    ShadowMadow Setup                        ║"
    echo "║        Secure Shadowsocks WiFi Hotspot for Raspberry Pi     ║"
    echo "║                     Version 2.0                             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Clean up any existing ShadowMadow processes and services
cleanup_existing() {
    print_status "Cleaning up any existing ShadowMadow installation..."
    
    # Stop all ShadowMadow services
    for service in shadowmadow-server shadowmadow-client shadowmadow-proxy; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            systemctl stop $service 2>/dev/null || true
        fi
    done
    
    # Wait for systemd to stop services
    sleep 5
    
    # Kill all related processes by name (multiple patterns)
    pkill -9 -f "ss-server" 2>/dev/null || true
    pkill -9 -f "ss-local" 2>/dev/null || true
    pkill -9 -f "shadowsocks" 2>/dev/null || true
    pkill -9 -f "shadowmadow-proxy" 2>/dev/null || true
    pkill -9 -f "python.*shadowmadow" 2>/dev/null || true
    
    # Wait for processes to die
    sleep 3
    
    # Ultra-aggressive port cleanup
    for port in 8388 1080 8080; do
        print_status "Forcefully clearing port $port..."
        
        # Get ALL processes using the port
        local pids=$(lsof -ti:$port 2>/dev/null || netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 || true)
        
        if [[ -n "$pids" ]]; then
            print_status "Found processes on port $port: $pids"
            # Kill with SIGTERM first
            echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
            sleep 2
            
            # Kill with SIGKILL
            echo "$pids" | xargs -r kill -9 2>/dev/null || true
            sleep 2
            
            # Double check with netstat and kill any remaining
            local remaining=$(netstat -tlnp 2>/dev/null | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 || true)
            if [[ -n "$remaining" ]]; then
                echo "$remaining" | xargs -r kill -9 2>/dev/null || true
            fi
        fi
    done
    
    # Final verification
    sleep 3
    for port in 8388 1080 8080; do
        if netstat -tln 2>/dev/null | grep -q ":$port "; then
            print_error "Port $port is still in use after aggressive cleanup!"
            netstat -tlnp 2>/dev/null | grep ":$port " || true
        else
            print_success "Port $port is now free"
        fi
    done
    
    print_success "Cleanup completed"
}

# Detect WiFi interface
detect_wifi_interface() {
    WIFI_INTERFACE=""
    for iface in wlan0 wlan1; do
        if ip link show $iface 2>/dev/null | grep -q "state"; then
            WIFI_INTERFACE=$iface
            break
        fi
    done
    
    if [[ -z "$WIFI_INTERFACE" ]]; then
        print_error "No WiFi interface found. Please ensure WiFi is available."
        exit 1
    fi
    
    print_success "Using WiFi interface: $WIFI_INTERFACE"
}

# Install required packages
install_packages() {
    print_status "Updating system and installing packages..."
    
    apt update && apt upgrade -y
    
    # Install core packages
    apt install -y \
        hostapd \
        dnsmasq \
        iptables-persistent \
        shadowsocks-libev \
        python3 \
        python3-socks \
        python3-requests \
        curl \
        openssl \
        rfkill \
        iw \
        wireless-tools \
        net-tools \
        iproute2 \
        lsof \
        psmisc \
        netstat-nat
        
    # Stop any conflicting services
    systemctl stop wpa_supplicant 2>/dev/null || true
    systemctl disable wpa_supplicant 2>/dev/null || true
    
    # Handle hostapd service properly - unmask if needed
    print_status "Configuring hostapd service..."
    if systemctl is-enabled hostapd 2>&1 | grep -q "masked"; then
        print_status "Unmasking hostapd service..."
        systemctl unmask hostapd
    fi
    
    # Remove any existing hostapd service symlinks that might cause issues
    rm -f /etc/systemd/system/hostapd.service 2>/dev/null || true
    systemctl daemon-reload
    
    print_success "All packages installed"
}

# Generate Shadowsocks configuration
setup_shadowsocks() {
    print_status "Setting up Shadowsocks..."
    
    # Create directory
    mkdir -p /etc/shadowsocks
    
    # Generate password
    SHADOWSOCKS_PASSWORD=$(openssl rand -base64 32)
    
    # Server config
    cat > /etc/shadowsocks/server.json << EOF
{
    "server": "127.0.0.1",
    "server_port": 8388,
    "password": "$SHADOWSOCKS_PASSWORD",
    "method": "aes-256-gcm",
    "timeout": 300,
    "fast_open": false
}
EOF

    # Client config
    cat > /etc/shadowsocks/client.json << EOF
{
    "server": "127.0.0.1",
    "server_port": 8388,
    "local_address": "127.0.0.1",
    "local_port": 1080,
    "password": "$SHADOWSOCKS_PASSWORD",
    "method": "aes-256-gcm",
    "timeout": 300
}
EOF

    # Set permissions
    chmod 644 /etc/shadowsocks/*.json
    chown root:root /etc/shadowsocks/*.json
    
    print_success "Shadowsocks configured with password: ${SHADOWSOCKS_PASSWORD:0:12}..."
    echo "$SHADOWSOCKS_PASSWORD" > /etc/shadowsocks/.password
}

# Create HTTP proxy
setup_http_proxy() {
    print_status "Creating HTTP proxy..."
    
    cat > /opt/shadowmadow-proxy.py << 'EOF'
#!/usr/bin/env python3
"""
ShadowMadow HTTP Proxy - Converts SOCKS5 to HTTP
"""
import socket
import threading
import socks
import time

class HTTPProxy:
    def __init__(self, local_port=8080, socks_host='127.0.0.1', socks_port=1080):
        self.local_port = local_port
        self.socks_host = socks_host
        self.socks_port = socks_port
        
    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096)
            if not request:
                return
                
            request_str = request.decode('utf-8', errors='ignore')
            lines = request_str.split('\n')
            
            if not lines:
                return
                
            first_line = lines[0].strip()
            parts = first_line.split(' ')
            
            if len(parts) < 3:
                return
                
            method, url, version = parts[0], parts[1], parts[2]
            
            if method == 'CONNECT':
                # HTTPS tunnel
                host_port = url
                if ':' in host_port:
                    host, port = host_port.split(':', 1)
                    port = int(port)
                else:
                    host = host_port
                    port = 443
                    
                try:
                    remote_socket = socks.socksocket()
                    remote_socket.set_proxy(socks.SOCKS5, self.socks_host, self.socks_port)
                    remote_socket.connect((host, port))
                    
                    client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                    self.tunnel_data(client_socket, remote_socket)
                    
                except Exception as e:
                    client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    
            else:
                # HTTP request
                host = None
                port = 80
                
                for line in lines:
                    if line.lower().startswith('host:'):
                        host_header = line.split(':', 1)[1].strip()
                        if ':' in host_header:
                            host, port_str = host_header.split(':', 1)
                            port = int(port_str)
                        else:
                            host = host_header
                        break
                
                if not host:
                    client_socket.send(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                    return
                
                try:
                    remote_socket = socks.socksocket()
                    remote_socket.set_proxy(socks.SOCKS5, self.socks_host, self.socks_port)
                    remote_socket.connect((host, port))
                    
                    remote_socket.send(request)
                    
                    while True:
                        data = remote_socket.recv(4096)
                        if not data:
                            break
                        client_socket.send(data)
                        
                except Exception as e:
                    client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    
        except Exception as e:
            pass
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def tunnel_data(self, client_socket, remote_socket):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.send(data)
            except:
                pass
                
        t1 = threading.Thread(target=forward, args=(client_socket, remote_socket))
        t2 = threading.Thread(target=forward, args=(remote_socket, client_socket))
        
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    
    def start(self):
        # Kill any existing processes using our port
        import os
        import subprocess
        try:
            # Kill any existing python processes using this port
            subprocess.run(["pkill", "-f", "shadowmadow-proxy"], stderr=subprocess.DEVNULL)
            time.sleep(1)
            
            # Kill any processes using port 8080
            result = subprocess.run(["lsof", "-ti:8080"], capture_output=True, text=True)
            if result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    try:
                        subprocess.run(["kill", "-9", pid], stderr=subprocess.DEVNULL)
                    except:
                        pass
            time.sleep(1)
        except:
            pass
            
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        # Try to bind with retries
        max_retries = 5
        for attempt in range(max_retries):
            try:
                server.bind(('0.0.0.0', self.local_port))
                break
            except OSError as e:
                if e.errno == 98 and attempt < max_retries - 1:  # Address already in use
                    print(f"Port {self.local_port} in use, retrying in {attempt + 1} seconds...")
                    time.sleep(attempt + 1)
                    # Try to kill any process using the port
                    import os
                    os.system(f"lsof -ti:{self.local_port} | xargs -r kill -9 2>/dev/null || true")
                    continue
                else:
                    raise
        
        try:
            server.listen(50)
            print(f"ShadowMadow HTTP Proxy listening on port {self.local_port}")
            
            while True:
                try:
                    client_socket, addr = server.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    print(f"Accept error: {e}")
                    time.sleep(1)
                        
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            server.close()

if __name__ == '__main__':
    proxy = HTTPProxy()
    proxy.start()
EOF

    chmod +x /opt/shadowmadow-proxy.py
    print_success "HTTP proxy created"
}

# Setup WiFi hotspot
setup_hotspot() {
    print_status "Configuring WiFi hotspot..."
    
    # hostapd configuration
    cat > /etc/hostapd/hostapd.conf << EOF
interface=$WIFI_INTERFACE
driver=nl80211
ssid=ShadowMadow-Hotspot
hw_mode=g
channel=6
ieee80211n=1
ignore_broadcast_ssid=0
macaddr_acl=0
auth_algs=1
wpa=2
wpa_passphrase=ShadowMadow123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wmm_enabled=1
max_num_sta=10
EOF

    # dnsmasq configuration
    cat > /etc/dnsmasq.conf << EOF
interface=$WIFI_INTERFACE
bind-interfaces
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
domain=local
address=/detectportal.firefox.com/192.168.4.1
address=/connectivity-check.ubuntu.com/192.168.4.1
address=/clients3.google.com/192.168.4.1
address=/connectivitycheck.gstatic.com/192.168.4.1
no-resolv
server=8.8.8.8
server=8.8.4.4
server=1.1.1.1
server=1.0.0.1
log-dhcp
cache-size=1000
neg-ttl=60
dhcp-authoritative
dhcp-option=option:router,192.168.4.1
dhcp-option=option:dns-server,192.168.4.1
EOF

    # Static IP configuration
    if [[ -f /etc/dhcpcd.conf ]]; then
        if ! grep -q "interface $WIFI_INTERFACE" /etc/dhcpcd.conf; then
            cat >> /etc/dhcpcd.conf << EOF

# ShadowMadow hotspot interface
interface $WIFI_INTERFACE
static ip_address=192.168.4.1/24
nohook wpa_supplicant
EOF
        fi
    else
        print_status "dhcpcd.conf not found, creating interface configuration manually..."
        # Create network interface configuration file
        cat > /etc/systemd/network/99-$WIFI_INTERFACE.network << EOF
[Match]
Name=$WIFI_INTERFACE

[Network]
Address=192.168.4.1/24
DHCPServer=no
EOF
    fi

    print_success "WiFi hotspot configured"
}

# Create systemd services
create_services() {
    print_status "Creating systemd services..."
    
    # Shadowsocks server service
    cat > /etc/systemd/system/shadowmadow-server.service << EOF
[Unit]
Description=ShadowMadow Shadowsocks Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks/server.json -v
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF

    # Shadowsocks client service
    cat > /etc/systemd/system/shadowmadow-client.service << EOF
[Unit]
Description=ShadowMadow Shadowsocks Client
After=network.target shadowmadow-server.service
Wants=shadowmadow-server.service
Requires=shadowmadow-server.service

[Service]
Type=simple
User=root
ExecStartPre=/bin/sleep 5
ExecStart=/usr/bin/ss-local -c /etc/shadowsocks/client.json -v
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF

    # HTTP proxy service
    cat > /etc/systemd/system/shadowmadow-proxy.service << EOF
[Unit]
Description=ShadowMadow HTTP Proxy
After=shadowmadow-client.service network.target
Wants=shadowmadow-client.service
Requires=shadowmadow-client.service

[Service]
Type=simple
User=root
ExecStartPre=/bin/sleep 3
ExecStart=/usr/bin/python3 /opt/shadowmadow-proxy.py
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

    print_success "Services created"
}

# Setup iptables rules
setup_iptables() {
    print_status "Configuring iptables..."
    
    cat > /etc/init.d/shadowmadow-routing << EOF
#!/bin/bash

start_routing() {
    # Clear existing rules
    iptables -t nat -F
    iptables -F

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Redirect HTTP/HTTPS to proxy
    iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --dport 80 -j REDIRECT --to-port 8080
    iptables -t nat -A PREROUTING -i $WIFI_INTERFACE -p tcp --dport 443 -j REDIRECT --to-port 8080

    # NAT for internet access
    for iface in eth0 wlan0; do
        if ip link show \$iface 2>/dev/null | grep -q "state UP"; then
            iptables -t nat -A POSTROUTING -o \$iface -j MASQUERADE
        fi
    done

    # Allow forwarding
    iptables -A FORWARD -i $WIFI_INTERFACE -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    echo "ShadowMadow routing started"
}

stop_routing() {
    iptables -t nat -F
    iptables -F
    echo "ShadowMadow routing stopped"
}

case "\$1" in
    start) start_routing ;;
    stop) stop_routing ;;
    restart) stop_routing; sleep 2; start_routing ;;
    *) echo "Usage: \$0 {start|stop|restart}"; exit 1 ;;
esac
EOF

    chmod +x /etc/init.d/shadowmadow-routing
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=1
    
    print_success "iptables configured"
}

# Configure network interfaces properly
configure_network() {
    print_status "Configuring network interfaces..."
    
    # Stop NetworkManager if it's interfering
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        systemctl stop NetworkManager
        systemctl disable NetworkManager
        print_status "Stopped NetworkManager to prevent interference"
    fi
    
    # Kill wpa_supplicant on our interface
    pkill -f "wpa_supplicant.*$WIFI_INTERFACE" 2>/dev/null || true
    
    # Ensure rfkill is not blocking
    rfkill unblock wifi 2>/dev/null || true
    
    # Wait for interface to be ready
    sleep 3
    
    print_success "Network interfaces configured"
}

# Create management script
create_management_script() {
    print_status "Creating management script..."
    
    cat > /usr/local/bin/shadowmadow << 'EOF'
#!/bin/bash

SERVICES=("shadowmadow-server" "shadowmadow-client" "shadowmadow-proxy" "hostapd" "dnsmasq")

start_shadowmadow() {
    echo "Starting ShadowMadow..."
    /etc/init.d/shadowmadow-routing start
    
    for service in "${SERVICES[@]}"; do
        systemctl start $service
        echo "Started $service"
    done
    
    echo "✓ ShadowMadow started!"
    echo "  SSID: ShadowMadow-Hotspot"
    echo "  Password: ShadowMadow123"
    echo "  IP: 192.168.4.1"
}

stop_shadowmadow() {
    echo "Stopping ShadowMadow..."
    
    for service in "${SERVICES[@]}"; do
        systemctl stop $service
        echo "Stopped $service"
    done
    
    /etc/init.d/shadowmadow-routing stop
    echo "✓ ShadowMadow stopped!"
}

status_shadowmadow() {
    echo "=== ShadowMadow Status ==="
    for service in "${SERVICES[@]}"; do
        status=$(systemctl is-active $service)
        printf "%-20s: %s\n" "$service" "$status"
    done
    
    echo ""
    echo "=== Network Status ==="
    echo "Hotspot IP: $(ip addr show wlan0 2>/dev/null | grep inet | head -1 | awk '{print $2}' | cut -d/ -f1 || echo 'Not configured')"
    echo "Connected clients: $(arp -a | grep "192.168.4" | wc -l)"
    
    echo ""
    echo "=== Port Status ==="
    ss -tlnp | grep ":8388\|:1080\|:8080" | awk '{print $1 " " $4}'
}

case "$1" in
    start) start_shadowmadow ;;
    stop) stop_shadowmadow ;;
    restart) stop_shadowmadow; sleep 3; start_shadowmadow ;;
    status) status_shadowmadow ;;
    *) 
        echo "ShadowMadow - Secure WiFi Hotspot"
        echo "Usage: $0 {start|stop|restart|status}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the secure hotspot"
        echo "  stop    - Stop the secure hotspot"
        echo "  restart - Restart the secure hotspot"
        echo "  status  - Show system status"
        exit 1 ;;
esac
EOF

    chmod +x /usr/local/bin/shadowmadow
    print_success "Management script created"
}

# Check for port conflicts and resolve them
resolve_port_conflicts() {
    print_status "Checking for port conflicts..."
    
    # More aggressive process cleanup
    for port in 8388 1080 8080; do
        local pids=$(lsof -ti:$port 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            print_status "Port $port is in use, killing conflicting processes..."
            # First try SIGTERM
            echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
            sleep 2
            
            # Check if still running, then use SIGKILL
            local remaining_pids=$(lsof -ti:$port 2>/dev/null || true)
            if [[ -n "$remaining_pids" ]]; then
                print_status "Processes still running on port $port, force killing..."
                echo "$remaining_pids" | xargs -r kill -9 2>/dev/null || true
                sleep 2
            fi
        fi
    done
    
    # Additional cleanup by process name
    pkill -9 -f "ss-server.*8388" 2>/dev/null || true
    pkill -9 -f "ss-local.*1080" 2>/dev/null || true
    pkill -9 -f "shadowmadow-proxy" 2>/dev/null || true
    sleep 2
    
    # Double check that ports are free
    for port in 8388 1080 8080; do
        if ss -tlnp | grep -q ":$port "; then
            print_error "Port $port is still in use after cleanup"
            local process=$(ss -tlnp | grep ":$port " | head -1)
            print_error "Process details: $process"
            
            # Last resort - try to kill by port one more time
            local final_pids=$(lsof -ti:$port 2>/dev/null || true)
            if [[ -n "$final_pids" ]]; then
                print_status "Final attempt to kill processes on port $port..."
                echo "$final_pids" | xargs -r kill -9 2>/dev/null || true
                sleep 3
            fi
        else
            print_success "Port $port is available"
        fi
    done
}

# Enable and start services
start_services() {
    print_status "Enabling and starting services..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Stop any conflicting processes
    pkill -f ss-local 2>/dev/null || true
    pkill -f ss-server 2>/dev/null || true
    pkill -f shadowmadow-proxy 2>/dev/null || true
    pkill -f "python.*shadowmadow-proxy" 2>/dev/null || true
    sleep 2
    
    # Resolve port conflicts
    resolve_port_conflicts
    
    # Unmask and enable hostapd service if it's masked
    print_status "Ensuring hostapd service is properly configured..."
    systemctl unmask hostapd 2>/dev/null || true
    systemctl daemon-reload
    
    # Try to enable hostapd with error handling
    if ! systemctl enable hostapd 2>/dev/null; then
        print_status "hostapd enable failed, attempting to fix..."
        # Remove any problematic symlinks
        rm -f /etc/systemd/system/hostapd.service 2>/dev/null || true
        rm -f /etc/systemd/system/multi-user.target.wants/hostapd.service 2>/dev/null || true
        systemctl daemon-reload
        sleep 2
        systemctl enable hostapd
    fi
    
    # Enable other services
    systemctl enable shadowmadow-server shadowmadow-client shadowmadow-proxy dnsmasq
    
    # Stop all ShadowMadow services first
    print_status "Stopping any existing ShadowMadow services..."
    for service in shadowmadow-server shadowmadow-client shadowmadow-proxy; do
        systemctl stop $service 2>/dev/null || true
    done
    sleep 3
    
    # Final port cleanup
    resolve_port_conflicts
    
    # Configure WiFi interface properly
    print_status "Configuring WiFi interface..."
    
    # Bring interface down first
    ip link set $WIFI_INTERFACE down 2>/dev/null || true
    sleep 1
    
    # Remove any existing IP addresses
    ip addr flush dev $WIFI_INTERFACE 2>/dev/null || true
    
    # Bring interface up
    ip link set $WIFI_INTERFACE up
    sleep 2
    
    # Add static IP
    ip addr add 192.168.4.1/24 dev $WIFI_INTERFACE 2>/dev/null || true
    sleep 1
    
    # Verify interface is up
    if ! ip link show $WIFI_INTERFACE | grep -q "state UP"; then
        print_error "Failed to bring up $WIFI_INTERFACE, trying alternative method..."
        ifconfig $WIFI_INTERFACE up 2>/dev/null || true
        ifconfig $WIFI_INTERFACE 192.168.4.1 netmask 255.255.255.0 2>/dev/null || true
    fi
    
    # Start services in order with better error handling
    print_status "Starting Shadowsocks server..."
    
    # Final check that port 8388 is free before starting
    if netstat -tln 2>/dev/null | grep -q ":8388 " || ss -tlnp | grep -q ":8388 "; then
        print_error "Port 8388 is still in use. Attempting emergency cleanup..."
        
        # Get processes using port 8388
        local server_pids=$(lsof -ti:8388 2>/dev/null || netstat -tlnp 2>/dev/null | grep ":8388 " | awk '{print $7}' | cut -d'/' -f1 || true)
        if [[ -n "$server_pids" ]]; then
            print_status "Killing processes on port 8388: $server_pids"
            echo "$server_pids" | xargs -r kill -9 2>/dev/null || true
        fi
        
        pkill -9 -f "ss-server" 2>/dev/null || true
        sleep 3
        
        # Check again
        if netstat -tln 2>/dev/null | grep -q ":8388 " || ss -tlnp | grep -q ":8388 "; then
            print_error "Cannot free port 8388. Aborting."
            print_error "Processes still using port 8388:"
            netstat -tlnp 2>/dev/null | grep ":8388 " || true
            exit 1
        fi
        print_success "Port 8388 cleared successfully"
    fi
    
    systemctl start shadowmadow-server
    sleep 3
    
    if ! systemctl is-active --quiet shadowmadow-server; then
        print_error "Shadowsocks server failed to start, checking logs..."
        journalctl -u shadowmadow-server --no-pager -n 10
        print_error "Server startup failed. Exiting."
        exit 1
    fi
    
    print_status "Starting Shadowsocks client..."
    
    # Check port 1080 before starting client
    if netstat -tln 2>/dev/null | grep -q ":1080 " || ss -tlnp | grep -q ":1080 "; then
        print_error "Port 1080 is still in use. Attempting emergency cleanup..."
        
        local client_pids=$(lsof -ti:1080 2>/dev/null || netstat -tlnp 2>/dev/null | grep ":1080 " | awk '{print $7}' | cut -d'/' -f1 || true)
        if [[ -n "$client_pids" ]]; then
            print_status "Killing processes on port 1080: $client_pids"
            echo "$client_pids" | xargs -r kill -9 2>/dev/null || true
        fi
        
        pkill -9 -f "ss-local" 2>/dev/null || true
        sleep 3
        
        if netstat -tln 2>/dev/null | grep -q ":1080 "; then
            print_error "Cannot free port 1080"
            netstat -tlnp 2>/dev/null | grep ":1080 " || true
        fi
    fi
    
    systemctl start shadowmadow-client
    sleep 3
    
    if ! systemctl is-active --quiet shadowmadow-client; then
        print_error "Shadowsocks client failed to start, checking logs..."
        journalctl -u shadowmadow-client --no-pager -n 10
        # Try restarting with delay
        sleep 2
        systemctl restart shadowmadow-client
        sleep 3
    fi
    
    print_status "Starting HTTP proxy..."
    systemctl start shadowmadow-proxy
    sleep 3
    
    if ! systemctl is-active --quiet shadowmadow-proxy; then
        print_error "HTTP proxy failed to start, checking logs..."
        journalctl -u shadowmadow-proxy --no-pager -n 10
        # Try restarting with delay
        sleep 2
        systemctl restart shadowmadow-proxy
        sleep 3
    fi
    
    print_status "Starting hostapd..."
    systemctl start hostapd
    sleep 3
    
    print_status "Starting dnsmasq..."
    systemctl start dnsmasq
    sleep 3
    
    # Apply routing rules
    print_status "Applying routing rules..."
    /etc/init.d/shadowmadow-routing start
    
    # Verify critical services
    local failed_services=()
    for service in shadowmadow-server shadowmadow-client shadowmadow-proxy hostapd dnsmasq; do
        if ! systemctl is-active --quiet $service; then
            failed_services+=($service)
        fi
    done
    
    if [ ${#failed_services[@]} -gt 0 ]; then
        print_error "Failed services: ${failed_services[*]}"
        print_status "Attempting to restart failed services..."
        for service in "${failed_services[@]}"; do
            # Force kill any related processes
            if [[ "$service" == "shadowmadow-proxy" ]]; then
                pkill -f "python.*shadowmadow-proxy" 2>/dev/null || true
                lsof -ti:8080 | xargs -r kill -9 2>/dev/null || true
            elif [[ "$service" == "shadowmadow-client" ]]; then
                pkill -f ss-local 2>/dev/null || true
                lsof -ti:1080 | xargs -r kill -9 2>/dev/null || true
            elif [[ "$service" == "shadowmadow-server" ]]; then
                pkill -f ss-server 2>/dev/null || true
                lsof -ti:8388 | xargs -r kill -9 2>/dev/null || true
            elif [[ "$service" == "hostapd" ]]; then
                # Special handling for hostapd
                systemctl unmask hostapd 2>/dev/null || true
                pkill -f hostapd 2>/dev/null || true
            fi
            sleep 2
            systemctl restart $service
            sleep 5
            
            # Check if it started successfully
            if systemctl is-active --quiet $service; then
                print_success "Successfully restarted $service"
            else
                print_error "Failed to restart $service, checking logs..."
                journalctl -u $service --no-pager -n 5
                
                # If hostapd still fails, try recovery
                if [[ "$service" == "hostapd" ]]; then
                    print_status "Attempting hostapd recovery..."
                    systemctl stop hostapd 2>/dev/null || true
                    systemctl unmask hostapd 2>/dev/null || true
                    rm -f /etc/systemd/system/hostapd.service 2>/dev/null || true
                    systemctl daemon-reload
                    systemctl enable hostapd
                    sleep 2
                    systemctl start hostapd
                fi
            fi
        done
    fi
    
    print_success "Service startup completed"
}

# Test setup
test_setup() {
    print_status "Testing setup..."
    
    # Check services
    all_good=true
    for service in shadowmadow-server shadowmadow-client shadowmadow-proxy hostapd dnsmasq; do
        if systemctl is-active --quiet $service; then
            print_success "$service is running"
        else
            print_error "$service is not running"
            all_good=false
        fi
    done
    
    # Check ports
    for port in 8388 1080 8080; do
        if ss -tlnp | grep -q ":$port "; then
            print_success "Port $port is listening"
        else
            print_error "Port $port is not listening"
            all_good=false
        fi
    done
    
    # Test SOCKS5
    if timeout 10 curl -s --socks5 127.0.0.1:1080 http://httpbin.org/ip >/dev/null 2>&1; then
        print_success "SOCKS5 proxy is working"
    else
        print_error "SOCKS5 proxy test failed"
        all_good=false
    fi
    
    if $all_good; then
        print_success "All tests passed! ShadowMadow is ready."
    else
        print_error "Some tests failed. Check the logs with 'journalctl -u [service-name]'"
    fi
}

# Recovery function for partial installations
recover_installation() {
    print_status "Attempting to recover from partial installation..."
    
    # Ensure all services are properly configured
    systemctl daemon-reload
    
    # Fix hostapd if it's still problematic
    if systemctl is-enabled hostapd 2>&1 | grep -q "masked"; then
        print_status "Fixing masked hostapd service..."
        systemctl unmask hostapd
        rm -f /etc/systemd/system/hostapd.service 2>/dev/null || true
        systemctl daemon-reload
        systemctl enable hostapd
    fi
    
    # Recreate the proxy service with fixed definition
    print_status "Recreating shadowmadow-proxy service..."
    cat > /etc/systemd/system/shadowmadow-proxy.service << EOF
[Unit]
Description=ShadowMadow HTTP Proxy
After=shadowmadow-client.service network.target
Wants=shadowmadow-client.service
Requires=shadowmadow-client.service

[Service]
Type=simple
User=root
ExecStartPre=/bin/sleep 3
ExecStart=/usr/bin/python3 /opt/shadowmadow-proxy.py
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    # Enable all required services
    for service in shadowmadow-server shadowmadow-client shadowmadow-proxy hostapd dnsmasq; do
        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            print_status "Enabling $service..."
            systemctl enable "$service" 2>/dev/null || true
        fi
    done
    
    # Manual cleanup before starting services
    print_status "Cleaning up processes and ports..."
    pkill -f "python.*shadowmadow-proxy" 2>/dev/null || true
    sleep 2
    
    # Kill processes on port 8080 manually
    local pids=$(lsof -ti:8080 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs kill -9 2>/dev/null || true
        sleep 2
    fi
    
    # Configure WiFi interface
    WIFI_INTERFACE="wlan0"
    print_status "Configuring WiFi interface..."
    ip link set $WIFI_INTERFACE down 2>/dev/null || true
    ip addr flush dev $WIFI_INTERFACE 2>/dev/null || true
    ip link set $WIFI_INTERFACE up
    sleep 2
    ip addr add 192.168.4.1/24 dev $WIFI_INTERFACE 2>/dev/null || true
    
    # Start services in order
    print_status "Starting services..."
    systemctl start shadowmadow-server
    sleep 3
    systemctl start shadowmadow-client  
    sleep 3
    systemctl start shadowmadow-proxy
    sleep 3
    systemctl start hostapd
    sleep 3
    systemctl start dnsmasq
    sleep 3
    
    # Apply routing
    /etc/init.d/shadowmadow-routing start 2>/dev/null || true
    
    print_success "Recovery attempt completed"
}

# Main installation function
main() {
    print_header
    
    print_status "Starting ShadowMadow installation..."
    
    check_root
    cleanup_existing
    detect_wifi_interface
    install_packages
    setup_shadowsocks
    setup_http_proxy
    setup_hotspot
    create_services
    setup_iptables
    configure_network
    create_management_script
    start_services
    test_setup
    
    echo ""
    print_header
    print_success "ShadowMadow installation complete!"
    echo ""
    echo -e "${GREEN}Your secure WiFi hotspot is ready:${NC}"
    echo -e "  ${YELLOW}SSID:${NC} ShadowMadow-Hotspot"
    echo -e "  ${YELLOW}Password:${NC} ShadowMadow123"
    echo -e "  ${YELLOW}IP Address:${NC} 192.168.4.1"
    echo ""
    echo -e "${BLUE}Management commands:${NC}"
    echo -e "  ${YELLOW}shadowmadow start${NC}   - Start the hotspot"
    echo -e "  ${YELLOW}shadowmadow stop${NC}    - Stop the hotspot"
    echo -e "  ${YELLOW}shadowmadow status${NC}  - Check status"
    echo -e "  ${YELLOW}shadowmadow restart${NC} - Restart services"
    echo ""
    echo -e "${GREEN}All traffic from connected devices will be encrypted via Shadowsocks!${NC}"
}

# Run main function
if [[ "$1" == "recover" ]]; then
    print_header
    print_status "Running ShadowMadow recovery..."
    check_root
    recover_installation
    test_setup
    print_success "Recovery completed!"
else
    main "$@"
fi

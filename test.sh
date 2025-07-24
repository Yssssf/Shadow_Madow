#!/bin/bash

# ShadowMadow Test Suite
# Comprehensive testing for the streamlined installation

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_test() {
    echo -e "${BLUE}[TEST] $1${NC}"
}

print_pass() {
    echo -e "${GREEN}[PASS] $1${NC}"
}

print_fail() {
    echo -e "${RED}[FAIL] $1${NC}"
}

print_info() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    print_test "Testing $test_name..."
    
    if eval "$test_command" >/dev/null 2>&1; then
        print_pass "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        print_fail "$test_name"
        return 1
    fi
}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                ShadowMadow Test Suite                        ║${NC}"
echo -e "${BLUE}║              Comprehensive System Validation                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# System Tests
print_info "Running system tests..."
run_test "Shadowsocks server service" "systemctl is-active --quiet shadowmadow-server"
run_test "Shadowsocks client service" "systemctl is-active --quiet shadowmadow-client"
run_test "HTTP proxy service" "systemctl is-active --quiet shadowmadow-proxy"
run_test "hostapd service" "systemctl is-active --quiet hostapd"
run_test "dnsmasq service" "systemctl is-active --quiet dnsmasq"

# Port Tests
print_info "Running port tests..."
run_test "Shadowsocks server port (8388)" "ss -tlnp | grep -q ':8388 '"
run_test "SOCKS5 client port (1080)" "ss -tlnp | grep -q ':1080 '"
run_test "HTTP proxy port (8080)" "ss -tlnp | grep -q ':8080 '"

# Configuration Tests
print_info "Running configuration tests..."
run_test "Shadowsocks server config" "test -f /etc/shadowsocks/server.json"
run_test "Shadowsocks client config" "test -f /etc/shadowsocks/client.json"
run_test "hostapd configuration" "test -f /etc/hostapd/hostapd.conf"
run_test "dnsmasq configuration" "grep -q 'interface=' /etc/dnsmasq.conf"

# Network Tests
print_info "Running network tests..."
run_test "WiFi interface up" "ip link show wlan0 | grep -q 'state UP'"
run_test "Hotspot IP configured" "ip addr show wlan0 | grep -q '192.168.4.1'"
run_test "IP forwarding enabled" "sysctl net.ipv4.ip_forward | grep -q '= 1'"

# Connectivity Tests
print_info "Running connectivity tests..."
run_test "SOCKS5 proxy connectivity" "timeout 10 curl -s --socks5 127.0.0.1:1080 http://httpbin.org/ip"
run_test "HTTP proxy connectivity" "timeout 10 curl -s --proxy http://127.0.0.1:8080 http://httpbin.org/ip"

# Management Script Tests
print_info "Running management tests..."
run_test "Management script exists" "test -x /usr/local/bin/shadowmadow"
run_test "Routing script exists" "test -x /etc/init.d/shadowmadow-routing"

# Security Tests
print_info "Running security tests..."
run_test "Shadowsocks password generated" "test -f /etc/shadowsocks/.password"
run_test "Config files permissions" "stat -c %a /etc/shadowsocks/server.json | grep -q 644"

# Advanced Tests
print_info "Running advanced tests..."

# Test iptables rules
if iptables -t nat -L PREROUTING | grep -q "REDIRECT" && iptables -t nat -L POSTROUTING | grep -q "MASQUERADE"; then
    print_pass "iptables NAT rules configured"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_fail "iptables NAT rules configured"
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

# Test DNS resolution
if nslookup google.com 192.168.4.1 >/dev/null 2>&1; then
    print_pass "DNS resolution working"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    print_fail "DNS resolution working"
fi
TESTS_TOTAL=$((TESTS_TOTAL + 1))

# Summary
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                        Test Results                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

if [ $TESTS_PASSED -eq $TESTS_TOTAL ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED! ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
    echo -e "${GREEN}ShadowMadow is fully operational and ready for use.${NC}"
    exit 0
else
    TESTS_FAILED=$((TESTS_TOTAL - TESTS_PASSED))
    echo -e "${YELLOW}⚠️  PARTIAL SUCCESS: $TESTS_PASSED/$TESTS_TOTAL tests passed${NC}"
    echo -e "${RED}❌ $TESTS_FAILED tests failed${NC}"
    echo ""
    echo -e "${YELLOW}Recommendations:${NC}"
    echo "1. Check service logs: journalctl -u [service-name]"
    echo "2. Verify network configuration: ip addr show"
    echo "3. Test connectivity manually: curl --socks5 127.0.0.1:1080 http://httpbin.org/ip"
    echo "4. Restart services: shadowmadow restart"
    exit 1
fi

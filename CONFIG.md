# ShadowMadow Configuration Reference

## Default Settings

The installation script uses these default values:

### WiFi Hotspot
- **SSID**: `ShadowMadow-Hotspot`
- **Password**: `ShadowMadow123`
- **Channel**: 6
- **IP Range**: 192.168.4.1-192.168.4.20
- **Gateway**: 192.168.4.1

### Shadowsocks
- **Server Port**: 8388
- **SOCKS5 Port**: 1080
- **Method**: aes-256-gcm
- **Password**: Auto-generated (32 characters)

### HTTP Proxy
- **Port**: 8080
- **Backend**: SOCKS5 (127.0.0.1:1080)

## Customization

### Changing WiFi Credentials

Edit `/etc/hostapd/hostapd.conf`:
```bash
sudo nano /etc/hostapd/hostapd.conf
```

Change these lines:
```
ssid=YourNewNetworkName
wpa_passphrase=YourNewPassword
```

Then restart:
```bash
sudo systemctl restart hostapd
```

### Changing IP Range

Edit `/etc/dnsmasq.conf`:
```bash
sudo nano /etc/dnsmasq.conf
```

Change:
```
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
```

And update `/etc/dhcpcd.conf`:
```
interface wlan0
static ip_address=192.168.4.1/24
```

### Changing Shadowsocks Settings

Edit both server and client configs:
```bash
sudo nano /etc/shadowsocks/server.json
sudo nano /etc/shadowsocks/client.json
```

Make sure passwords match in both files.

### Changing HTTP Proxy Port

Edit the proxy script:
```bash
sudo nano /opt/shadowmadow-proxy.py
```

Change the `local_port` parameter in the `HTTPProxy()` initialization.

Update iptables rules in `/etc/init.d/shadowmadow-routing`:
```bash
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port NEW_PORT
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port NEW_PORT
```

## Advanced Configuration

### Adding Custom DNS Servers

Edit `/etc/dnsmasq.conf`:
```
server=1.1.1.1
server=1.0.0.1
server=8.8.8.8
```

### Bandwidth Limiting

Add to dnsmasq configuration:
```
dhcp-option=option:router,192.168.4.1
dhcp-option=option:dns-server,192.168.4.1
```

### Multiple SSID Support

Create additional hostapd configurations:
```bash
cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd2.conf
```

Edit the new file with different SSID and create separate service.

### Logging Configuration

Enable detailed logging by editing service files:
```bash
sudo nano /etc/systemd/system/shadowmadow-server.service
```

Add `-v` or `-vv` for verbose logging:
```
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks/server.json -vv
```

### Firewall Rules

Add custom iptables rules to `/etc/init.d/shadowmadow-routing`:
```bash
# Block specific ports
iptables -A INPUT -p tcp --dport 22 -i wlan0 -j DROP

# Rate limiting
iptables -A INPUT -i wlan0 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
```

## Performance Tuning

### CPU Optimization
Set CPU governor to performance:
```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### Memory Optimization
Add to `/boot/config.txt`:
```
gpu_mem=16
```

### Network Optimization
Add to `/etc/sysctl.conf`:
```
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 16384 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
```

## Security Hardening

### Change Default Passwords
- WiFi password in hostapd.conf
- Shadowsocks password in config files
- System user passwords

### Disable Unused Services
```bash
sudo systemctl disable bluetooth
sudo systemctl disable cups
```

### Enable Firewall
```bash
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 192.168.4.0/24
```

### Regular Updates
```bash
sudo apt update && sudo apt upgrade -y
```

## Monitoring

### View Real-time Connections
```bash
watch -n 1 'arp -a | grep "192.168.4"'
```

### Monitor Bandwidth
```bash
sudo apt install vnstat
vnstat -i wlan0
```

### Check Service Health
```bash
shadowmadow status
```

### Log Analysis
```bash
journalctl -u shadowmadow-server --since "1 hour ago"
```

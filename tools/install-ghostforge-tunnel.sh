#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
(( EUID == 0 )) || { echo 'Run with sudo bash' >&2; exit 1; }
. /etc/os-release
[[ "$ID" == ubuntu && ( "$VERSION_ID" == "22.04" || "$VERSION_ID" == "24.04" ) ]] ||
 { echo 'Requires Ubuntu 22.04 or 24.04' >&2; exit 1; }
HOST="${1:-}"
if [[ -z "$HOST" ]]; then read -r -p 'Public IPv4 address or DNS hostname: ' HOST; fi
[[ -n "$HOST" ]] || { echo 'Host is required' >&2; exit 1; }
SAN=$(python3 - "$HOST" <<'PY'
import ipaddress,re,sys
s=sys.argv[1].strip()
try:
 p=ipaddress.ip_address(s)
 if p.version!=4: sys.exit('Requires IPv4')
 print('IP:'+s)
except ValueError:
 if not re.fullmatch(r'(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',s):
  sys.exit('Invalid public address')
 print('DNS:'+s.lower())
PY
)
if ! command -v go >/dev/null || ! command -v iptables >/dev/null ||
   ! command -v curl >/dev/null || ! command -v openssl >/dev/null; then
 export DEBIAN_FRONTEND=noninteractive
 apt-get update -qq
 apt-get install -y --no-install-recommends golang-go iptables iproute2 curl openssl ca-certificates python3
fi
[[ -c /dev/net/tun ]] || { modprobe tun 2>/dev/null || true; }
[[ -c /dev/net/tun ]] || { echo 'TUN unavailable; ask your VPS provider to enable /dev/net/tun' >&2; exit 1; }
WAN=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
[[ "$WAN" =~ ^[a-zA-Z0-9_.:-]+$ && "$WAN" != ghostforge0 ]] ||
 { echo 'No safe outbound interface found' >&2; exit 1; }
install -d -m 700 /etc/ghostforge-tunnel
install -d -m 755 /opt/ghostforge-tunnel/src /usr/local/libexec
BASE="$(cd "$(dirname "$0")" && pwd)/../tunnel-server"
for file in go.mod main.go protocol.go tun_linux.go; do
 if [[ -f "$BASE/$file" ]]; then
  install -m 644 "$BASE/$file" "/opt/ghostforge-tunnel/src/$file"
 else
  curl -fLSs --retry 3 "https://raw.githubusercontent.com/kangiskon/GhostForge/main/tunnel-server/$file" \
    -o "/opt/ghostforge-tunnel/src/$file"
 fi
done
(cd /opt/ghostforge-tunnel/src && CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/ghostforge-tunnel .)
chmod 755 /usr/local/bin/ghostforge-tunnel
if [[ ! -f /etc/ghostforge-tunnel/server.key || ! -f /etc/ghostforge-tunnel/server.crt ]]; then
 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 -sha256 \
  -subj '/CN=GhostForge Tunnel' -addext "subjectAltName=$SAN" \
  -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout /etc/ghostforge-tunnel/server.key -out /etc/ghostforge-tunnel/server.crt >/dev/null 2>&1
fi
chmod 600 /etc/ghostforge-tunnel/server.key
chmod 644 /etc/ghostforge-tunnel/server.crt
if [[ ! -f /etc/ghostforge-tunnel/token.env ]]; then
 printf 'GHOSTFORGE_TUNNEL_TOKEN=%s\n' "$(openssl rand -hex 32)" > /etc/ghostforge-tunnel/token.env
fi
chmod 600 /etc/ghostforge-tunnel/token.env
printf 'HOST=%s\nWAN_IF=%s\nTUN_IF=ghostforge0\nPORT=4443\n' "$HOST" "$WAN" > /etc/ghostforge-tunnel/server.conf
chmod 600 /etc/ghostforge-tunnel/server.conf
cat > /usr/local/libexec/ghostforge-net-up <<'UP'
#!/usr/bin/env bash
set -euo pipefail
. /etc/ghostforge-tunnel/server.conf
iptables -C FORWARD -i "$TUN_IF" -o "$WAN_IF" -s 10.74.0.0/30 -j ACCEPT 2>/dev/null ||
 iptables -I FORWARD 1 -i "$TUN_IF" -o "$WAN_IF" -s 10.74.0.0/30 -j ACCEPT
iptables -C FORWARD -i "$WAN_IF" -o "$TUN_IF" -d 10.74.0.0/30 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
 iptables -I FORWARD 1 -i "$WAN_IF" -o "$TUN_IF" -d 10.74.0.0/30 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.74.0.0/30 -o "$WAN_IF" -j MASQUERADE 2>/dev/null ||
 iptables -t nat -A POSTROUTING -s 10.74.0.0/30 -o "$WAN_IF" -j MASQUERADE
UP
cat > /usr/local/libexec/ghostforge-net-down <<'DOWN'
#!/usr/bin/env bash
set -euo pipefail
. /etc/ghostforge-tunnel/server.conf
iptables -D FORWARD -i "$TUN_IF" -o "$WAN_IF" -s 10.74.0.0/30 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i "$WAN_IF" -o "$TUN_IF" -d 10.74.0.0/30 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s 10.74.0.0/30 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
DOWN
chmod 755 /usr/local/libexec/ghostforge-net-up /usr/local/libexec/ghostforge-net-down
cat > /etc/systemd/system/ghostforge-tunnel.service <<'UNIT'
[Unit]
Description=GhostForge Experimental TLS IPv4 VPN Tunnel
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=/etc/ghostforge-tunnel/token.env
ExecStartPre=/usr/local/libexec/ghostforge-net-up
ExecStart=/usr/local/bin/ghostforge-tunnel --listen 0.0.0.0:4443 --tun ghostforge0 --cert /etc/ghostforge-tunnel/server.crt --key /etc/ghostforge-tunnel/server.key
ExecStopPost=/usr/local/libexec/ghostforge-net-down
Restart=on-failure
RestartSec=4
User=root
Group=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
[Install]
WantedBy=multi-user.target
UNIT
chmod 644 /etc/systemd/system/ghostforge-tunnel.service
printf 'net.ipv4.ip_forward = 1\n' > /etc/sysctl.d/96-ghostforge-forward.conf
sysctl -p /etc/sysctl.d/96-ghostforge-forward.conf >/dev/null
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
 ufw allow 4443/tcp comment 'GhostForge Tunnel' >/dev/null
fi
cat > /usr/local/bin/ghostforge-tunnel-info <<'INFO'
#!/usr/bin/env bash
set -euo pipefail
(( EUID == 0 )) || { echo 'Run with sudo' >&2; exit 1; }
. /etc/ghostforge-tunnel/server.conf
. /etc/ghostforge-tunnel/token.env
printf 'GhostForge server: %s\nPort: %s\n' "$HOST" "$PORT"
printf 'TLS certificate SHA-256: %s\n' "$(openssl x509 -in /etc/ghostforge-tunnel/server.crt -outform DER | sha256sum | awk '{print $1}')"
printf 'Private authentication token: %s\n' "$GHOSTFORGE_TUNNEL_TOKEN"
echo 'Do not publish or share the private token.'
INFO
chmod 750 /usr/local/bin/ghostforge-tunnel-info
systemctl daemon-reload
systemctl enable --now ghostforge-tunnel.service
systemctl is-active --quiet ghostforge-tunnel.service ||
 { echo 'Service not running; use journalctl -u ghostforge-tunnel -n 80' >&2; exit 1; }
echo 'GhostForge Tunnel installed; view server and pairing details with sudo ghostforge-tunnel-info'
echo 'Allow TCP 4443 in your VPS provider firewall. Existing websites are unaffected.'
echo 'A matching GhostForge Android Tunnel client is needed to connect.'

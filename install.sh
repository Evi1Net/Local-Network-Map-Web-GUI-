#!/usr/bin/env bash
# Network Map installer (defensive monitoring only). Run: sudo bash install.sh
set -e
[ "$(id -u)" = 0 ] || { echo "Run as root: sudo bash install.sh"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"; D=/opt/network-map
if command -v apt-get >/dev/null; then apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y nmap python3 python3-venv python3-pip iputils-ping traceroute snmp curl iproute2 arping
elif command -v dnf >/dev/null; then dnf install -y nmap python3 python3-pip iputils traceroute net-snmp-utils curl iproute
elif command -v yum >/dev/null; then yum install -y nmap python3 python3-pip iputils traceroute net-snmp-utils curl iproute
elif command -v pacman >/dev/null; then pacman -Sy --noconfirm nmap python python-pip iputils traceroute net-snmp curl iproute2
elif command -v zypper >/dev/null; then zypper -n install nmap python3 python3-pip iputils traceroute net-snmp curl iproute2
else echo "Unsupported distro"; exit 1; fi
# ---- extra discovery tools (best effort; the app works without them) ----
if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y lldpd arp-scan fping netdiscover || true
elif command -v dnf >/dev/null; then dnf install -y lldpd arp-scan fping || true
elif command -v pacman >/dev/null; then pacman -S --noconfirm lldpd arp-scan fping || true; fi
if command -v lldpd >/dev/null; then
  echo 'DAEMON_ARGS="-c -e -f -s"' > /etc/default/lldpd; [ -d /etc/sysconfig ] && echo 'LLDPD_OPTIONS="-c -e -f -s"' > /etc/sysconfig/lldpd
  systemctl enable --now lldpd 2>/dev/null || true; systemctl restart lldpd 2>/dev/null || true
fi
mkdir -p $D/data $D/static
cp "$SRC/main.py" "$SRC/fingerprint.py" "$SRC/topology.py" $D/; cp "$SRC"/static/* $D/static/; cp "$SRC/PROMPT.md" $D/ 2>/dev/null || true
python3 -m venv $D/venv; $D/venv/bin/pip install -q fastapi "uvicorn[standard]"
[ -s $D/static/cytoscape.min.js ] || curl -fsSL https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js -o $D/static/cytoscape.min.js
# ---- port selection: never fight another web server for the port ----
PORT="${PORT:-80}"
systemctl stop network-map 2>/dev/null || true
busy(){ ss -ltn "sport = :$1" 2>/dev/null | grep -q LISTEN; }
if busy "$PORT"; then
  if systemctl is-active --quiet apache2 && grep -q "Apache2 Ubuntu Default Page" /var/www/html/index.html 2>/dev/null; then
    echo "Port $PORT is held by the stock Apache 'Ubuntu Default Page' - disabling apache2 (it serves nothing else)."
    systemctl disable --now apache2
  fi
  if busy "$PORT"; then
    OLD=$PORT; PORT=8080; while busy "$PORT"; do PORT=$((PORT+1)); done
    echo "Port $OLD is used by another service (see: ss -ltnp | grep :$OLD) - using port $PORT instead."
  fi
fi
cat > /etc/systemd/system/network-map.service <<U
[Unit]
Description=Network Map
After=network-online.target
[Service]
WorkingDirectory=$D
Environment=NETMAP_PORT=$PORT
ExecStart=$D/venv/bin/python $D/main.py
Restart=always
User=root
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload; systemctl enable network-map; systemctl restart network-map
IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
SUF=""; [ "$PORT" = 80 ] || SUF=":$PORT"
sleep 2; systemctl is-active --quiet network-map || { echo "Service failed to start - run: journalctl -u network-map -n 30"; exit 1; }
echo; echo "Network Map is running: http://${IP:-SERVER-IP}$SUF"
echo "Complete."

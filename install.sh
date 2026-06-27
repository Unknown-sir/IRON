#!/usr/bin/env bash
set -euo pipefail

REPO_USER="Unknown-sir"
REPO_NAME="IRON"
BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${BRANCH}"
INSTALL_DIR="/opt/iron"
CONFIG_DIR="/etc/iron"
SERVICE_DIR="/etc/systemd/system"
PYTHON_BIN="/usr/bin/python3"

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
need_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || { red "Run as root: sudo bash install.sh"; exit 1; }; }

fetch_file(){
  local src="$1" dst="$2"
  if [[ -f "$(dirname "$0")/$src" ]]; then
    cp "$(dirname "$0")/$src" "$dst"
  else
    curl -fsSL "${BASE_URL}/${src}" -o "$dst"
  fi
}

install_deps(){
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssl curl ca-certificates iproute2
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 openssl curl ca-certificates iproute
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 openssl curl ca-certificates iproute
  else
    yellow "Unknown package manager. Make sure python3, openssl and curl are installed."
  fi
}

install_core(){
  mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
  fetch_file "iron.py" "$INSTALL_DIR/iron.py"
  chmod +x "$INSTALL_DIR/iron.py"
  cat > /usr/local/bin/iron <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /opt/iron/iron.py "$@"
EOF
  chmod +x /usr/local/bin/iron
}

generate_cert(){
  local name="${1:-iron-hub}"
  mkdir -p "$CONFIG_DIR"
  if [[ -f "$CONFIG_DIR/hub.crt" && -f "$CONFIG_DIR/hub.key" ]]; then
    yellow "TLS cert already exists: $CONFIG_DIR/hub.crt"
    return
  fi
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$CONFIG_DIR/hub.key" -out "$CONFIG_DIR/hub.crt" \
    -subj "/CN=${name}" >/dev/null 2>&1
  chmod 600 "$CONFIG_DIR/hub.key"
  green "Generated self-signed TLS cert: $CONFIG_DIR/hub.crt"
}

new_token(){
  if [[ -x /usr/local/bin/iron ]]; then
    iron token
  else
    python3 "$INSTALL_DIR/iron.py" token
  fi
}

write_hub_config(){
  local control_port token listen_port target_port target_host cert_name
  read -rp "Control/TLS port [9443]: " control_port; control_port=${control_port:-9443}
  read -rp "Public listen port on this server [443]: " listen_port; listen_port=${listen_port:-443}
  read -rp "Target host on Agent side [127.0.0.1]: " target_host; target_host=${target_host:-127.0.0.1}
  read -rp "Target port on Agent side [$listen_port]: " target_port; target_port=${target_port:-$listen_port}
  read -rp "Agent ID [default]: " agent_id; agent_id=${agent_id:-default}
  read -rp "TLS certificate CN [iron-hub]: " cert_name; cert_name=${cert_name:-iron-hub}
  generate_cert "$cert_name"
  token=$(new_token)
  cat > "$CONFIG_DIR/hub.json" <<EOF
{
  "agent_id": "${agent_id}",
  "token": "${token}",
  "control_host": "0.0.0.0",
  "control_port": ${control_port},
  "certfile": "${CONFIG_DIR}/hub.crt",
  "keyfile": "${CONFIG_DIR}/hub.key",
  "heartbeat_seconds": 10,
  "heartbeat_timeout_seconds": 30,
  "buffer_size": 65536,
  "send_timeout_seconds": 15,
  "local_drain_timeout_seconds": 20,
  "stream_queue_size": 512,
  "max_streams": 8192,
  "ports": [
    {
      "listen_host": "0.0.0.0",
      "listen_port": ${listen_port},
      "target_host": "${target_host}",
      "target_port": ${target_port}
    }
  ]
}
EOF
  chmod 600 "$CONFIG_DIR/hub.json"
  green "Hub config written: $CONFIG_DIR/hub.json"
  yellow "Save this token for Agent: ${token}"
}

write_agent_config(){
  local hub_host hub_port token agent_id ca_choice server_name
  read -rp "Hub server IP/domain: " hub_host
  read -rp "Hub control/TLS port [9443]: " hub_port; hub_port=${hub_port:-9443}
  read -rp "Agent ID [default]: " agent_id; agent_id=${agent_id:-default}
  read -rsp "Paste Hub token: " token; echo
  read -rp "TLS server name/CN [iron-hub]: " server_name; server_name=${server_name:-iron-hub}
  yellow "For best security copy /etc/iron/hub.crt from Hub to this Agent as /etc/iron/hub.crt."
  read -rp "Use strict TLS verification with /etc/iron/hub.crt? [y/N]: " ca_choice
  mkdir -p "$CONFIG_DIR"
  if [[ "$ca_choice" =~ ^[Yy]$ ]]; then
    cat > "$CONFIG_DIR/agent.json" <<EOF
{
  "agent_id": "${agent_id}",
  "token": "${token}",
  "hub_host": "${hub_host}",
  "hub_port": ${hub_port},
  "server_name": "${server_name}",
  "ca_file": "${CONFIG_DIR}/hub.crt",
  "heartbeat_seconds": 10,
  "heartbeat_timeout_seconds": 30,
  "buffer_size": 65536,
  "send_timeout_seconds": 15,
  "local_drain_timeout_seconds": 20,
  "stream_queue_size": 512,
  "max_streams": 8192,
  "max_reconnect_seconds": 30
}
EOF
  else
    cat > "$CONFIG_DIR/agent.json" <<EOF
{
  "agent_id": "${agent_id}",
  "token": "${token}",
  "hub_host": "${hub_host}",
  "hub_port": ${hub_port},
  "server_name": "${server_name}",
  "insecure_skip_verify": true,
  "heartbeat_seconds": 10,
  "heartbeat_timeout_seconds": 30,
  "buffer_size": 65536,
  "send_timeout_seconds": 15,
  "local_drain_timeout_seconds": 20,
  "stream_queue_size": 512,
  "max_streams": 8192,
  "max_reconnect_seconds": 30
}
EOF
  fi
  chmod 600 "$CONFIG_DIR/agent.json"
  green "Agent config written: $CONFIG_DIR/agent.json"
}

install_services(){
  cat > "$SERVICE_DIR/iron-hub.service" <<EOF
[Unit]
Description=IRON Secure Reverse Tunnel Hub
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/iron.py hub --config ${CONFIG_DIR}/hub.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF
  cat > "$SERVICE_DIR/iron-agent.service" <<EOF
[Unit]
Description=IRON Secure Reverse Tunnel Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/iron.py agent --config ${CONFIG_DIR}/agent.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

enable_bbr(){
  cat > /etc/sysctl.d/99-iron.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_keepalive_time=30
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
net.core.somaxconn=65535
fs.file-max=1048576
EOF
  sysctl --system >/dev/null || true
  green "Kernel TCP tuning applied."
}

start_role(){
  local role="$1"
  systemctl enable --now "iron-${role}.service"
  systemctl --no-pager --full status "iron-${role}.service" || true
}

install_hub(){
  need_root; install_deps; install_core; install_services; enable_bbr; write_hub_config; start_role hub
  green "Hub installed. Open control/public ports in your firewall if needed."
}

install_agent(){
  need_root; install_deps; install_core; install_services; write_agent_config; start_role agent
  green "Agent installed."
}

uninstall_all(){
  need_root
  systemctl disable --now iron-hub.service iron-agent.service 2>/dev/null || true
  rm -f "$SERVICE_DIR/iron-hub.service" "$SERVICE_DIR/iron-agent.service" /usr/local/bin/iron
  systemctl daemon-reload || true
  read -rp "Remove configs in /etc/iron too? [y/N]: " ans
  [[ "$ans" =~ ^[Yy]$ ]] && rm -rf "$CONFIG_DIR"
  rm -rf "$INSTALL_DIR"
  green "IRON removed."
}

show_menu(){
  cat <<'EOF'
IRON installer
1) Install Hub   (IR/public server)
2) Install Agent (EU/service server)
3) Generate/refresh Hub config
4) Generate/refresh Agent config
5) Status
6) Logs
7) Uninstall
EOF
  read -rp "Choose [1-7]: " choice
  case "$choice" in
    1) install_hub ;;
    2) install_agent ;;
    3) need_root; install_core; install_services; write_hub_config ;;
    4) need_root; install_core; install_services; write_agent_config ;;
    5) systemctl --no-pager status iron-hub.service iron-agent.service || true ;;
    6) journalctl -u iron-hub.service -u iron-agent.service -f ;;
    7) uninstall_all ;;
    *) red "Invalid choice"; exit 1 ;;
  esac
}

case "${1:-menu}" in
  hub) install_hub ;;
  agent) install_agent ;;
  uninstall) uninstall_all ;;
  menu|*) show_menu ;;
esac

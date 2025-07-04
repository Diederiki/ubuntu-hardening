#!/usr/bin/env bash
#
# Enhanced Ubuntu 24.04 Server Hardening Script (Interactive Edition)
# Author: ChatGPT x Diederik

set -euo pipefail
IFS=$'\n\t'

# === Constants & Defaults ===
DEFAULT_SSH_PORT=3022
SSH_PORT=${SSH_PORT:-$DEFAULT_SSH_PORT}
DOMAIN=""
EMAIL=""
NONINTERACTIVE=false

# === Color Codes ===
GREEN="\e[1;32m"
RED="\e[1;31m"
YELLOW="\e[1;33m"
BLUE="\e[1;34m"
CYAN="\e[1;36m"
MAGENTA="\e[1;35m"
BOLD="\e[1m"
RESET="\e[0m"

# === Logging ===
log()   { echo -e "${CYAN}[INFO]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# === Utilities ===
confirm() {
  [[ "$NONINTERACTIVE" == true ]] && return 0
  read -r -p "$* [y/N]: " resp
  [[ "$resp" =~ ^[Yy] ]] || error "User declined. Exiting."
}

# === Argument Parsing ===
usage() {
  cat <<EOF
Usage: $0 [options]
  -p PORT     SSH port (default: $DEFAULT_SSH_PORT)
  -d DOMAIN   Domain for Let's Encrypt
  -e EMAIL    Email for Let's Encrypt
  -y          Non-interactive (assume yes)
  -h          Show help
EOF
  exit 1
}
while getopts ":p:d:e:yh" opt; do
  case "$opt" in
    p) SSH_PORT=$OPTARG ;;  
    d) DOMAIN=$OPTARG ;;  
    e) EMAIL=$OPTARG ;;  
    y) NONINTERACTIVE=true ;;  
    h|*) usage ;;  
  esac
done

# === Core Functions ===
update_system() {
  log "Updating system and installing prerequisites..."
  apt update && apt upgrade -y
  apt install -y ufw fail2ban suricata netfilter-persistent \
    curl jq software-properties-common certbot python3-certbot-nginx \
    unattended-upgrades portsentry rkhunter clamav
}

configure_ssh() {
  log "Configuring SSH to listen on port $SSH_PORT only..."
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
  sed -ri '/^\s*Port\s+[0-9]+/d' /etc/ssh/sshd_config
  echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
  sed -ri 's/^#?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
  systemctl restart ssh
}

configure_ufw() {
  log "Setting up UFW rules..."
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "$SSH_PORT"/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw --force enable
}

configure_suricata() {
  log "Configuring Suricata IPS..."
  local iface trusted_ip
  iface=$(ip route get 1.1.1.1 | awk '/dev/ {print $5}')
  trusted_ip=$(who am i | awk '{print $5}' | tr -d '()' || echo "")

  iptables -F; iptables -X
  iptables -A INPUT -p tcp --dport "$SSH_PORT" -s "$trusted_ip" -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -i "$iface" ! -p tcp --dport "$SSH_PORT" -j NFQUEUE --queue-num 0
  iptables -A OUTPUT -o "$iface" -j NFQUEUE --queue-num 0
  iptables -A FORWARD -j NFQUEUE --queue-num 0
  netfilter-persistent save

  cat > /etc/systemd/system/suricata-ips.service <<EOF
[Unit]
Description=Suricata IPS (NFQUEUE)
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now suricata-ips
}

configure_fail2ban() {
  log "Configuring Fail2Ban for Suricata..."
  cat > /etc/fail2ban/filter.d/suricata.conf <<EOF
[Definition]
failregex = \[.*\]\s+\[.*\]\s+\[Classification: .*?\]\s+\[Priority: [0-9]+\]\s+\{.*?\} <HOST>
ignoreregex =
EOF
  cat > /etc/fail2ban/jail.d/suricata.local <<EOF
[suricata]
enabled = true
filter  = suricata
action  = iptables[name=Suricata, port=any, protocol=all]
logpath = /var/log/suricata/fast.log
findtime = 300
bantime = 600
maxretry = 3
EOF
  systemctl restart fail2ban
}

fix_ntp_dns() {
  log "Ensuring NTP sync and DNS resolution..."
  sed -ri 's/^#?NTP=.*/NTP=pool.ntp.org/' /etc/systemd/timesyncd.conf || true
  systemctl restart systemd-timesyncd
  timedatectl set-ntp true
}

install_certbot() {
  log "Installing/renewing Let's Encrypt certificate..."
  # Prompt for domain and email if not set
  if [[ -z "$DOMAIN" ]]; then
    read -r -p "Enter your domain (e.g. example.com): " DOMAIN
  fi
  if [[ -z "$EMAIL" ]]; then
    read -r -p "Enter your email address: " EMAIL
  fi
  # Validate input
  [[ -z "$DOMAIN" || -z "$EMAIL" ]] && error "Domain and email are required."
  certbot --nginx -d "$DOMAIN" --agree-tos -m "$EMAIL" --redirect --non-interactive
}


extra_hardening() {
  log "Configuring unattended upgrades, Portsentry, Rkhunter, ClamAV..."
  dpkg-reconfigure -f noninteractive unattended-upgrades

  sed -ri \
    -e 's/^TCP_MODE="tcp"/TCP_MODE="atcp"/' \
    -e 's/^UDP_MODE="udp"/UDP_MODE="audp"/' \
    /etc/default/portsentry
  sed -ri \
    -e 's/^#?BLOCK_TCP=.*/BLOCK_TCP="1"/' \
    -e 's/^#?BLOCK_UDP=.*/BLOCK_UDP="1"/' \
    -e 's|^#?KILL_ROUTE=.*|KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"|' \
    /etc/portsentry/portsentry.conf
  systemctl restart portsentry

  freshclam || warn "Freshclam update failed"
  rkhunter --update || warn "Rkhunter update failed"
  rkhunter --propupd || warn "Rkhunter property update failed"
  rkhunter --check --sk || warn "Rkhunter scan incomplete"
}

show_status() {
  log "Checking service status..."
  echo -n -e "\n${BLUE}UFW:${RESET} "; ufw status verbose
  echo -n -e "\n${BLUE}SSH:${RESET} "; systemctl is-active --quiet ssh && echo -e "${GREEN}Active${RESET}" || echo -e "${RED}Inactive${RESET}"
  echo -n -e "\n${BLUE}Suricata IPS:${RESET} "; systemctl is-active --quiet suricata-ips && echo -e "${GREEN}Active${RESET}" || echo -e "${RED}Inactive${RESET}"
  echo -n -e "\n${BLUE}Fail2Ban:${RESET} "; systemctl is-active --quiet fail2ban && echo -e "${GREEN}Active${RESET}" || echo -e "${RED}Inactive${RESET}"
  echo -n -e "\n${BLUE}Portsentry:${RESET} "; systemctl is-active --quiet portsentry && echo -e "${GREEN}Active${RESET}" || echo -e "${RED}Inactive${RESET}"
  echo -n -e "\n${BLUE}ClamAV:${RESET} "; command -v clamscan &>/dev/null && echo -e "${GREEN}OK${RESET}" || echo -e "${RED}Missing${RESET}"
  echo -n -e "\n${BLUE}Rkhunter:${RESET} "; command -v rkhunter &>/dev/null && echo -e "${GREEN}OK${RESET}" || echo -e "${RED}Missing${RESET}"
  # Pause to allow user to review
  read -r -p "\nPress Enter to return to menu..."
}

# === New Helpers ===
view_logs() {
  local srv=$1
  log "Showing last 20 lines of ${srv} logs:"
  journalctl -u "${srv}" -n 20 --no-pager
  read -r -p "Press Enter to continue..."
}

view_iptables() {
  log "Current iptables rules:"
  iptables -L -n -v
  read -r -p "Press Enter to continue..."
}

# === Improved Menu UI ===
draw_box() {
  local w=50
  printf "${MAGENTA}%${w}s\n" | tr ' ' '='
  printf "${MAGENTA}|${RESET}%*s${MAGENTA}|\n" $((w-2)) " $1 "
  printf "${MAGENTA}%${w}s\n${RESET}" | tr ' ' '='
}

menu() {
  clear
  draw_box "Ubuntu Server Hardening"
  echo -e "${GREEN} 1)${RESET} Update system"
  echo -e "${GREEN} 2)${RESET} Configure SSH Port to 3022"
  echo -e "${GREEN} 3)${RESET} Configure UFW Firewall"
  echo -e "${GREEN} 4)${RESET} Configure Suricata IPS (Intrusion Prevention System)"
  echo -e "${GREEN} 5)${RESET} Configure Fail2Ban"
  echo -e "${GREEN} 6)${RESET} Fix NTP & DNS resolution"
  echo -e "${GREEN} 7)${RESET} Install/renew Let's Encrypt for nginx/apache"
  echo -e "${GREEN} 8)${RESET} Extra Hardening - ClamAV - RootkitHunter - PortSentry"
  echo -e "${GREEN} 9)${RESET} Show hardening Status"
  echo -e "${GREEN}10)${RESET} View Logs"
  echo -e "${GREEN}11)${RESET} View iptables"
  echo -e "${GREEN}12)${RESET} Run ALL steps"
  echo -e "${RED} 0)${RESET} Exit"
  echo -ne "\n${BOLD}Choose an option: ${RESET}"
  read -r choice
}

# === Main Loop ===
while true; do
  menu
  case $choice in
    1) update_system ;; 
    2) configure_ssh ;; 
    3) configure_ufw ;; 
    4) configure_suricata ;; 
    5) configure_fail2ban ;; 
    6) fix_ntp_dns ;; 
    7) install_certbot ;; 
    8) extra_hardening ;; 
    9) show_status ;; 
    10) view_logs "ssh" ;; 
    11) view_iptables ;; 
    12)
      confirm "Proceed with all hardening steps?"
      update_system; configure_ssh; configure_ufw; configure_suricata; \
      configure_fail2ban; fix_ntp_dns; install_certbot; extra_hardening ;; 
    0) log "Exiting."; exit 0 ;; 
    *) warn "Invalid choice, try again." ;; 
  esac
  echo -e "\n${GREEN}✅ Done. Returning to menu...${RESET}"
  sleep 1
done

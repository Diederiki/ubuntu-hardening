#!/bin/bash
#
# Ultimate Ubuntu 24.04 Server Hardening Script (Interactive Edition with Colors)
# Author: ChatGPT x You ⚔️

set -e

# === Color codes === #
GREEN="\e[1;32m"
RED="\e[1;31m"
YELLOW="\e[1;33m"
BLUE="\e[1;34m"
RESET="\e[0m"

# === MENU === #
function menu() {
    echo -e "\n${BLUE}🛡️  Ultimate VPS Security Hardening Menu${RESET}"
    echo -e "${BLUE}=========================================${RESET}"
    echo -e "${GREEN}1)${RESET} Change SSH Port to 3022"
    echo -e "${GREEN}2)${RESET} Configure UFW (firewall)"
    echo -e "${GREEN}3)${RESET} Install and configure Suricata IPS"
    echo -e "${GREEN}4)${RESET} Install and configure Fail2Ban"
    echo -e "${GREEN}5)${RESET} Fix NTP and DNS resolution"
    echo -e "${GREEN}6)${RESET} Install Let's Encrypt for Apache/Nginx"
    echo -e "${GREEN}7)${RESET} Run ALL steps"
    echo -e "${GREEN}8)${RESET} Extra Hardening: Unattended Updates, PortSentry, Rootkit/AV"
    echo -e "${RED}0) Exit${RESET}"
    echo -ne "\n${YELLOW}Choose an option: ${RESET}"
    read choice
}

function update_system() {
    echo -e "${YELLOW}[*] Updating system and installing dependencies...${RESET}"
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y ufw fail2ban suricata iptables-persistent curl jq software-properties-common
}

function change_ssh_port() {
    echo -e "${YELLOW}[*] Changing SSH port to 3022...${RESET}"
    sudo sed -i 's/^#Port 22/Port 3022/;s/^Port 22/Port 3022/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
}

function configure_ufw() {
    echo -e "${YELLOW}[*] Configuring UFW firewall...${RESET}"
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow 3022/tcp
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw --force enable
}

function configure_suricata() {
    echo -e "${YELLOW}[*] Configuring Suricata IPS (NFQUEUE)...${RESET}"
    INTERFACE=$(ip route get 1.1.1.1 | grep -oP 'dev \K[^ ]+')
    SSH_PORT=3022
    TRUSTED_SSH_IP="$(who | awk 'NR==1{print $5}' | tr -d '()')"

    iptables -F
    iptables -X

    iptables -A INPUT -p tcp --dport $SSH_PORT -s $TRUSTED_SSH_IP -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i $INTERFACE ! -p tcp --dport $SSH_PORT -j NFQUEUE --queue-num 0
    iptables -A OUTPUT -o $INTERFACE -j NFQUEUE --queue-num 0
    iptables -A FORWARD -j NFQUEUE --queue-num 0

    netfilter-persistent save

    cat <<EOF | sudo tee /etc/systemd/system/suricata-ips.service > /dev/null
[Unit]
Description=Suricata IPS Mode (NFQUEUE)
After=network.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml -q 0
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable suricata-ips
    sudo systemctl start suricata-ips
}

function configure_fail2ban() {
    echo -e "${YELLOW}[*] Configuring Fail2Ban for Suricata...${RESET}"
    cat <<EOF | sudo tee /etc/fail2ban/filter.d/suricata.conf > /dev/null
[Definition]
failregex = \[.*\] \[.*\] \[Classification: .*?\] \[Priority: [0-9]+\] \{.*?\} <HOST>
ignoreregex =
EOF

    cat <<EOF | sudo tee /etc/fail2ban/jail.d/suricata.local > /dev/null
[suricata]
enabled  = true
filter   = suricata
action   = iptables[name=Suricata, port=any, protocol=all]
logpath  = /var/log/suricata/fast.log
findtime = 300
bantime = 600
maxretry = 3
EOF

    sudo systemctl restart fail2ban
}

function fix_ntp_dns() {
    echo -e "${YELLOW}[*] Fixing NTP and DNS resolution...${RESET}"
    sudo sed -i '/^#?NTP=/c\NTP=pool.ntp.org' /etc/systemd/timesyncd.conf || true
    sudo systemctl restart systemd-timesyncd
    sudo timedatectl set-ntp true
}

function install_letsencrypt() {
    echo -e "${YELLOW}[*] Installing Let's Encrypt (Certbot)...${RESET}"
    sudo apt install certbot python3-certbot-nginx -y
    echo -ne "${YELLOW}Enter your domain (e.g. example.com): ${RESET}"
    read DOMAIN
    echo -ne "${YELLOW}Enter your email address: ${RESET}"
    read EMAIL
    sudo certbot --nginx -d $DOMAIN --agree-tos -m $EMAIL --redirect --non-interactive
}

function extra_hardening() {
    echo -e "${YELLOW}[*] Installing Unattended Upgrades...${RESET}"
    sudo apt install unattended-upgrades -y
    sudo dpkg-reconfigure -f noninteractive unattended-upgrades

    echo -e "${YELLOW}[*] Installing PortSentry for port scan detection...${RESET}"
    sudo apt install portsentry -y
    sudo sed -i 's/TCP_MODE="tcp"/TCP_MODE="atcp"/' /etc/default/portsentry
    sudo sed -i 's/UDP_MODE="udp"/UDP_MODE="audp"/' /etc/default/portsentry
    sudo systemctl enable portsentry --now

    echo -e "${YELLOW}[*] Installing Rootkit Hunter and ClamAV...${RESET}"
    sudo apt install rkhunter clamav -y
    sudo freshclam
    sudo rkhunter --update
    sudo rkhunter --propupd
    sudo rkhunter --check --sk
}

# === LOOP === #
while true; do
    menu
    case $choice in
        1) update_system; change_ssh_port;;
        2) configure_ufw;;
        3) configure_suricata;;
        4) configure_fail2ban;;
        5) fix_ntp_dns;;
        6) install_letsencrypt;;
        7) update_system; change_ssh_port; configure_ufw; configure_suricata; configure_fail2ban; fix_ntp_dns;;
        8) extra_hardening;;
        0) echo -e "${RED}Exiting setup.${RESET}"; exit 0;;
        *) echo -e "${RED}Invalid choice. Try again.${RESET}";;
    esac
    echo -e "\n${GREEN}✅ Operation complete. Returning to menu...${RESET}"
    sleep 2
done

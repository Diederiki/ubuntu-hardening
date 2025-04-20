![image](https://github.com/user-attachments/assets/f2bc2f99-402f-4646-a09a-ba72ba69a541)


🛡️ Ubuntu 24.04 Server Hardening Toolkit

An interactive, all-in-one Bash script for securing fresh Ubuntu 24.04 VPS deployments.**  
Includes real-world best practices and tools to harden your server in minutes — no experience needed.

---

🚀 Features

✅ UFW Firewall setup  
🔒 SSH hardening (moves SSH to port `3022`)  
🛡️ Suricata IDS/IPS (NFQUEUE inline mode)  
🚫 Fail2Ban integration for Suricata alerts  
🔄 Unattended Security Updates  
🛰️ Port scan detection with PortSentry  
🧪 Rootkit and malware detection (rkhunter + ClamAV)  
🔐 Optional Let's Encrypt SSL (for Apache/Nginx)  
🎨 Color-coded, interactive terminal menu  

---

📦 Installation

curl -O https://raw.githubusercontent.com/Diederiki/ubuntu-hardening/main/ubuntu-hardening.sh

chmod +x ubuntu-hardening.sh

sudo ./ubuntu-hardening.sh

> ⚠️ You’ll need `sudo` access — recommended to run on a fresh Ubuntu 24.04 VPS.

---

📜 Menu Options

| Option | Description                                              |
|--------|----------------------------------------------------------|
| 1      | Change SSH port to 3022                                  |
| 2      | Configure UFW firewall                                   |
| 3      | Install + configure Suricata (IPS mode via NFQUEUE)     |
| 4      | Install + configure Fail2Ban (Suricata log monitoring)   |
| 5      | Fix NTP and DNS issues                                   |
| 6      | Install Let's Encrypt (Certbot for Nginx)                |
| 7      | Run all steps (full secure install)                      |
| 8      | Bonus hardening (auto updates, port scan detect, AV)     |
| 0      | Exit                                                     |

---

🔐 What This Protects You From

- Common brute-force SSH attacks  
- Unauthorized port scans & probing  
- Basic malware and rootkit infections  
- Known network exploits detected by Suricata  
- Misconfigured or forgotten firewall rules  

---

📁 Files

| File            | Purpose                             |
|-----------------|-------------------------------------|
| `vps-harden.sh` | Main interactive script             |
| `README.md`     | This readme                         |

---


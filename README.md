![image](https://github.com/user-attachments/assets/2ed41b25-7161-4308-9757-4d69400ce964)


🛡️ Ultimate Ubuntu 24.04 Server Hardening Script

This interactive, colorful Bash script secures your Ubuntu system with a one-stop menu of powerful tools including firewall configuration, IPS/IDS, Fail2Ban integration, rootkit scanners, Let's Encrypt support, and more.


✨ Features


- Change default SSH port to avoid brute-force attacks
- Configure UFW with sensible defaults
- Install & configure Suricata in IPS (NFQUEUE) mode
- Fail2Ban integration with Suricata alerts
- Auto-fix NTP and DNS resolution issues
- Let’s Encrypt certificate provisioning for Apache/Nginx
- Harden with:
  - Unattended security updates
  - Portsentry active scan protection (advanced stealth mode)
  - Rootkit Hunter and ClamAV
- System-wide status check for all services
- Fully interactive menu-based UI with color output
- 

🚀 Quick Start


```bash
sudo curl -sSL https://raw.githubusercontent.com/YourUsername/ubuntu-hardening/main/ubuntu-hardening.sh | bash
```


> ⚠️ Recommended to test on a fresh Ubuntu 24.04
> Compatible with Ubuntu 20.04 / 22.04 / 24.04


---

📋 Menu Options

```
1) Change SSH Port to 3022
2) Configure UFW (firewall)
3) Install and configure Suricata IPS
4) Install and configure Fail2Ban
5) Fix NTP and DNS resolution
6) Install Let's Encrypt for Apache/Nginx
7) Run ALL steps
8) Extra Hardening: Unattended Updates, PortSentry, Rootkit/AV
9) Show system hardening status
0) Exit
```

---

📦 What’s Installed

| Tool         | Purpose                              |
|--------------|--------------------------------------|
| `ufw`        | Host-based firewall                  |
| `suricata`   | Intrusion prevention (IPS) engine    |
| `fail2ban`   | Log-based banning system             |
| `portsentry` | Port-scan detector and blocker       |
| `rkhunter`   | Rootkit scanner                      |
| `clamav`     | Antivirus scanner                    |
| `certbot`    | SSL/TLS certificates via Let’s Encrypt |
| `unattended-upgrades` | Auto-install security patches |

---

💡 Tips

- SSH will move to port `3022`. Don’t forget to allow it in your client:
  ```bash
  ssh -p 3022 user@your-server-ip
  ```
- Review logs at:
  - `/var/log/suricata/fast.log`
  - `/var/log/fail2ban.log`
  - `/var/log/clamav/`
- Portsentry blocks show up in:
  - `/var/lib/portsentry/portsentry.blocked.*`

---


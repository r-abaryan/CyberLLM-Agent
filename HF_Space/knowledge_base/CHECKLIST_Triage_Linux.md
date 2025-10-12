# Linux Triage Checklist (Quick)

Host
- Processes: ps aux --forest, suspicious parents
- Persistence: crontab, systemd services, rc.local
- Network: ss -tulpn, iptables rules, unusual listeners
- Files: /tmp, /var/tmp, home dirs, SSH keys

Logs
- auth.log / secure; sudo usage; new users
- Syslog/journalctl anomalies; service restarts

Evidence
- Memory/disk artifacts if permitted
- Collect bash history and recent modified files

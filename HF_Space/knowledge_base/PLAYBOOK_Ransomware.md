# Ransomware Playbook (Condensed)

Immediate Actions
- Isolate affected hosts from network
- Block indicators (hashes, C2 domains/IPs)
- Disable compromised accounts; rotate credentials
- Preserve volatile evidence (memory, process lists)

Containment
- Segregate affected VLANs; restrict SMB/RDP
- Snapshot critical systems

Eradication
- Identify initial vector (phishing/RDP/exploit); patch
- Remove payloads and scheduled tasks/services

Recovery
- Restore from known-good backups; verify integrity
- Validate business apps and data consistency

Preventive Measures
- Harden RDP/remote access; MFA
- EDR policies to block ransomware behaviors
- Regular backup tests and least-privilege review

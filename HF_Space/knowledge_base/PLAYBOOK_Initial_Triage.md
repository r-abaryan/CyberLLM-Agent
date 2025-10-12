# Initial Triage Playbook

Use when a new suspicious event or alert is received.

1. Validate the alert
   - Confirm source (EDR/SIEM) and timestamp
   - Check duplicates and noise suppression
2. Scope quickly
   - Identify users, hosts, processes, network egress
   - Pull related logs (auth, DNS, proxy, EDR)
3. Capture indicators
   - IPs, domains, hashes, file paths, parent/child processes
4. Contain if warranted
   - Isolate host, disable account, block indicators
5. Preserve evidence
   - Snapshot, collect triage artifacts (proc list, netstat, autoruns)
6. Escalate per severity rubric
   - Notify IR channel, management, and stakeholders as defined

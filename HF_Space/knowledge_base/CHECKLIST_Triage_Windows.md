# Windows Triage Checklist (Quick)

Host
- Processes: tasklist /v, Parent/child anomalies
- Persistence: services, scheduled tasks, Run keys
- Network: netstat -ano, DNS cache
- Files: downloads/temp/startup folders, recent executables

Logs
- Security: logon types, failures, new services
- Sysmon: process creations, network, file events
- PowerShell: ScriptBlock logs

Evidence
- Memory capture (if policy permits)
- Artifact collection (prefetch, amcache, shimcache)

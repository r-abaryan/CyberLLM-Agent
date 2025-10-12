# Data Exfiltration Playbook (Condensed)

Immediate Actions
- Identify exfil channels (HTTPS, DNS, cloud storage)
- Block egress indicators (domains/IPs/buckets)
- Isolate suspicious endpoints/users

Containment
- Restrict outbound to known-good; enable TLS inspection if policy allows
- Increase logging on proxy/DNS/firewall

Eradication
- Remove exfil tools/tunnels; revoke API keys/tokens
- Patch exploited services; reset compromised creds

Recovery
- Validate data integrity; rotate secrets; notify stakeholders
- For regulated data, start legal/compliance workflows

Preventive Measures
- DLP policies; least privilege on data stores
- Egress allowlisting and anomaly detection

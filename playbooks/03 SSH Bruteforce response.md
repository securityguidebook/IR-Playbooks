# Playbook 03 — SSH Brute Force Response

**MITRE Tactic:** TA0006 — Credential Access
**MITRE Technique:** T1110.001 — Brute Force: Password Guessing
**Environment:** Linux servers / Azure VMs
**Typical Severity:** Medium → High (escalates if successful login confirmed)

---

## Trigger

This playbook is activated when:
- Wazuh / Sentinel rule fires on 5+ failed SSH logins from a single IP
- Syslog alert: repeated `Failed password` or `Invalid user` messages
- fail2ban reports a banned IP

---

## Severity Classification

| Condition | Severity |
|---|---|
| Failed attempts only, source IP is known scanner | Low |
| High-volume attempts from unknown IP | Medium |
| Attempts targeting root or privileged accounts | High |
| Successful login confirmed after failed attempts | Critical |

---

## Phase 1 — Immediate Triage (First 15 Minutes)

### 1.1 Confirm the alert
```bash
# Check auth logs directly on the affected host
sudo grep "Failed password" /var/log/auth.log | tail -50
sudo grep "Accepted password\|Accepted publickey" /var/log/auth.log | tail -20
```

In Sentinel/Wazuh dashboard:
```kql
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage has "Failed password" or SyslogMessage has "Invalid user"
| extend SourceIP = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize Attempts = count() by SourceIP, Computer
| sort by Attempts desc
```

### 1.2 Check if any login succeeded
```bash
sudo grep "Accepted" /var/log/auth.log | grep "<SOURCE_IP>"
```

**If a successful login is found → immediately escalate to Critical and jump to Phase 3.**

### 1.3 Check source IP reputation
- [VirusTotal](https://virustotal.com/gui/ip-address/<IP>)
- [AbuseIPDB](https://abuseipdb.com/check/<IP>)
- Note: most brute-force IPs will be flagged — check the **volume of reports** and **country of origin**

### 1.4 Check what accounts were targeted
```bash
sudo grep "Invalid user" /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -rn
```
Flag immediately if `root`, `admin`, or any known service account was targeted.

---

## Phase 2 — Containment

### 2.1 Block the source IP at firewall (immediate)
```bash
# UFW
sudo ufw deny from <SOURCE_IP> to any

# iptables
sudo iptables -I INPUT -s <SOURCE_IP> -j DROP
sudo iptables-save > /etc/iptables/rules.v4
```

### 2.2 Verify fail2ban is active
```bash
sudo fail2ban-client status sshd
# Should show: Currently banned IPs
```

If fail2ban is not installed:
```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban --now
```

### 2.3 If SSH root login is enabled — disable it now
```bash
sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## Phase 3 — Confirmed Compromise Response

If a successful login was detected after brute-force attempts:

### 3.1 Isolate the host immediately
```bash
# Azure — detach from network via portal or CLI
az vm nic remove --resource-group <RG> --vm-name <VM> --nics <NIC>
```

### 3.2 Capture volatile evidence before remediation
```bash
# Active connections at time of detection
sudo netstat -antp > /tmp/netstat_$(date +%F_%T).txt

# Running processes
sudo ps aux > /tmp/processes_$(date +%F_%T).txt

# Logged in users
sudo who > /tmp/who_$(date +%F_%T).txt
sudo last > /tmp/last_$(date +%F_%T).txt

# Crontabs (persistence check)
sudo crontab -l
sudo ls -la /etc/cron*
```

### 3.3 Check for persistence mechanisms
```bash
# New user accounts created
sudo grep "new user\|new group" /var/log/auth.log

# SSH authorized_keys modified
sudo find /home -name "authorized_keys" -newer /var/log/auth.log

# New SUID binaries
sudo find / -perm -4000 -type f 2>/dev/null
```

### 3.4 Escalate to senior engineer immediately

---

## Phase 4 — Evidence Collection

- [ ] Auth log excerpt showing failed and successful attempts
- [ ] Source IP reputation report (VirusTotal / AbuseIPDB screenshots)
- [ ] Targeted account list
- [ ] Firewall block confirmation
- [ ] Volatile evidence files (if compromise confirmed)
- [ ] Timeline of events

---

## Escalation Criteria

Escalate immediately if:
- Successful SSH login confirmed from brute-force source IP
- Root or privileged account targeted
- Evidence of post-access activity (new users, cron jobs, outbound connections)
- Multiple hosts targeted simultaneously

---

## Phase 5 — Remediation

- [ ] Source IP blocked at perimeter
- [ ] fail2ban configured and active
- [ ] Root SSH login disabled
- [ ] Password authentication disabled (key-only enforced)
- [ ] SSH port changed from 22 if high-volume scanning continues
- [ ] All passwords on targeted accounts rotated
- [ ] Patch any outdated SSH version

---

## Phase 6 — Post-Incident

```
Incident ID:
Affected Host(s):
Source IP(s):
Targeted Accounts:
Successful Login: Yes / No
Containment Time:
Evidence Collected:
Root Cause:
Recommendations:
  - [ ] Deploy Ansible hardening playbook across remaining hosts
  - [ ] Review firewall rules for unnecessary SSH exposure
  - [ ] Implement SSH jump host / bastion for all admin access
```

---

## References

- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)
- [Related KQL Rule: SSH Brute Force Detection](https://github.com/securityguidebook/kql-detection-rules/blob/main/rules/01-ssh-brute-force.md)
- [Related: Ansible SSH Hardening Playbook](https://github.com/securityguidebook/ansible-security-hardening)

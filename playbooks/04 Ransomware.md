# Playbook 04 — Ransomware Containment

**MITRE Tactic:** TA0040 — Impact
**MITRE Technique:** T1486 — Data Encrypted for Impact
**Also relevant:** T1490 — Inhibit System Recovery | T1489 — Service Stop
**Environment:** Windows endpoints, Azure, on-premises servers
**Typical Severity:** CRITICAL — treat as P1 from the moment of detection

---

## ⚠️ Critical Note Before Starting

Ransomware response is time-sensitive. Every minute of delay allows encryption to spread further. Read the entire playbook before starting, then execute fast. Do **not** attempt to decrypt or recover files until full containment is confirmed — recovery attempts on an active infection can accelerate damage.

**Do not pay the ransom without explicit authorisation from senior leadership and legal counsel.**

---

## Trigger

This playbook is activated when:
- Endpoint protection (Defender, CrowdStrike, etc.) raises a ransomware alert
- Users report files have been renamed with unknown extensions (e.g., `.locked`, `.encrypted`, `.WNCRY`)
- Ransom note files appear on file shares or desktops (`README.txt`, `HOW_TO_DECRYPT.html`, etc.)
- Mass file modification events detected across shared drives
- Azure Sentinel Rule 08 (Mass Resource Deletion) fires alongside endpoint alerts
- Helpdesk receives multiple simultaneous reports of inaccessible files

---

## Severity Classification

Ransomware is always **CRITICAL**. Sub-classify by scope:

| Scope | Classification |
|---|---|
| Single endpoint, isolated | Critical — Contained |
| Multiple endpoints, same network segment | Critical — Active Spread |
| Domain controller or file server affected | Critical — Severe |
| Cloud storage / Azure resources encrypted | Critical — Severe |
| Backup systems affected | Critical — Catastrophic |

---

## Phase 1 — Immediate Triage (First 10 Minutes)

Speed is everything. Run triage in parallel where possible.

### 1.1 Confirm the incident
- Locate the ransom note — photograph or screenshot it (note the ransomware family name if shown)
- Check file extensions on affected files — are they changed?
- Check if the infection is still actively encrypting (watch file modification timestamps)

### 1.2 Identify patient zero — which machine was hit first?

```kql
// Find the earliest file encryption events across endpoints
// Requires Defender for Endpoint or Sysmon logs

DeviceFileEvents
| where TimeGenerated > ago(2h)
| where ActionType == "FileModified" or ActionType == "FileRenamed"
| where FileName has_any (".locked", ".encrypted", ".enc", ".crypt", ".WNCRY", ".ransom")
    or FolderPath has "README" or FolderPath has "HOW_TO"
| summarize
    FirstEvent = min(TimeGenerated),
    AffectedFiles = count(),
    FolderPaths = make_set(FolderPath)
    by DeviceName, InitiatingProcessAccountName
| sort by FirstEvent asc
```

### 1.3 Check for lateral movement — how far has it spread?

```kql
// Look for suspicious network connections from affected host
// This helps identify if the ransomware is propagating via SMB or RDP

DeviceNetworkEvents
| where TimeGenerated > ago(2h)
| where DeviceName == "<PATIENT_ZERO_HOSTNAME>"
| where RemotePort in (445, 3389, 135, 139)  // SMB, RDP, RPC
| where ActionType == "ConnectionSuccess"
| summarize
    Connections = count(),
    RemoteHosts = make_set(RemoteIP)
    by DeviceName, RemotePort
| sort by Connections desc
```

### 1.4 Check if backup systems are reachable
- Immediately verify backup infrastructure is online and **isolate it from the network if possible**
- Check if VSS (Volume Shadow Copies) have been deleted:
```powershell
# Run on affected host or via remote session
vssadmin list shadows
# If output is empty — shadow copies have been deleted (common ransomware behaviour)
```

---

## Phase 2 — Containment (Minutes 10–30)

### 2.1 ISOLATE AFFECTED MACHINES — IMMEDIATELY

**Do not simply power off** — this can destroy forensic evidence and may interrupt decryption key recovery.

**Option A — Network isolation via Defender for Endpoint (fastest)**
```
Microsoft 365 Defender Portal →
Device inventory → [Affected Device] →
Actions → Isolate device
```

**Option B — Manual network isolation**
```powershell
# Disable all network adapters on the affected host
Get-NetAdapter | Disable-NetAdapter -Confirm:$false

# Or block all traffic via Windows Firewall
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
```

**Option C — Azure VM isolation (if cloud hosted)**
```powershell
# Remove the VM from its network via Azure CLI
az vm nic remove --resource-group <RG> --vm-name <VM> --nics <NIC_NAME>

# Or apply a deny-all NSG rule immediately
az network nsg rule create \
    --resource-group <RG> \
    --nsg-name <NSG_NAME> \
    --name DenyAllEmergency \
    --priority 100 \
    --direction Inbound \
    --access Deny \
    --protocol "*" \
    --source-address-prefixes "*" \
    --destination-port-ranges "*"
```

### 2.2 Isolate adjacent machines in the same network segment
- Any machine that had active SMB connections to patient zero should be treated as potentially infected
- Isolate these machines too, starting with servers and domain controllers

### 2.3 Disable affected user accounts
If the ransomware ran under a specific user context:
```powershell
# Disable account and revoke sessions
Disable-ADAccount -Identity "<USERNAME>"
Invoke-MgInvalidateUserRefreshToken -UserId "<UPN>"
```

### 2.4 Preserve the encryption process (do not kill it prematurely)
Counterintuitively — if you can safely capture a memory dump of the encrypting process, do it before killing it. Some ransomware families store the decryption key in memory.

```powershell
# Capture memory dump of the ransomware process (run as admin)
# Requires procdump from Sysinternals
procdump.exe -ma <PID_of_ransomware_process> C:\forensics\ransomware_memdump.dmp
```

Then terminate the process:
```powershell
Stop-Process -Id <PID> -Force
```

### 2.5 Disable shared drives and mapped network shares
```powershell
# Disable all SMB shares on affected server to stop encryption spreading
Get-SmbShare | Where-Object {$_.Name -ne "IPC$"} | Remove-SmbShare -Force
```

---

## Phase 3 — Evidence Collection

Capture before ANY remediation or recovery attempt. Evidence collected now supports forensics, insurance claims, law enforcement, and future prevention.

### 3.1 On each affected host, collect:
```powershell
# Create evidence folder
New-Item -ItemType Directory -Path C:\forensics

# Running processes at time of collection
Get-Process | Export-Csv C:\forensics\processes.csv

# Active network connections
netstat -anob > C:\forensics\netstat.txt

# Recently modified files (last 4 hours)
Get-ChildItem -Recurse -Path C:\ -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-4)} |
    Select-Object FullName, LastWriteTime, Length |
    Export-Csv C:\forensics\recent_files.csv

# Scheduled tasks (common persistence mechanism)
Get-ScheduledTask | Export-Csv C:\forensics\scheduled_tasks.csv

# Autorun entries
reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run C:\forensics\autoruns_hklm.reg
reg export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run C:\forensics\autoruns_hkcu.reg

# Event logs
wevtutil epl Security C:\forensics\Security.evtx
wevtutil epl System C:\forensics\System.evtx
wevtutil epl Application C:\forensics\Application.evtx
```

### 3.2 Identify the ransomware family
- Upload a ransom note sample (not an encrypted file) to [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
- Search the file extension on [No More Ransom](https://www.nomoreransom.org/) — a free decryption tool may exist
- Note the ransomware name — this determines whether decryption without paying is possible

### 3.3 Identify the initial access vector

```kql
// Check sign-in events around patient zero's first encryption activity
SigninLogs
| where TimeGenerated > ago(24h)
| where DeviceDetail has "<PATIENT_ZERO_HOSTNAME>" or UserPrincipalName == "<AFFECTED_USER>"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType
| sort by TimeGenerated asc
```

```kql
// Check for phishing email delivery before the incident
EmailEvents
| where TimeGenerated > ago(24h)
| where RecipientEmailAddress == "<AFFECTED_USER_EMAIL>"
| where DeliveryAction != "Blocked"
| project TimeGenerated, SenderFromAddress, Subject, Urls, AttachmentCount, DeliveryLocation
```

---

## Escalation Criteria

**Escalate to senior management and legal immediately if:**
- More than 5 endpoints affected
- Domain controller, file server, or backup systems affected
- Cloud environments (Azure/AWS) affected
- Exfiltration confirmed or suspected (double-extortion ransomware)
- The ransomware note includes a deadline or data leak threat

**External escalation contacts to prepare:**
- Cyber insurance provider — notify as early as possible (policy may require it)
- Legal counsel — especially if personal data may be affected (potential GDPR/Privacy Act notification obligation)
- Law enforcement — report to Australian Cyber Security Centre (ACSC) / local equivalent
- If OT/ICS systems affected — escalate to separate OT security team immediately

---

## Phase 4 — Eradication

Do not begin eradication until containment is fully confirmed and evidence is collected.

### 4.1 Identify and remove the ransomware payload
```powershell
# Run Windows Defender offline scan on isolated machine
Start-MpScan -ScanType FullScan
# Or boot from Windows Defender Offline media for deeply embedded malware
```

Upload a sample of the ransomware binary to VirusTotal for family identification if safe to do so.

### 4.2 Remove persistence mechanisms
```powershell
# Check and clean scheduled tasks added by ransomware
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | 
    Select-Object TaskName, TaskPath, State

# Check startup registry keys
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Check for new local admin accounts created by the ransomware
Get-LocalGroupMember -Group "Administrators"
```

### 4.3 Reset all credentials
- All accounts that logged into affected machines must have passwords reset
- Service accounts on affected systems must have credentials rotated
- Domain admin credentials must be rotated if a domain controller was affected

---

## Phase 5 — Recovery

**Only begin recovery after eradication is confirmed.**

### 5.1 Attempt decryption before reimaging
- Check [No More Ransom](https://www.nomoreransom.org/) for free decryptors
- If memory dump captured in Phase 2, provide to ransomware analysts for key extraction

### 5.2 Restore from backup
- Verify backup integrity before restoring — confirm backup predates the infection
- Restore to clean, freshly built machine where possible — not the infected host
- Verify restored files are not encrypted before bringing systems back online

### 5.3 Staged recovery
Bring systems back online in priority order:
1. Domain controllers / identity infrastructure
2. Core business applications
3. File servers (with monitoring active)
4. User endpoints

### 5.4 Monitor intensively for 72 hours post-recovery
```kql
// Watch for re-encryption attempts after recovery
DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType == "FileRenamed"
| where FileName matches regex @"\.[a-z0-9]{4,10}$"
| where FolderPath !has "\\Temp\\" and FolderPath !has "\\AppData\\"
| summarize count() by DeviceName, bin(TimeGenerated, 5m)
| where count_ > 50
```

---

## Phase 6 — Post-Incident

### Immediate reporting obligations to check:
- **Australia:** Report to ACSC at cyber.gov.au (recommended for Critical Infrastructure)
- **GDPR (if applicable):** 72-hour notification window if EU personal data affected
- **Cyber insurance:** Notify within policy-specified timeframe
- **Board / Senior leadership:** Executive summary required

### Incident Report Fields
```
Incident ID:
Date/Time First Activity Detected:
Date/Time Detected by Security Team:
Date/Time Contained:
Date/Time Eradicated:
Date/Time Recovery Completed:

Patient Zero (hostname + user):
Affected Endpoints (count + names):
Servers Affected: Yes / No
  If yes — which:
Domain Controller Affected: Yes / No
Backup Systems Affected: Yes / No
Cloud Resources Affected: Yes / No
Data Exfiltration Confirmed/Suspected: Yes / No / Unknown

Ransomware Family:
Ransom Amount Demanded:
Ransom Paid: Yes / No (requires C-suite authorisation)

Initial Access Vector:
  [ ] Phishing email
  [ ] Exposed RDP
  [ ] Compromised credentials
  [ ] Malicious attachment
  [ ] Supply chain / third party
  [ ] Unknown

Data Loss: Yes / No
  If yes — data types affected:

Timeline of Events:
  [List key events with timestamps]

Actions Taken:

Root Cause:

Lessons Learned:

Recommendations:
  [ ] Patch exposed RDP / disable if not required
  [ ] Enforce MFA on all accounts
  [ ] Implement network segmentation to limit spread
  [ ] Review and test backup recovery procedures
  [ ] Deploy EDR on all endpoints
  [ ] Conduct phishing simulation training
```

### Post-incident review (within 2 weeks)
- Full incident timeline review with all involved parties
- Gap analysis: what controls failed? what worked?
- Update detection rules and playbooks based on findings
- Review backup and recovery procedures — test them if not recently tested

---

## References

- [MITRE ATT&CK T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [No More Ransom — Free decryptors](https://www.nomoreransom.org/)
- [ID Ransomware — Identify ransomware family](https://id-ransomware.malwarehunterteam.com/)
- [ACSC — Ransomware response guide](https://www.cyber.gov.au/threats/types-threats/ransomware)
- [Microsoft — Recovering from ransomware](https://learn.microsoft.com/en-us/security/ransomware/ransomware-recovery)
- [Sysinternals — procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)
- [Related KQL Rule: Azure Resource Mass Deletion](https://github.com/securityguidebook/kql-detection-rules/blob/main/rules/rule-08-azure-resource-mass-deletion.md)
- [Related KQL Rule: Suspicious PowerShell Execution](https://github.com/securityguidebook/kql-detection-rules/blob/main/rules/rule-07-suspicious-powershell.md)
- [Related: Playbook 01 — Phishing Response](01-phishing.md) (common initial access vector)
- [Related: Playbook 02 — Suspicious Azure Sign-In](02-suspicious-azure-signin.md) (post-compromise cloud activity)

# Playbook 01 — Phishing Email Response

**MITRE Tactic:** TA0001 — Initial Access
**MITRE Technique:** T1566 — Phishing
**Environment:** Microsoft 365 / Exchange Online
**Typical Severity:** Medium → High (escalates if link clicked or credentials entered)

---

## Trigger

This playbook is activated when:
- A user reports a suspicious email via the Phish Alert Button or helpdesk ticket
- An email security tool (Defender for Office 365, Proofpoint, etc.) flags a delivered message
- A Sentinel analytics rule detects a known phishing domain in email logs

---

## Severity Classification

| Condition | Severity |
|---|---|
| Suspicious email reported, no interaction | Low |
| User clicked link but did not enter credentials | Medium |
| User entered credentials on phishing page | High |
| Multiple users affected / credentials confirmed stolen | Critical |

---

## Phase 1 — Immediate Triage (First 15 Minutes)

### 1.1 Gather email artefacts
Collect the following from the reported email:
- [ ] Sender display name and actual email address (check for spoofing)
- [ ] Reply-to address (often different from sender)
- [ ] Email subject line and timestamp
- [ ] All URLs in the body (do NOT click — copy from message header/source)
- [ ] Any attachments (filename, hash if available)

### 1.2 Check email headers
```
Received: headers — trace delivery path
Authentication-Results: — check SPF, DKIM, DMARC pass/fail
X-Originating-IP: — actual sending IP
```

### 1.3 Analyse the URL/domain
- Query domain in [VirusTotal](https://virustotal.com)
- Check domain age in [whois](https://who.is) — new domains (<30 days) are high risk
- Check IP reputation in [AbuseIPDB](https://abuseipdb.com)
- Search for the domain in Sentinel:
```kql
EmailEvents
| where TimeGenerated > ago(24h)
| where Urls has "<PHISHING_DOMAIN>"
| project TimeGenerated, RecipientEmailAddress, SenderFromAddress, Subject, Urls
```

### 1.4 Determine blast radius — who else received it?
```kql
EmailEvents
| where TimeGenerated > ago(24h)
| where SenderFromAddress == "<SENDER_ADDRESS>"
    or Subject == "<SUBJECT_LINE>"
| summarize Recipients = make_set(RecipientEmailAddress), Count = count()
```

---

## Phase 2 — Containment

### 2.1 Remove the email from all mailboxes
In Microsoft 365 Defender / Purview:
```
Content Search → New Search → Search by sender / subject / date
→ Actions → Purge → Soft delete (recoverable) or Hard delete
```

Or via PowerShell:
```powershell
# Requires Compliance Search permissions
New-ComplianceSearch -Name "PhishPurge01" -ExchangeLocation All `
  -ContentMatchQuery "From:<sender> AND Subject:<subject>"
Start-ComplianceSearch -Identity "PhishPurge01"
New-ComplianceSearchAction -SearchName "PhishPurge01" -Purge -PurgeType SoftDelete
```

### 2.2 Block the sender domain
In Exchange admin or Defender:
- Add sender domain to blocked senders list
- Add phishing URL/domain to Tenant Allow/Block List

### 2.3 If user clicked the link — check for credential entry
Ask the user directly: *"Did you enter any username or password on the page that opened?"*

If yes → escalate to **High** and move to Phase 3 immediately.

---

## Phase 3 — Credential Compromise Response (if applicable)

### 3.1 Immediately reset the affected account
```powershell
# Force password reset and revoke all sessions
Set-AzureADUser -ObjectId "<UPN>" -PasswordPolicies DisablePasswordExpiration
Revoke-AzureADUserAllRefreshToken -ObjectId "<UPN>"
```

### 3.2 Check for post-compromise activity
```kql
// Suspicious inbox rules created after phishing timestamp
OfficeActivity
| where TimeGenerated > ago(2h)
| where UserId == "<UPN>"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| project TimeGenerated, Operation, Parameters
```

```kql
// New OAuth app consents
AuditLogs
| where TimeGenerated > ago(2h)
| where InitiatedBy has "<UPN>"
| where OperationName == "Consent to application"
```

### 3.3 Check for impossible travel / anomalous sign-ins
```kql
SigninLogs
| where TimeGenerated > ago(4h)
| where UserPrincipalName == "<UPN>"
| where ResultType == 0
| project TimeGenerated, IPAddress, Location, AppDisplayName, DeviceDetail
```

### 3.4 Force MFA re-registration
Revoke existing MFA methods and require re-registration from a trusted device.

---

## Phase 4 — Evidence Collection

Before closing, capture:
- [ ] Screenshot of original phishing email
- [ ] VirusTotal / AbuseIPDB results for domain and IP
- [ ] Email header analysis output
- [ ] Sentinel query results showing blast radius
- [ ] Confirmation of email purge completion
- [ ] Sign-in logs for affected user (if applicable)
- [ ] Any inbox rules or OAuth consents found

---

## Escalation Criteria

Escalate to senior security engineer or manager if:
- Credentials confirmed entered (High severity)
- More than 5 users affected
- Evidence of post-compromise activity (inbox rules, OAuth grants, data access)
- Executive / privileged account targeted
- Suspected targeted spearphishing (not mass campaign)

---

## Phase 5 — Remediation & Recovery

- [ ] Confirm phishing email purged from all mailboxes
- [ ] Confirm sender domain blocked
- [ ] Confirm affected user password reset and sessions revoked
- [ ] Remove any malicious inbox rules discovered
- [ ] Revoke any suspicious OAuth app consents
- [ ] Notify affected users with guidance (do not reuse compromised password)

---

## Phase 6 — Post-Incident

### Incident report fields
```
Incident ID:
Date/Time Detected:
Date/Time Contained:
Affected Users:
Attack Vector:
Indicators of Compromise (IOCs):
  - Sender domain:
  - Phishing URL:
  - Sending IP:
Actions Taken:
Root Cause:
Lessons Learned:
Recommendations:
```

### Recommended follow-up actions
- Submit phishing domain to Microsoft SSTIC / Google Safe Browsing
- Share IOCs with threat intelligence feed if applicable
- Review email filtering rules — did existing controls miss this?
- Consider targeted security awareness training for affected users

---

## References

- [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)
- [Microsoft — Respond to a compromised email account](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account)
- [Related KQL Rule: Suspicious Azure Sign-In](https://github.com/securityguidebook/kql-detection-rules/blob/main/rules/04-suspicious-azure-signin.md)

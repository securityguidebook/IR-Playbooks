# Playbook 02 — Suspicious Azure Sign-In Response

**MITRE Tactic:** TA0001 — Initial Access | TA0006 — Credential Access
**MITRE Technique:** T1078.004 — Valid Accounts: Cloud Accounts
**Environment:** Azure AD / Entra ID, Microsoft 365
**Typical Severity:** Medium → Critical (escalates rapidly if post-access activity found)

---

## Trigger

This playbook is activated when:
- Microsoft Sentinel analytics rule fires on anomalous sign-in behaviour
- Azure AD Identity Protection raises a risky sign-in alert
- Rule 02 (Impossible Travel) or Rule 04 (Suspicious Azure Sign-In) from the KQL Detection Library fires
- A user reports they received an unexpected MFA prompt they did not initiate
- Security team observes a sign-in from a high-risk country or anonymising proxy

---

## Severity Classification

| Condition | Severity |
|---|---|
| Suspicious sign-in flagged, no post-access activity | Low |
| Sign-in from new country/IP, user cannot confirm | Medium |
| Impossible travel confirmed, credentials likely compromised | High |
| Post-access activity found (inbox rules, OAuth grants, data access) | Critical |
| Privileged/admin account affected | Critical — escalate immediately |

---

## Phase 1 — Immediate Triage (First 15 Minutes)

### 1.1 Pull the sign-in details from Sentinel

```kql
// Get full sign-in context for the flagged account
SigninLogs
| where TimeGenerated > ago(4h)
| where UserPrincipalName == "<UPN>"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    CountryOrRegion = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city),
    AppDisplayName,
    ClientAppUsed,
    DeviceDetail,
    ResultType,
    ResultDescription,
    RiskLevelDuringSignIn,
    RiskLevelAggregated,
    AuthenticationRequirement
| sort by TimeGenerated desc
```

### 1.2 Check for impossible travel

```kql
// Detect sign-ins from multiple countries within 2 hours
SigninLogs
| where TimeGenerated > ago(2h)
| where UserPrincipalName == "<UPN>"
| where ResultType == 0
| summarize
    Countries = make_set(tostring(LocationDetails.countryOrRegion)),
    IPs = make_set(IPAddress),
    Apps = make_set(AppDisplayName),
    SignInCount = count()
    by UserPrincipalName
| where array_length(Countries) > 1
```

### 1.3 Check the source IP reputation
- Query IP in [VirusTotal](https://virustotal.com)
- Query IP in [AbuseIPDB](https://abuseipdb.com)
- Check the ASN — datacenter/hosting ASN is more suspicious than residential
- Check if IP belongs to a known VPN or Tor exit node

### 1.4 Determine the user's actual location
- Call or message the user directly: *"Are you currently travelling or using a VPN?"*
- If unreachable — treat as High severity and proceed to containment
- If they confirm they are NOT in the flagged location → escalate to High immediately

### 1.5 Check the device used
```kql
// Was the sign-in from a known, managed device?
SigninLogs
| where TimeGenerated > ago(4h)
| where UserPrincipalName == "<UPN>"
| extend
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceName = tostring(DeviceDetail.displayName),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    IsManaged = tostring(DeviceDetail.isManaged),
    OS = tostring(DeviceDetail.operatingSystem)
| project TimeGenerated, DeviceId, DeviceName, IsCompliant, IsManaged, OS, IPAddress
```

A sign-in from an unmanaged or unknown device is a significant escalation indicator.

---

## Phase 2 — Containment

### 2.1 Revoke all active sessions immediately
```powershell
# Revoke all refresh tokens — forces re-authentication on all devices
# Requires Azure AD PowerShell or Microsoft Graph

# Via Azure AD PowerShell
Connect-AzureAD
Revoke-AzureADUserAllRefreshToken -ObjectId "<UPN>"

# Via Microsoft Graph (PowerShell)
Connect-MgGraph -Scopes "User.ReadWrite.All"
Invoke-MgInvalidateUserRefreshToken -UserId "<UPN>"
```

### 2.2 Block sign-in (if compromise confirmed or user unreachable)
```powershell
# Block the account from signing in
Set-AzureADUser -ObjectId "<UPN>" -AccountEnabled $false
```

Or via Azure Portal:
**Azure AD → Users → [User] → Block sign-in → Yes**

### 2.3 Force MFA step-up for the session (if not blocking outright)
In Azure AD Conditional Access — create a temporary policy requiring MFA from a trusted location for this specific user while investigation continues.

### 2.4 Dismiss or confirm the risky sign-in in Identity Protection
**Azure AD → Security → Identity Protection → Risky sign-ins → [Event] → Confirm compromise or Dismiss**

Confirming compromise triggers additional automated risk responses if configured.

---

## Phase 3 — Post-Access Investigation

Run these queries regardless of whether the sign-in was confirmed malicious. You need to know what was accessed.

### 3.1 Check for malicious inbox rules (common first-persistence move)
```kql
// Look for inbox rules created around the time of the suspicious sign-in
OfficeActivity
| where TimeGenerated > ago(24h)
| where UserId == "<UPN>"
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| project
    TimeGenerated,
    UserId,
    Operation,
    Parameters,
    ClientIP
| sort by TimeGenerated asc
```

**Red flag rules to look for:**
- Forward all email to an external address
- Delete emails containing keywords like "invoice", "password", "IT"
- Move emails to obscure folders to hide them from the user

### 3.2 Check for new OAuth application consents
```kql
// Attackers often grant themselves persistent access via OAuth apps
AuditLogs
| where TimeGenerated > ago(24h)
| where InitiatedBy has "<UPN>"
| where OperationName in ("Consent to application", "Add app role assignment to service principal")
| project
    TimeGenerated,
    OperationName,
    TargetResources,
    InitiatedBy,
    Result
```

### 3.3 Check for new MFA methods registered (persistence)
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where InitiatedBy has "<UPN>" or TargetResources has "<UPN>"
| where OperationName has "authentication method" or OperationName has "MFA"
| project TimeGenerated, OperationName, TargetResources, Result
```

### 3.4 Check for sensitive data access (SharePoint, OneDrive)
```kql
OfficeActivity
| where TimeGenerated > ago(24h)
| where UserId == "<UPN>"
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")
| summarize
    FilesAccessed = count(),
    FileNames = make_set(SourceFileName),
    Sites = make_set(SiteUrl)
    by UserId, ClientIP
| sort by FilesAccessed desc
```

### 3.5 Check for privilege escalation or role changes
```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where InitiatedBy has "<UPN>"
| where OperationName has "role" or OperationName has "privilege" or OperationName has "admin"
| project TimeGenerated, OperationName, TargetResources, Result
```

---

## Phase 4 — Evidence Collection

Before any remediation, capture the following:

- [ ] Full sign-in log export for the affected account (last 24–72 hours)
- [ ] Screenshot of the suspicious sign-in event in Sentinel/Identity Protection
- [ ] VirusTotal and AbuseIPDB results for the source IP
- [ ] Any inbox rules discovered (export the full rule configuration)
- [ ] Any OAuth app consents granted (app name, permissions, date)
- [ ] Any new MFA methods registered (method type, date added)
- [ ] File access log if sensitive data was accessed
- [ ] Timeline of events from first anomalous sign-in to detection

---

## Escalation Criteria

Escalate to senior security engineer or manager immediately if:
- Admin, privileged, or executive account is affected
- Post-access activity found: inbox rules, OAuth grants, privilege changes
- Evidence of data access or exfiltration
- Multiple accounts affected (indicates credential stuffing or internal spread)
- Attacker revoked legitimate MFA methods and registered their own

---

## Phase 5 — Remediation & Recovery

- [ ] Account sign-in blocked or sessions revoked
- [ ] Password reset from a trusted, managed device
- [ ] All MFA methods audited — remove unknown methods, re-register from scratch
- [ ] Malicious inbox rules deleted
- [ ] Malicious OAuth app consents revoked:
  **Azure AD → Enterprise Applications → [App] → Permissions → Revoke**
- [ ] Any privilege changes made by the attacker reversed
- [ ] Conditional Access policy reviewed — tighten if gaps identified
- [ ] User informed and educated on phishing/credential safety

---

## Phase 6 — Post-Incident

### Incident Report Fields
```
Incident ID:
Date/Time Detected:
Date/Time Contained:
Affected Account(s):
Account Type (user / admin / service):
Source IP:
Source Country:
Sign-in Risk Level (Azure AD):
Post-Access Activity Found: Yes / No
  If yes — detail:
Actions Taken:
Root Cause (phishing / credential stuffing / password spray / unknown):
Indicators of Compromise:
  - IP Address:
  - User Agent:
  - OAuth App (if applicable):
Lessons Learned:
Recommendations:
```

### Recommended Follow-Up
- Review Conditional Access policies — was this sign-in blocked or allowed? Should it have been blocked?
- Consider requiring compliant device for all cloud app access
- Check if other accounts signed in from the same source IP
- If phishing confirmed — trigger Playbook 01 (Phishing) for the initial access vector
- Submit source IP to threat intelligence feeds

---

## References

- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [Microsoft — Investigate risky users](https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk)
- [Microsoft — Responding to a compromised email account](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account)
- [Related KQL Rule: Impossible Travel Detection](https://github.com/securityguidebook/kql-detection-rules/blob/main/rules/rule-02-impossible-travel.md)
- [Related KQL Rule: MFA Fatigue Detection](https://github.com/securityguidebook/kql-detection-rules/blob/main/rules/rule-06-mfa-fatigue.md)
- [Related: Playbook 01 — Phishing Response](01-phishing.md) (often the root cause)

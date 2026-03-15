# Incident Response Playbook Library

> Professional incident response runbooks for common cyber security threats — structured for SOC analysts to follow under pressure.

![Type](https://img.shields.io/badge/Type-Blue%20Team-blue)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Environment](https://img.shields.io/badge/Environment-Azure%20%7C%20M365%20%7C%20Linux-teal)

---

## About

These playbooks are based on incident types I handled directly as a Security Engineer at a managed security services provider (Log(N) Pacific) and Information Security Analyst at Sony PlayStation. They follow a consistent structure so any SOC analyst can pick them up and execute without ambiguity.

Every playbook covers:
- **Trigger** — what fires this playbook
- **Severity classification** — how to rate the incident
- **Immediate triage** — first 15 minutes
- **Containment steps** — stop the bleeding
- **Evidence collection** — what to capture before you remediate
- **Escalation criteria** — when to call someone senior
- **Remediation** — how to fully resolve
- **Post-incident** — lessons learned, reporting

---

## Playbook Index

| # | Playbook | Environment | MITRE Tactic |
|---|----------|-------------|--------------|
| 01 | [Phishing Email Response](playbooks/01-phishing.md) | M365 / Exchange | Initial Access |
| 02 | [Suspicious Azure Sign-In](playbooks/02-suspicious-azure-signin.md) | Azure AD | Credential Access |
| 03 | [SSH Brute Force Response](playbooks/03-ssh-brute-force.md) | Linux | Credential Access |
| 04 | [Ransomware Containment](playbooks/04-ransomware.md) | Windows / Azure | Impact |

---

## How to Use These

These are designed to be used as **live documents during an incident**. Open the relevant playbook, work through it top to bottom, and fill in the incident ticket fields as you go.

For teams using Sentinel or ServiceNow, the KQL queries embedded in each playbook can be run directly in your SIEM to gather evidence at each stage.

---

## Companion Projects

- [KQL Detection Rules](https://github.com/securityguidebook/kql-detection-rules) — the Sentinel rules that trigger these playbooks
- [Azure Honey Net SOC](https://github.com/securityguidebook/Azure-Honey-Net-SOC) — the lab environment used to test these scenarios

---

## Author

**Pawarid Tupmongkol** | [LinkedIn](https://linkedin.com/in/pawaridtupmongkol) | [GitHub](https://github.com/securityguidebook)

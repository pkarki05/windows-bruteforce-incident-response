
## Overview

This project documents a cybersecurity incident investigation involving suspected **Brute Force / Password Spraying activity** against a Windows host.

The investigation was performed using **Splunk** to analyze Windows Security Event Logs exported in CSV format. The findings were then mapped to the **NIST SP 800-61 incident response lifecycle**.

The purpose of this project is to demonstrate practical skills in:

* Windows security log analysis
* Splunk / SIEM investigation
* Incident detection and analysis
* Indicators of Compromise (IoCs) identification
* Brute-force and password-spraying detection
* Incident containment and remediation planning
* Incident response documentation
* NIST SP 800-61 lifecycle mapping

---

## Incident Summary

| Attribute              | Details                             |
| ---------------------- | ----------------------------------- |
| Incident Type          | Brute Force / Password Spraying     |
| Target Host            | `DESKTOP-2N2ATE`                    |
| Log Source             | Windows Security Event Logs         |
| Analysis Platform      | Splunk                              |
| Operating Environment  | Kali Linux                          |
| Primary Event ID       | `4625` — Failed Logon               |
| Logon Type             | Type 3 — Network                    |
| Total Failed Attempts  | 62                                  |
| Unique Usernames       | 24                                  |
| Unique Source IPs      | 10                                  |
| Primary Target Account | `ADMINISTRATOR`                     |
| ADMINISTRATOR Attempts | 40 of 62                            |
| Observed Time Window   | 17 June 2026, 22:38:22–22:53:49 UTC |

The investigation identified a concentrated series of failed authentication attempts against the Windows host.

The `ADMINISTRATOR` account was targeted in **40 of the 62 recorded failed logons**, representing approximately **64.5%** of the observed attempts.

No successful `Event ID 4624` logon from the identified attacking IP addresses was observed in the analyzed dataset during the investigated period.

---

## Investigation Objectives

The investigation focused on:

1. Identifying abnormal authentication activity.
2. Determining the volume and timeframe of failed logons.
3. Identifying targeted usernames.
4. Identifying source IP addresses associated with the activity.
5. Determining whether successful authentication was observed.
6. Assessing the apparent scope of the activity.
7. Mapping the response to the NIST SP 800-61 lifecycle.
8. Developing containment, eradication, recovery, and preventative recommendations.

---

## Detection & Analysis

### Windows Event ID 4625

The primary indicator identified during the investigation was:

**Event ID 4625 — An account failed to log on**

The analysis identified:

* 62 failed authentication attempts.
* 24 unique usernames targeted.
* 10 unique source IP addresses.
* A significant concentration of attempts against the `ADMINISTRATOR` account.
* Activity occurring within approximately 15 minutes.

### Source IP Analysis

Three prominent source IP addresses were identified:

| Source IP       | Attempts | Location noted in investigation |
| --------------- | -------: | ------------------------------- |
| `103.165.78.91` |       27 | India                           |
| `185.118.79.30` |       19 | Latvia                          |
| `45.238.132.70` |        8 | Brazil                          |

The original investigation also used VirusTotal to review the reputation of the identified IP addresses.

The investigation notes recorded malicious reports associated with:

* `185.118.79.30`
* `45.238.132.70`

The IP `103.165.78.91` was described as suspicious despite being reported as clean in the investigation.

---

## Splunk Analysis

The investigation used Splunk searches to aggregate and investigate the Windows logs.

Examples of the searches used include:

```spl
index=windows | stats count by Id
```

```spl
index=windows | stats count by Machinename
```

```spl
index=windows | stats count AS Attempts by Username
| sort -Attempts
| head 5
```

```spl
index=windows Id=4625 Source_IP!="-"
| stats count AS Attempts by Source_IP
| sort -Attempts
| head 5
```

```spl
index=windows Id=4625
| stats dc(Username) AS Unique_User_Name
```

```spl
index=windows
| stats min(_time) as Start_Time, max(_time) as End_Time
```

These searches were used to establish the event volume, targeted accounts, source IP distribution, and incident timeframe.

---

## Indicators of Compromise

| Indicator       | Value            |
| --------------- | ---------------- |
| Event ID        | `4625`           |
| Logon Type      | `3`              |
| Target Host     | `DESKTOP-2N2ATE` |
| Primary Account | `ADMINISTRATOR`  |
| Source IP       | `103.165.78.91`  |
| Source IP       | `185.118.79.30`  |
| Source IP       | `45.238.132.70`  |

Additional usernames identified in the investigation included:

```text
ACCOUNTS
BACKUP
ROOT
ALEX
STUDENT
CERBERUS
```

---

## NIST SP 800-61 Incident Response Lifecycle

The investigation was mapped to the following incident response phases.

### 1. Preparation

Recommended preparation controls include:

* Strong password policies
* Account lockout policies
* MFA for administrative access
* Restricted exposure of administrative services
* Centralized Windows logging
* SIEM monitoring and alerting
* Endpoint telemetry

### 2. Detection & Analysis

The investigation identified:

* A spike in Event ID 4625 failures.
* Multiple source IP addresses.
* Multiple targeted usernames.
* Repeated attempts against the `ADMINISTRATOR` account.
* Network-based authentication activity.

### 3. Containment

Recommended containment actions include:

* Blocking identified malicious source IP addresses.
* Protecting or temporarily locking targeted high-risk accounts.
* Monitoring for additional source IP addresses.
* Reviewing network exposure of administrative services.

### 4. Eradication & Recovery

Recommended remediation includes:

* Removing unnecessary public exposure of RDP/SMB.
* Requiring VPN and MFA for remote administration.
* Reviewing account credentials and permissions.
* Deploying LAPS where appropriate.
* Implementing stronger authentication controls.
* Validating that successful authentication did not occur from identified attacking sources.

### 5. Post-Incident Activity

Recommended improvements include:

* Rate-based Splunk detection rules.
* Improved endpoint telemetry.
* Sysmon integration.
* Stronger account protection.
* Administrative access restrictions.
* Updated incident-response playbooks.
* Zero Trust and phishing-resistant MFA considerations.

---

## Key Findings

The investigation established the following observations:

* **62** failed logon events were recorded.
* The activity occurred over approximately **15 minutes**.
* **24 unique usernames** were targeted.
* **10 unique source IP addresses** were identified.
* The `ADMINISTRATOR` account represented **40 of 62 attempts**.
* Three prominent external IP addresses accounted for 54 of the 62 attempts.
* The observed activity was consistent with automated credential-guessing behavior.
* No successful `Event ID 4624` logon from the identified attacking IPs was observed in the analyzed dataset.

The evidence supports attempted unauthorized access. It does **not**, by itself, establish that the host was successfully compromised or that data was accessed.

---

## Security Recommendations

### Immediate Controls

* Implement account lockout protections.
* Block confirmed malicious source IPs where appropriate.
* Review accounts targeted during the attack.
* Increase monitoring for continued authentication attempts.

### Medium-Term Controls

* Remove direct public exposure of administrative services.
* Require VPN and MFA for remote administrative access.
* Enable Network Level Authentication where applicable.
* Integrate Sysmon telemetry with Splunk.
* Create automated failed-login detection rules.

### Long-Term Controls

* Deploy LAPS for local administrator password management.
* Disable or rename built-in administrative accounts where appropriate.
* Implement phishing-resistant MFA such as FIDO2/WebAuthn.
* Consider Zero Trust Network Access for remote administration.
* Improve centralized security monitoring and correlation.

---

## Repository Structure

```text
windows-bruteforce-incident-response/
│
├── README.md
│
├── report/
│   └── Incident_Response_Report_NIST_SP_800-61.docx
│
├── logs/
│   └── windows_logs.csv
│
├── screenshots/
│   ├── splunk-event-4625.png
│   ├── source-ip-analysis.png
│   ├── username-analysis.png
│   ├── ip-reputation-analysis.png
│   └── timeline-analysis.png
│
└── queries/
    └── splunk_queries.txt
```

---

## Evidence & Screenshots

The repository can include screenshots demonstrating the investigation process in Splunk.

Recommended screenshots:

1. Event ID 4625 event count
2. Unique source IP analysis
3. Targeted username analysis
4. Top attacking IP addresses
5. IP reputation analysis
6. Incident timeframe
7. Event ID 4624 validation
8. Relevant containment or remediation evidence



## Limitations

This investigation is based on the supplied Windows Security Event Log dataset.

The available evidence does not independently establish:

* The attacker's identity.
* The complete external infrastructure used by the attacker.
* Whether credentials were successfully obtained outside the analyzed dataset.
* Whether data was accessed or exfiltrated.
* The complete enterprise-wide scope of the activity.
* Exact discovery, declaration, containment, eradication, or resolution timestamps.

Additional evidence such as EDR telemetry, firewall logs, VPN logs, authentication infrastructure logs, and network telemetry would be required for a broader compromise assessment.

---

## References

1. NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide.
2. MITRE ATT&CK — T1110: Brute Force.
3. Microsoft Learn — Windows Security Event ID 4625.
4. VirusTotal — Threat Intelligence and IP Reputation.
5. Splunk Documentation — Search Processing Language (SPL).


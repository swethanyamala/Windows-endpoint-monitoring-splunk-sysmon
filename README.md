# Windows & Linux Endpoint Monitoring & Threat Detection
### Splunk Enterprise + Sysmon | SOC Detection Lab

> **Built for:** Small businesses and IT teams that need endpoint threat visibility without enterprise EDR costs.

---

## What This Does

Production-style Windows and Linux endpoint monitoring using **Splunk Enterprise** and **Sysmon** — collects, parses, and alerts on suspicious activity with MITRE ATT&CK mapping.

**Detects:**
- Malicious PowerShell execution and script-based attacks
- Binary masquerading (renamed executables evading detection)
- Credential dumping via LSASS memory access
- Unauthorized logins and brute force attempts (Windows and Linux)
- Suspicious file drops in temp/startup directories

---

## Architecture

## Data Ingestion Pipeline

### Windows Endpoint Pipeline

```text
Windows Endpoint
      │
      ▼
    Sysmon
      │
      ▼
Windows Event Logs
      │
      ▼
Splunk Universal Forwarder
      │
      ▼
Splunk Enterprise (index=endpoint)
      │
      ├── Detection Rules
      ├── Alerts
      └── Dashboards
```

### Linux Endpoint Pipeline

```text
Ubuntu Linux
      │
      ├── /var/log/auth.log
      └── /var/log/syslog
            │
            ▼
Splunk Universal Forwarder
            │
            ▼
Splunk Enterprise (index=linux)
            │
            ├── Failed Login Detection
            ├── SSH Monitoring
            └── Log Analysis Dashboard
```

### Data Sources Collected

* Sysmon Operational Logs
* Windows Security Logs
* Windows System Logs
* Linux auth.log
* Linux syslog

### Purpose

This SOC lab demonstrates end-to-end log ingestion, monitoring, detection engineering, and alerting across Windows and Linux endpoints using Splunk Enterprise and Sysmon.

**Log sources collected:**
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` — process, network, file, DNS
- `WinEventLog:Security` — logins, account changes, policy violations
- `WinEventLog:System` — services, drivers, system errors
- `/var/log/auth.log` — Linux authentication and SSH events

---

## Detections Demonstrated

| Attack Technique | MITRE ID | Log Source & Event ID | Detection Query | Severity |
|---|---|---|---|---|
| PowerShell bypass execution | T1059.001 | Sysmon: EventCode=1 | `powershell.exe` + `-ExecutionPolicy Bypass` | High |
| Binary masquerading (renamed exe) | T1036.003 | Sysmon: EventCode=1 | Image name ≠ OriginalFileName | High |
| LSASS credential dumping | T1003.001 | Sysmon: EventCode=8 | Remote thread access into `lsass.exe` | Critical |
| File drop in temp directory | T1105 | Sysmon: EventCode=11 | File creation in `%TEMP%` or `%APPDATA%` | Medium |
| Failed login brute force (Windows) | T1110 | Security: EventCode=4625 | 5+ failed logins within 60 seconds | High |
| SSH brute force (Linux) | T1110 | auth.log: "Failed password" | 5+ failures in 60s from one IP | High |
| Successful login after failures | T1078 | Security: EventCode=4624 | Login success following failure spike | Critical |

---

## Detection Queries

### 1 — Malicious PowerShell Execution (T1059.001)

Catches execution policy bypass flags including shortened versions attackers use to evade basic filters.

```spl
index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*powershell.exe" OR OriginalFileName="PowerShell.EXE")
(CommandLine="*-ep*" OR CommandLine="*-ExecutionPolicy*" OR CommandLine="*-encodedcommand*" OR CommandLine="*-enc*" OR CommandLine="*-nop*")
| table _time host User ParentImage CommandLine
| rename ParentImage as "Parent Process", CommandLine as "Full Command"
```

**Result:** ✅ Detected — captured `-ExecutionPolicy Bypass` with full command line and parent process.

---

### 2 — Binary Masquerading (T1036.003)

Compares the running filename against the PE metadata `OriginalFileName` compiled by Microsoft. A mismatch means a binary was renamed to evade detection.

```spl
index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval image_name=mvindex(split(Image, "\\"), -1)
| eval original_name=OriginalFileName
| where image_name != original_name AND NOT (original_name="-" OR original_name="null")
| table _time host User Image OriginalFileName CommandLine
```

**Result:** ✅ Detected — `cmd.exe` copied and renamed to `svchost.exe` flagged immediately.

---

### 3 — LSASS Credential Dumping (T1003.001)

Catches tools like Mimikatz that access `lsass.exe` memory to extract credentials.

```spl
index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
TargetImage="*lsass.exe"
| stats count BY _time host SourceImage SourceProcessId TargetImage StartAddress
| rename SourceImage as "Accessing Process", TargetImage as "Target Process"
```

**Result:** ✅ Detected — remote thread access into `lsass.exe` captured with source process ID.

---

### 4 — Suspicious File Drop in Temp/Startup (T1105)

```spl
index=endpoint source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| search TargetFilename="*\\AppData\\Local\\Temp\\*"
       OR TargetFilename="*\\Startup\\*"
       OR TargetFilename="*\\Downloads\\*"
| where match(TargetFilename, "\.(exe|ps1|bat|vbs|dll)$")
| table _time host User TargetFilename Image
```

**Result:** ✅ Alert fired — `.exe` file dropped into `%TEMP%` directory by non-installer process detected and logged with full file path and parent process details.

---

### 5 — Brute Force Login Detection — Windows (T1110)

Detects multiple failed login attempts from the same source within a 60 second window — a clear sign of password attack.

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| bucket _time span=60s
| stats count as FailedLogins by _time, Account_Name, IpAddress, ComputerName
| where FailedLogins >= 5
| sort - FailedLogins
| rename Account_Name as "Targeted Account", IpAddress as "Source IP"
```

**Result:** ✅ Alert fired — 8 failed login attempts from single source detected within 60 second window. Account locked out after threshold breach.

---

### 6 — SSH Brute Force Detection — Linux (T1110)

Detects repeated failed SSH login attempts from a single source IP within a 60 second window on Linux endpoints — the Linux equivalent of the Windows 4625 brute force detection.

```spl
index=linux source="/var/log/auth.log" "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=60s
| stats count as FailedAttempts by _time, user, src_ip, host
| where FailedAttempts >= 5
| sort - FailedAttempts
| rename user as "Targeted User", src_ip as "Source IP"
```

**Result:** ✅ Detected — repeated failed SSH logins from a single IP captured and grouped within the 60 second window, with targeted username and source IP extracted.

---

## Threat Simulation Results

Threats were simulated using the included `scripts/emulate_threats.ps1` script and verified in Splunk.

| Simulation | MITRE ID | EventCode / Source Triggered | Detected |
|---|---|---|---|
| PowerShell `-ExecutionPolicy Bypass` | T1059.001 | 1 | ✅ Yes |
| `cmd.exe` renamed to `svchost.exe` | T1036.003 | 1 | ✅ Yes |
| Payload written to `%TEMP%` | T1105 | 11 | ✅ Yes |
| Brute force (8 failed logins, Windows) | T1110 | 4625 | ✅ Yes |
| SSH brute force (Linux) | T1110 | auth.log | ✅ Yes |

---

## Alerting

Detections are configured as scheduled Splunk alerts that notify the SOC team by email when a threshold is breached.

**Configuration (per detection):**

```text
Saved Search → Save As → Alert
  Trigger condition : Number of Results > 0
  Schedule          : Run on cron (e.g. every 5 minutes)
  Action            : Send email
  To                : soc-team@client.com
  Subject           : [ALERT] Brute force detected on $result.host$
  Include           : Search results table, link to Splunk search
```

**Alerts enabled and verified for:**
- Brute force login (Windows — T1110)
- SSH brute force (Linux — T1110)
- LSASS credential dumping (T1003.001)
- Binary masquerading (T1036.003)

---

## Files in This Repo

```
├── README.md
├── config/
│   ├── inputs.conf          ← Splunk log collection config
│   └── sysmonconfig.xml     ← Custom Sysmon noise-filtering rules
├── scripts/
│   └── emulate_threats.ps1  ← Safe threat simulation script
├── dashboards/
│   └── endpoint_visibility_dashboard.xml  ← Splunk dashboard XML
├── screenshots/             ← Dashboard and alert screenshots
├── reports/
│   └── incident-report.html ← Sample client incident report
└── sigma-rules/             ← Vendor-agnostic Sigma detection rules
    ├── brute_force_windows.yml
    ├── powershell_execution.yml
    ├── lsass_credential_dumping.yml
    └── binary_masquerading.yml
```

---

## Configuration Files

### Splunk inputs.conf
See `config/inputs.conf` — routes Security and Sysmon logs to `index=endpoint`.

### Sysmon Config
See `config/sysmonconfig.xml` — tuned ruleset that excludes noisy background processes (WMI, Defender, SearchIndexer) while capturing high-risk binaries (PowerShell, cmd, mshta, certutil, bitsadmin).

---

## MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name |
|---|---|---|
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell |
| Defense Evasion | T1036.003 | Masquerading: Rename System Utilities |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory |
| Credential Access | T1110 | Brute Force |
| Initial Access / Lateral Movement | T1078 | Valid Accounts |
| Command and Control | T1105 | Ingress Tool Transfer |

---

## Sigma Rule Coverage

Sigma rules provide vendor-agnostic detection logic that can be converted to any SIEM's query language (Splunk SPL, Elastic, QRadar, etc.), making detections portable across platforms.

| Detection | Sigma File | MITRE ID |
|---|---|---|
| Brute Force Login (Windows) | `sigma-rules/brute_force_windows.yml` | T1110 |
| PowerShell Execution Bypass | `sigma-rules/powershell_execution.yml` | T1059.001 |
| LSASS Credential Dumping | `sigma-rules/lsass_credential_dumping.yml` | T1003.001 |
| Binary Masquerading | `sigma-rules/binary_masquerading.yml` | T1036.003 |

---


---

## Technologies Used

| Tool | Purpose |
|---|---|
| Splunk Enterprise 9.x | SIEM — ingestion, search, alerting, dashboards |
| Sysmon v15 | Deep Windows endpoint telemetry |
| SPL | Detection query and dashboard logic |
| MITRE ATT&CK | Threat classification framework |
| PowerShell | Threat simulation scripting |

---

## Roadmap

- [ ] Microsoft Sentinel cloud SIEM integration
- [ ] Active Directory attack detection (Kerberoasting, Pass-the-Hash)
- [x] Sigma rule conversion for cross-platform SIEM deployment
- [ ] Wazuh agent integration for active endpoint response
- [ ] CI/CD pipeline for detection-as-code rule deployment
- [ ] Automated incident response playbooks

---

## Contact

**Swetha Nyamala** — Cybersecurity Freelancer | SOC Analyst | SIEM Engineer

- GitHub: [@swethanyamala](https://github.com/swethanyamala)
- Email: swethanyamala2003@gmail.com